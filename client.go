package websocket_proxy

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type wsWorker struct {
	id     int
	conn   *websocket.Conn
	writeM sync.Mutex
}

type socksClient struct {
	workers  []*wsWorker
	workerMu sync.RWMutex

	tcpMu       sync.RWMutex
	tcpSessions map[string]net.Conn

	udpMu    sync.RWMutex
	udpAssoc *udpAssociation
}

type udpAssociation struct {
	conn       *net.UDPConn
	clientAddr *net.UDPAddr
}

func RunSocks5Client(serverURL, listenAddr string) error {
	u, err := url.Parse(serverURL)
	if err != nil {
		return err
	}
	c := &socksClient{tcpSessions: make(map[string]net.Conn)}

	if err := c.initWorkers(u.String(), defaultWorkerCount); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	log.Println("socks5 listening on", listenAddr, "workers:", defaultWorkerCount)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go c.handleSocksConn(conn)
	}
}

func (c *socksClient) initWorkers(serverURL string, n int) error {
	if n <= 0 {
		n = 1
	}
	workers := make([]*wsWorker, 0, n)
	for i := 0; i < n; i++ {
		ws, _, err := websocket.DefaultDialer.Dial(serverURL, nil)
		if err != nil {
			for _, w := range workers {
				_ = w.conn.Close()
			}
			return fmt.Errorf("dial worker %d failed: %w", i, err)
		}
		w := &wsWorker{id: i, conn: ws}
		workers = append(workers, w)
		go c.readLoop(w)
	}
	c.workerMu.Lock()
	c.workers = workers
	c.workerMu.Unlock()
	return nil
}

func (c *socksClient) chooseWorker(sessionKey string) *wsWorker {
	c.workerMu.RLock()
	defer c.workerMu.RUnlock()
	if len(c.workers) == 0 {
		return nil
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(sessionKey))
	idx := int(h.Sum32()) % len(c.workers)
	return c.workers[idx]
}

func (c *socksClient) readLoop(w *wsWorker) {
	_ = w.conn.SetReadDeadline(time.Now().Add(wsReadTimeout))
	w.conn.SetPongHandler(func(string) error {
		_ = w.conn.SetReadDeadline(time.Now().Add(wsReadTimeout))
		return nil
	})

	for {
		_, payload, err := w.conn.ReadMessage()
		if err != nil {
			return
		}
		_ = w.conn.SetReadDeadline(time.Now().Add(wsReadTimeout))

		dec, err := DecryptWithGzip(payload, Key)
		if err != nil {
			continue
		}
		var p ProxyType
		if err := p.UnmarshalBinary(dec); err != nil {
			continue
		}
		switch p.Type {
		case 1:
			key := makeSessionKey("", p.Dest, p.Src)
			c.tcpMu.RLock()
			conn := c.tcpSessions[key]
			c.tcpMu.RUnlock()
			if conn != nil && len(p.Payload) > 0 {
				_, _ = conn.Write(p.Payload)
			}
		case 0:
			c.udpMu.RLock()
			assoc := c.udpAssoc
			c.udpMu.RUnlock()
			if assoc != nil && assoc.clientAddr != nil {
				packet := buildSocksUDPReply(ipFromAddr(p.Src), int(p.Src.Port), p.Payload)
				_, _ = assoc.conn.WriteToUDP(packet, assoc.clientAddr)
			}
		}
	}
}

func (c *socksClient) sendPacket(sessionKey string, p ProxyType) error {
	bin, err := p.MarshalBinary()
	if err != nil {
		return err
	}
	enc, err := EncryptWithGzip(bin, Key)
	if err != nil {
		return err
	}
	worker := c.chooseWorker(sessionKey)
	if worker == nil {
		return fmt.Errorf("no websocket workers available")
	}
	worker.writeM.Lock()
	defer worker.writeM.Unlock()
	_ = worker.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	return worker.conn.WriteMessage(websocket.BinaryMessage, enc)
}

func (c *socksClient) handleSocksConn(conn net.Conn) {
	defer conn.Close()

	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	_, _ = conn.Write([]byte{0x05, 0x00})

	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHead); err != nil || reqHead[0] != 0x05 {
		return
	}
	cmd := reqHead[1]
	atyp := reqHead[3]
	addrBuf, err := readAddrByAtyp(conn, atyp)
	if err != nil {
		return
	}
	host, port, _, err := parseSocksAddr(append([]byte{atyp}, addrBuf...))
	if err != nil {
		return
	}

	switch cmd {
	case 0x01:
		if err := c.handleConnect(conn, host, port); err != nil {
			log.Println("socks connect error:", err)
		}
	case 0x03:
		if err := c.handleUDPAssociate(conn); err != nil {
			log.Println("socks udp error:", err)
		}
	default:
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func (c *socksClient) handleConnect(conn net.Conn, host string, port int) error {
	dstIP, err := resolveToIP(host)
	if err != nil {
		return err
	}
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	src := addrFromTCPAddr(conn.LocalAddr().(*net.TCPAddr))
	dst := addrFromIPPort(dstIP, port)
	key := makeSessionKey("", src, dst)

	c.tcpMu.Lock()
	c.tcpSessions[key] = conn
	c.tcpMu.Unlock()
	defer func() {
		c.tcpMu.Lock()
		delete(c.tcpSessions, key)
		c.tcpMu.Unlock()
	}()

	buf := make([]byte, 16*1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tcpSessionTimeout))
		n, err := conn.Read(buf)
		if n > 0 {
			p := ProxyType{Type: 1, Src: src, Dest: dst, Payload: append([]byte(nil), buf[:n]...)}
			if err := c.sendPacket(key, p); err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
	}
}

func (c *socksClient) handleUDPAssociate(conn net.Conn) error {
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	bnd := udpConn.LocalAddr().(*net.UDPAddr)
	rep := []byte{0x05, 0x00, 0x00, 0x01}
	ip4 := bnd.IP.To4()
	if ip4 == nil {
		ip4 = net.IPv4(127, 0, 0, 1)
	}
	rep = append(rep, ip4...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(bnd.Port))
	rep = append(rep, port...)
	_, _ = conn.Write(rep)

	assoc := &udpAssociation{conn: udpConn}
	c.udpMu.Lock()
	c.udpAssoc = assoc
	c.udpMu.Unlock()
	defer func() {
		c.udpMu.Lock()
		if c.udpAssoc == assoc {
			c.udpAssoc = nil
		}
		c.udpMu.Unlock()
	}()

	go io.Copy(io.Discard, conn)

	buf := make([]byte, 64*1024)
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if n < 4 || buf[2] != 0x00 {
			continue
		}
		host, dport, consumed, err := parseSocksAddr(buf[3:n])
		if err != nil {
			continue
		}
		payload := append([]byte(nil), buf[3+consumed:n]...)
		dstIP, err := resolveToIP(host)
		if err != nil {
			continue
		}
		assoc.clientAddr = clientAddr
		src := addrFromUDPAddr(clientAddr)
		dst := addrFromIPPort(dstIP, dport)
		p := ProxyType{Type: 0, Src: src, Dest: dst, Payload: payload}
		if err := c.sendPacket(makeSessionKey("", src, dst), p); err != nil {
			return err
		}
	}
}

func readAddrByAtyp(r io.Reader, atyp byte) ([]byte, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 6)
		_, err := io.ReadFull(r, b)
		return b, err
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(r, ln); err != nil {
			return nil, err
		}
		b := make([]byte, int(ln[0])+2)
		_, err := io.ReadFull(r, b)
		return append(ln, b...), err
	case 0x04:
		b := make([]byte, 18)
		_, err := io.ReadFull(r, b)
		return b, err
	default:
		return nil, fmt.Errorf("unsupported atyp %d", atyp)
	}
}

func resolveToIP(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s failed", host)
	}
	return ips[0], nil
}

func buildSocksUDPReply(ip net.IP, port int, payload []byte) []byte {
	ip4 := ip.To4()
	if ip4 != nil {
		b := []byte{0x00, 0x00, 0x00, 0x01}
		b = append(b, ip4...)
		p := make([]byte, 2)
		binary.BigEndian.PutUint16(p, uint16(port))
		b = append(b, p...)
		return append(b, payload...)
	}
	b := []byte{0x00, 0x00, 0x00, 0x04}
	b = append(b, ip.To16()...)
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	b = append(b, p...)
	return append(b, payload...)
}
