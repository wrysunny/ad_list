package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	socksVersion5        = 0x05
	methodNoAuth         = 0x00
	methodUserPass       = 0x02
	methodNoAcceptable   = 0xFF
	authVersionUserPass  = 0x01
	authStatusSuccess    = 0x00
	authStatusFailure    = 0x01
	cmdConnect           = 0x01
	cmdUDPAssociate      = 0x03
	atypIPv4             = 0x01
	atypDomain           = 0x03
	atypIPv6             = 0x04
	replySucceeded       = 0x00
	replyGeneralFailure  = 0x01
	replyNotAllowed      = 0x02
	replyNetUnreachable  = 0x03
	replyHostUnreachable = 0x04
	replyConnRefused     = 0x05
	replyCmdNotSupported = 0x07
	replyAddrNotSupport  = 0x08
)

var errUnsupportedATYP = errors.New("unsupported atyp")

type Config struct {
	ListenAddr string
	EnableAuth bool
	Username   string
	Password   string
	DialTO     time.Duration
	IdleTO     time.Duration
	UDPTO      time.Duration
}

type Server struct {
	cfg Config
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":1080"
	}
	if cfg.EnableAuth && (cfg.Username == "" || cfg.Password == "") {
		return nil, errors.New("username/password must be non-empty")
	}
	if cfg.DialTO <= 0 {
		cfg.DialTO = 10 * time.Second
	}
	if cfg.IdleTO <= 0 {
		cfg.IdleTO = 5 * time.Minute
	}
	if cfg.UDPTO <= 0 {
		cfg.UDPTO = 90 * time.Second
	}
	return &Server{cfg: cfg}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	defer ln.Close()

	log.Printf("SOCKS5 server listening on %s", ln.Addr().String())

	var wg sync.WaitGroup
	defer wg.Wait()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Printf("temporary accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("accept failed: %w", err)
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			s.handleClient(ctx, c)
		}(conn)
	}
}

func (s *Server) handleClient(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(s.cfg.IdleTO))

	if err := s.negotiateAuth(c); err != nil {
		log.Printf("auth negotiate from %s failed: %v", c.RemoteAddr(), err)
		return
	}

	if s.cfg.EnableAuth {
		if err := s.userPassAuth(c); err != nil {
			log.Printf("userpass auth from %s failed: %v", c.RemoteAddr(), err)
			return
		}
	}

	req, err := readRequest(c)
	if err != nil {
		if errors.Is(err, errUnsupportedATYP) {
			_ = writeReply(c, replyAddrNotSupport, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
		} else {
			_ = writeReply(c, replyGeneralFailure, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
		}
		log.Printf("read request from %s failed: %v", c.RemoteAddr(), err)
		return
	}

	switch req.Cmd {
	case cmdConnect:
		s.handleConnect(c, req)
	case cmdUDPAssociate:
		s.handleUDPAssociate(ctx, c)
	default:
		_ = writeReply(c, replyCmdNotSupported, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	}
}

func (s *Server) negotiateAuth(c net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		return err
	}
	if header[0] != socksVersion5 {
		return errors.New("invalid socks version")
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	support := false
	selected := byte(methodNoAcceptable)
	for _, m := range methods {
		if s.cfg.EnableAuth && m == methodUserPass {
			support = true
			selected = methodUserPass
			break
		}
		if !s.cfg.EnableAuth && m == methodNoAuth {
			support = true
			selected = methodNoAuth
			break
		}
	}
	if !support {
		_, _ = c.Write([]byte{socksVersion5, methodNoAcceptable})
		if s.cfg.EnableAuth {
			return errors.New("client does not support username/password method")
		}
		return errors.New("client does not support no-auth method")
	}
	_, err := c.Write([]byte{socksVersion5, selected})
	return err
}

func (s *Server) userPassAuth(c net.Conn) error {
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil {
		return err
	}
	if h[0] != authVersionUserPass {
		_, _ = c.Write([]byte{authVersionUserPass, authStatusFailure})
		return errors.New("invalid auth version")
	}
	ulen := int(h[1])
	if ulen == 0 {
		_, _ = c.Write([]byte{authVersionUserPass, authStatusFailure})
		return errors.New("empty username")
	}
	ub := make([]byte, ulen)
	if _, err := io.ReadFull(c, ub); err != nil {
		return err
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(c, pl); err != nil {
		return err
	}
	plen := int(pl[0])
	pb := make([]byte, plen)
	if _, err := io.ReadFull(c, pb); err != nil {
		return err
	}

	if string(ub) != s.cfg.Username || string(pb) != s.cfg.Password {
		_, _ = c.Write([]byte{authVersionUserPass, authStatusFailure})
		return errors.New("invalid credentials")
	}
	_, err := c.Write([]byte{authVersionUserPass, authStatusSuccess})
	return err
}

type request struct {
	Cmd  byte
	Host string
	Port int
}

func readRequest(r io.Reader) (*request, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	if h[0] != socksVersion5 {
		return nil, errors.New("invalid version in request")
	}
	atyp := h[3]
	host, err := readAddr(r, atyp)
	if err != nil {
		return nil, err
	}
	portb := make([]byte, 2)
	if _, err = io.ReadFull(r, portb); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(portb))
	return &request{Cmd: h[1], Host: host, Port: port}, nil
}

func readAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return "", err
		}
		l := int(lb[0])
		if l == 0 {
			return "", errors.New("zero domain length")
		}
		db := make([]byte, l)
		if _, err := io.ReadFull(r, db); err != nil {
			return "", err
		}
		return string(db), nil
	default:
		return "", errUnsupportedATYP
	}
}

func (s *Server) handleConnect(client net.Conn, req *request) {
	target := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
	d := net.Dialer{Timeout: s.cfg.DialTO, KeepAlive: 30 * time.Second}
	remote, err := d.Dial("tcp", target)
	if err != nil {
		rep := mapDialErr(err)
		_ = writeReply(client, rep, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
		return
	}
	defer remote.Close()

	localAddr := remote.LocalAddr()
	tcpAddr, ok := localAddr.(*net.TCPAddr)
	if !ok {
		tcpAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	}
	if err := writeReply(client, replySucceeded, tcpAddr); err != nil {
		return
	}

	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})
	pipeBidirectional(client, remote)
}

func (s *Server) handleUDPAssociate(ctx context.Context, client net.Conn) {
	udpLn, err := net.ListenPacket("udp", "[::]:0")
	if err != nil {
		_ = writeReply(client, replyGeneralFailure, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
		return
	}
	defer udpLn.Close()

	udpAddr := udpLn.LocalAddr().(*net.UDPAddr)
	if err := writeReply(client, replySucceeded, &net.TCPAddr{IP: udpAddr.IP, Port: udpAddr.Port}); err != nil {
		return
	}

	clientHost, _, err := net.SplitHostPort(client.RemoteAddr().String())
	if err != nil {
		return
	}

	var (
		clientUDPAddr *net.UDPAddr
		once          sync.Once
	)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			_ = udpLn.SetReadDeadline(time.Now().Add(s.cfg.UDPTO))
			n, src, rerr := udpLn.ReadFrom(buf)
			if rerr != nil {
				if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
					errCh <- nil
					return
				}
				errCh <- rerr
				return
			}

			srcUDP, ok := src.(*net.UDPAddr)
			if !ok {
				continue
			}

			once.Do(func() {
				if srcUDP.IP.String() == clientHost {
					clientUDPAddr = srcUDP
				}
			})

			if clientUDPAddr != nil && srcUDP.IP.Equal(clientUDPAddr.IP) && srcUDP.Port == clientUDPAddr.Port {
				addr, payload, perr := parseUDPRequest(buf[:n])
				if perr != nil {
					continue
				}
				if _, werr := udpLn.WriteTo(payload, addr); werr != nil {
					continue
				}
				continue
			}

			if clientUDPAddr == nil {
				continue
			}
			resp, rerr := buildUDPDatagram(srcUDP, buf[:n])
			if rerr != nil {
				continue
			}
			_, _ = udpLn.WriteTo(resp, clientUDPAddr)
		}
	}()

	// hold TCP control channel until closed by client or context done.
	closeSig := make(chan struct{})
	go func() {
		defer close(closeSig)
		_, _ = io.Copy(io.Discard, client)
	}()

	select {
	case <-ctx.Done():
	case <-closeSig:
	case <-errCh:
	}
}

func parseUDPRequest(b []byte) (*net.UDPAddr, []byte, error) {
	if len(b) < 4 {
		return nil, nil, errors.New("short udp packet")
	}
	if b[2] != 0x00 {
		return nil, nil, errors.New("fragmentation not supported")
	}
	atyp := b[3]
	off := 4
	var host string
	switch atyp {
	case atypIPv4:
		if len(b) < off+4+2 {
			return nil, nil, errors.New("short ipv4 udp packet")
		}
		host = net.IP(b[off : off+4]).String()
		off += 4
	case atypIPv6:
		if len(b) < off+16+2 {
			return nil, nil, errors.New("short ipv6 udp packet")
		}
		host = net.IP(b[off : off+16]).String()
		off += 16
	case atypDomain:
		if len(b) < off+1 {
			return nil, nil, errors.New("short domain len")
		}
		dl := int(b[off])
		off++
		if len(b) < off+dl+2 {
			return nil, nil, errors.New("short domain udp packet")
		}
		host = string(b[off : off+dl])
		off += dl
	default:
		return nil, nil, errors.New("unsupported atyp in udp")
	}
	port := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	payload := b[off:]

	res, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, nil, err
	}
	return res, payload, nil
}

func buildUDPDatagram(src *net.UDPAddr, payload []byte) ([]byte, error) {
	host := src.IP
	var atyp byte
	var addr []byte
	if v4 := host.To4(); v4 != nil {
		atyp = atypIPv4
		addr = v4
	} else if v6 := host.To16(); v6 != nil {
		atyp = atypIPv6
		addr = v6
	} else {
		return nil, errors.New("invalid source ip")
	}

	out := make([]byte, 0, 4+len(addr)+2+len(payload))
	out = append(out, 0x00, 0x00, 0x00, atyp)
	out = append(out, addr...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(src.Port))
	out = append(out, pb...)
	out = append(out, payload...)
	return out, nil
}

func writeReply(w io.Writer, rep byte, a *net.TCPAddr) error {
	ip := a.IP
	if ip == nil {
		ip = net.IPv4zero
	}
	var atyp byte
	var addr []byte
	if v4 := ip.To4(); v4 != nil {
		atyp = atypIPv4
		addr = v4
	} else {
		atyp = atypIPv6
		addr = ip.To16()
	}
	if addr == nil {
		atyp = atypIPv4
		addr = net.IPv4zero
	}

	buf := make([]byte, 0, 6+len(addr))
	buf = append(buf, socksVersion5, rep, 0x00, atyp)
	buf = append(buf, addr...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(a.Port))
	buf = append(buf, pb...)
	_, err := w.Write(buf)
	return err
}

func mapDialErr(err error) byte {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return replyHostUnreachable
		}
		if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
			switch sysErr.Err {
			case syscall.ECONNREFUSED:
				return replyConnRefused
			case syscall.ENETUNREACH:
				return replyNetUnreachable
			case syscall.EHOSTUNREACH:
				return replyHostUnreachable
			}
		}
	}
	return replyGeneralFailure
}

func pipeBidirectional(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

func main() {
	listen := flag.String("listen", ":1080", "listen address, e.g. :1080 or [::]:1080")
	enableAuth := flag.Bool("enable-auth", true, "enable username/password authentication")
	username := flag.String("user", "admin", "username for socks5 auth")
	password := flag.String("pass", "admin123", "password for socks5 auth")
	dialTO := flag.Duration("dial-timeout", 10*time.Second, "tcp dial timeout")
	idleTO := flag.Duration("idle-timeout", 5*time.Minute, "tcp connection idle timeout")
	udpTO := flag.Duration("udp-timeout", 90*time.Second, "udp association idle timeout")
	flag.Parse()

	server, err := NewServer(Config{
		ListenAddr: *listen,
		EnableAuth: *enableAuth,
		Username:   *username,
		Password:   *password,
		DialTO:     *dialTO,
		IdleTO:     *idleTO,
		UDPTO:      *udpTO,
	})
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := server.ListenAndServe(ctx); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
