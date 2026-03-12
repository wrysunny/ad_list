package websocket_proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	HandshakeTimeout:  5 * time.Second,
	EnableCompression: true,
	ReadBufferSize:    16 * 1024,
	WriteBufferSize:   16 * 1024,
	CheckOrigin: func(r *http.Request) bool {
		h := r.Header.Get("Origin")
		return h == "" || h == "chrome-extension://enmpedlkjjjnhoehlkkghdjiloebecpn" || strings.Contains(strings.ToLower(h), trustDomain)
	},
}

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}
	defer wsConn.Close()

	wsCtx := &WSConnectionContext{SessionPrefix: generateSessionPrefix()}
	state := newServerTunnelState(wsConn, wsCtx)
	defer state.closeAll()
	go state.cleanupLoop()
	go state.pingLoop()

	_ = wsConn.SetReadDeadline(time.Now().Add(wsReadTimeout))
	wsConn.SetPongHandler(func(string) error {
		_ = wsConn.SetReadDeadline(time.Now().Add(wsReadTimeout))
		return nil
	})

	for {
		t, payload, err := wsConn.ReadMessage()
		if err != nil {
			return
		}
		_ = wsConn.SetReadDeadline(time.Now().Add(wsReadTimeout))

		switch t {
		case websocket.PingMessage:
			state.writeMu.Lock()
			_ = wsConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			_ = wsConn.WriteMessage(websocket.PongMessage, payload)
			state.writeMu.Unlock()
		case websocket.BinaryMessage:
			data, err := DecryptWithGzip(payload, Key)
			if err != nil {
				log.Println("decrypt error:", err)
				continue
			}
			var p ProxyType
			if err := p.UnmarshalBinary(data); err != nil {
				log.Println("unmarshal error:", err)
				continue
			}
			switch p.Type {
			case 1:
				state.handleTCP(p)
			case 0:
				state.handleUDP(p)
			}
		}
	}
}

func WebsocketServer() {
	mux := http.NewServeMux()
	mux.HandleFunc(WebSocketPath, websocketHandler)
	mux.HandleFunc("/stats", statsHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"code":200,"message":"websocket proxy server"}`)
	})
	server := &http.Server{
		Addr:         ":43832",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	log.Println("server listening on :43832")
	log.Fatal(server.ListenAndServe())
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(currentStats())
}

type serverTunnelState struct {
	wsConn      *websocket.Conn
	writeMu     *sync.Mutex
	prefix      string
	sessionMu   sync.RWMutex
	tcpSessions map[string]*tcpProxySession
	udpSessions map[string]*udpProxySession
	closed      chan struct{}
}

func newServerTunnelState(wsConn *websocket.Conn, wsCtx *WSConnectionContext) *serverTunnelState {
	return &serverTunnelState{
		wsConn:      wsConn,
		writeMu:     &wsCtx.writeMu,
		prefix:      wsCtx.SessionPrefix,
		tcpSessions: make(map[string]*tcpProxySession),
		udpSessions: make(map[string]*udpProxySession),
		closed:      make(chan struct{}),
	}
}

func (s *serverTunnelState) closeAll() {
	select {
	case <-s.closed:
		return
	default:
		close(s.closed)
	}

	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	for k, v := range s.tcpSessions {
		if v.conn != nil {
			_ = v.conn.Close()
		}
		delete(s.tcpSessions, k)
		incTCPActive(-1)
	}
	for k, v := range s.udpSessions {
		if v.conn != nil {
			_ = v.conn.Close()
		}
		delete(s.udpSessions, k)
		incUDPActive(-1)
	}
}

func (s *serverTunnelState) pingLoop() {
	t := time.NewTicker(wsPingInterval)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			s.writeMu.Lock()
			_ = s.wsConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			err := s.wsConn.WriteMessage(websocket.PingMessage, nil)
			s.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (s *serverTunnelState) cleanupLoop() {
	t := time.NewTicker(cleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			s.cleanupExpiredSessions()
		}
	}
}

func (s *serverTunnelState) cleanupExpiredSessions() {
	now := time.Now()

	s.sessionMu.Lock()
	for k, sess := range s.tcpSessions {
		sess.mu.Lock()
		stale := now.Sub(sess.LastActive) > tcpSessionTimeout
		sess.mu.Unlock()
		if stale {
			if sess.conn != nil {
				_ = sess.conn.Close()
			}
			delete(s.tcpSessions, k)
			incTCPActive(-1)
		}
	}
	for k, sess := range s.udpSessions {
		sess.mu.Lock()
		stale := now.Sub(sess.LastActive) > udpSessionTimeout
		sess.mu.Unlock()
		if stale {
			if sess.conn != nil {
				_ = sess.conn.Close()
			}
			delete(s.udpSessions, k)
			incUDPActive(-1)
		}
	}
	s.sessionMu.Unlock()
}

func (s *serverTunnelState) writePacket(p ProxyType) error {
	bin, err := p.MarshalBinary()
	if err != nil {
		return err
	}
	enc, err := EncryptWithGzip(bin, Key)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.wsConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	return s.wsConn.WriteMessage(websocket.BinaryMessage, enc)
}

func (s *serverTunnelState) handleTCP(p ProxyType) {
	if len(p.Payload) == 0 {
		return
	}
	key := makeSessionKey(s.prefix, p.Src, p.Dest)

	s.sessionMu.Lock()
	sess, ok := s.tcpSessions[key]
	if !ok {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ipFromAddr(p.Dest).String(), fmt.Sprintf("%d", p.Dest.Port)), tcpDialTimeout)
		if err != nil {
			s.sessionMu.Unlock()
			return
		}
		tcpConn := conn.(*net.TCPConn)
		sess = &tcpProxySession{conn: tcpConn, src: p.Src, dest: p.Dest, LastActive: time.Now(), HeartbeatTime: time.Now()}
		s.tcpSessions[key] = sess
		incTCPActive(1)
		go s.tcpReplyLoop(key, sess)
	}
	s.sessionMu.Unlock()

	sess.mu.Lock()
	_ = sess.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	_, err := sess.conn.Write(p.Payload)
	if err == nil {
		sess.LastActive = time.Now()
		sess.HeartbeatTime = time.Now()
		incTCPFromClient(uint64(len(p.Payload)))
	}
	sess.mu.Unlock()
}

func (s *serverTunnelState) tcpReplyLoop(key string, sess *tcpProxySession) {
	defer func() {
		s.sessionMu.Lock()
		delete(s.tcpSessions, key)
		s.sessionMu.Unlock()
		incTCPActive(-1)
		if sess.conn != nil {
			_ = sess.conn.Close()
		}
	}()

	buf := make([]byte, 16*1024)
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(tcpSessionTimeout))
		n, err := sess.conn.Read(buf)
		if n > 0 {
			sess.mu.Lock()
			sess.LastActive = time.Now()
			sess.HeartbeatTime = time.Now()
			sess.mu.Unlock()
		}
		if n > 0 {
			incTCPToClient(uint64(n))
			reply := ProxyType{Type: 1, Src: sess.dest, Dest: sess.src, Payload: append([]byte(nil), buf[:n]...)}
			if err := s.writePacket(reply); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *serverTunnelState) handleUDP(p ProxyType) {
	key := makeSessionKey(s.prefix, p.Src, p.Dest)
	s.sessionMu.Lock()
	sess, ok := s.udpSessions[key]
	if !ok {
		remote := &net.UDPAddr{IP: ipFromAddr(p.Dest), Port: int(p.Dest.Port)}
		conn, err := net.DialUDP("udp", nil, remote)
		if err != nil {
			s.sessionMu.Unlock()
			return
		}
		_ = conn.SetDeadline(time.Now().Add(udpDialTimeout))
		sess = &udpProxySession{conn: conn, src: p.Src, dest: p.Dest, LastActive: time.Now()}
		s.udpSessions[key] = sess
		incUDPActive(1)
		go s.udpReplyLoop(key, sess)
	}
	s.sessionMu.Unlock()

	if len(p.Payload) > 0 {
		sess.mu.Lock()
		_ = sess.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
		_, err := sess.conn.Write(p.Payload)
		if err == nil {
			sess.LastActive = time.Now()
			incUDPFromClient(uint64(len(p.Payload)))
		}
		sess.mu.Unlock()
	}
}

func (s *serverTunnelState) udpReplyLoop(key string, sess *udpProxySession) {
	defer func() {
		s.sessionMu.Lock()
		delete(s.udpSessions, key)
		s.sessionMu.Unlock()
		incUDPActive(-1)
		if sess.conn != nil {
			_ = sess.conn.Close()
		}
	}()
	buf := make([]byte, 64*1024)
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
		n, err := sess.conn.Read(buf)
		if n > 0 {
			sess.mu.Lock()
			sess.LastActive = time.Now()
			sess.mu.Unlock()
		}
		if n > 0 {
			incUDPToClient(uint64(n))
			reply := ProxyType{Type: 0, Src: sess.dest, Dest: sess.src, Payload: append([]byte(nil), buf[:n]...)}
			if err := s.writePacket(reply); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
