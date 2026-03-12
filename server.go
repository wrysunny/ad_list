package websocket_proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	HandshakeTimeout:  5 * time.Second,
	EnableCompression: true,
	ReadBufferSize:    1024 * 16,
	WriteBufferSize:   1024 * 16,
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

	for {
		t, payload, err := wsConn.ReadMessage()
		if err != nil {
			return
		}
		switch t {
		case websocket.PingMessage:
			state.writeMu.Lock()
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
	server := &http.Server{Addr: ":43832", Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	log.Println("server listening on :43832")
	log.Fatal(server.ListenAndServe())
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	type stat struct {
		FromClientBytes uint64 `json:"rx"`
		ToClientBytes   uint64 `json:"tx"`
		ActiveSessions  int32  `json:"active_sessions"`
	}
	resp := struct {
		TCP       stat   `json:"tcp"`
		UDP       stat   `json:"udp"`
		Timestamp string `json:"timestamp"`
	}{
		TCP:       stat{FromClientBytes: atomic.LoadUint64(&globalTCPFromClient), ToClientBytes: atomic.LoadUint64(&globalTCPToClient), ActiveSessions: atomic.LoadInt32(&globalTCPActive)},
		UDP:       stat{FromClientBytes: atomic.LoadUint64(&globalUDPFromClient), ToClientBytes: atomic.LoadUint64(&globalUDPToClient), ActiveSessions: atomic.LoadInt32(&globalUDPActive)},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	_ = json.NewEncoder(w).Encode(resp)
}

type serverTunnelState struct {
	wsConn      *websocket.Conn
	writeMu     *sync.Mutex
	sessionMu   sync.Mutex
	tcpSessions map[string]*tcpProxySession
	udpSessions map[string]*udpProxySession
}

func newServerTunnelState(wsConn *websocket.Conn, wsCtx *WSConnectionContext) *serverTunnelState {
	return &serverTunnelState{
		wsConn:      wsConn,
		writeMu:     &wsCtx.writeMu,
		tcpSessions: make(map[string]*tcpProxySession),
		udpSessions: make(map[string]*udpProxySession),
	}
}

func (s *serverTunnelState) closeAll() {
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
	s.wsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return s.wsConn.WriteMessage(websocket.BinaryMessage, enc)
}

func (s *serverTunnelState) handleTCP(p ProxyType) {
	if len(p.Payload) == 0 {
		return
	}
	key := makeSessionKey("", p.Src, p.Dest)
	s.sessionMu.Lock()
	sess, ok := s.tcpSessions[key]
	if !ok {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ipFromAddr(p.Dest).String(), fmt.Sprintf("%d", p.Dest.Port)), 10*time.Second)
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

	sess.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := sess.conn.Write(p.Payload); err == nil {
		incTCPFromClient(uint64(len(p.Payload)))
	}
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
		n, err := sess.conn.Read(buf)
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
	key := makeSessionKey("", p.Src, p.Dest)
	s.sessionMu.Lock()
	sess, ok := s.udpSessions[key]
	if !ok {
		remote := &net.UDPAddr{IP: ipFromAddr(p.Dest), Port: int(p.Dest.Port)}
		conn, err := net.DialUDP("udp", nil, remote)
		if err != nil {
			s.sessionMu.Unlock()
			return
		}
		sess = &udpProxySession{conn: conn, src: p.Src, dest: p.Dest, LastActive: time.Now()}
		s.udpSessions[key] = sess
		incUDPActive(1)
		go s.udpReplyLoop(key, sess)
	}
	s.sessionMu.Unlock()

	if len(p.Payload) > 0 {
		if _, err := sess.conn.Write(p.Payload); err == nil {
			incUDPFromClient(uint64(len(p.Payload)))
		}
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
		n, err := sess.conn.Read(buf)
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
