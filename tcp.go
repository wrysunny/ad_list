package websocket_proxy

import (
	"github.com/gorilla/websocket"
	"log"
	"net"
	"sync"
	"time"
)

func wsTCP(wsConn *websocket.Conn, data []byte, sessionMu *sync.Mutex, wsCtx *WSConnectionContext, sessions map[string]*tcpProxySession) {
	var p ProxyType
	if err := p.UnmarshalBinary(data); err != nil {
		log.Println("TCP Unmarshal error:", err)
		return
	}

	// 心跳包（空payload）仅更新心跳时间
	if len(p.Payload) == 0 {
		sessionMu.Lock()
		for _, sess := range sessions {
			sess.HeartbeatTime = time.Now()
		}
		sessionMu.Unlock()
		return
	}

	// 生成带前缀的会话key
	key := makeSessionKey(wsCtx.SessionPrefix, p.Src, p.Dest)

	sessionMu.Lock()
	sess, ok := sessions[key]
	if !ok {
		destAddr := &net.TCPAddr{IP: net.IP(p.Dest.Address[:]), Port: int(p.Dest.Port)}
		// 带超时的TCP连接
		conn, err := net.DialTimeout("tcp", destAddr.String(), 5*time.Second)
		if err != nil {
			sessionMu.Unlock()
			return
		}
		tcpConn := conn.(*net.TCPConn)
		// 设置TCP连接的读写超时
		tcpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		tcpConn.SetWriteDeadline(time.Now().Add(30 * time.Second))

		// 生成会话ID（用于重连恢复）
		sessionID := key
		sess = &tcpProxySession{
			conn:          tcpConn,
			src:           p.Src,
			dest:          p.Dest,
			LastActive:    time.Now(),
			HeartbeatTime: time.Now(),
			SessionID:     sessionID,
		}
		sessions[key] = sess
		incTCPActive(1)
		go tcpReplyLoop(wsConn, sess, key, sessionMu, wsCtx, sessions)
	}
	sessionMu.Unlock()

	// 发送 payload（带流量控制）
	if len(p.Payload) > 0 {
		// 设置写超时
		sess.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := sess.conn.Write(p.Payload); err != nil {
			log.Println("TCP Write error:", err)
		} else {
			incTCPFromClient(uint64(len(p.Payload)))
			sess.LastActive = time.Now()
			sess.HeartbeatTime = time.Now()
		}
	}
}

func tcpReplyLoop(wsConn *websocket.Conn, sess *tcpProxySession, key string, sessionMu *sync.Mutex, wsCtx *WSConnectionContext, sessions map[string]*tcpProxySession) {
	defer func() {
		sessionMu.Lock()
		delete(sessions, key)
		if sess.conn != nil {
			sess.conn.Close()
		}
		sessionMu.Unlock()
		incTCPActive(-1)
	}()

	buf := make([]byte, 16*1024)
	for {
		// 重置读超时
		sess.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := sess.conn.Read(buf)
		if n > 0 {
			sess.LastActive = time.Now()
			sess.HeartbeatTime = time.Now()
			incTCPToClient(uint64(n))

			reply := ProxyType{
				Type:      1,
				Len:       uint16(n),
				Src:       sess.dest,
				Dest:      sess.src,
				Payload:   make([]byte, n),
				SessionID: sess.SessionID,
			}
			copy(reply.Payload, buf[:n])

			bin, _ := reply.MarshalBinary()
			enc, _ := EncryptWithGzip(bin, Key)

			// 流量控制：写操作带超时
			wsCtx.writeMu.Lock()
			wsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			err := wsConn.WriteMessage(websocket.BinaryMessage, enc)
			wsCtx.writeMu.Unlock()
			if err != nil {
				log.Println("WS Write error:", err)
				break
			}
		}
		if err != nil {
			break
		}
	}
}
