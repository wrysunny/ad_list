package websocket_proxy

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var upgrader = websocket.Upgrader{
	HandshakeTimeout:  5 * time.Second,
	EnableCompression: true,
	ReadBufferSize:    1024 * 16,
	WriteBufferSize:   1024 * 16,
	// 允许跨域（生产环境建议做严格检查）
	CheckOrigin: func(r *http.Request) bool {
		h := r.Header.Get("Origin")
		if h == "" || h == "chrome-extension://enmpedlkjjjnhoehlkkghdjiloebecpn" || strings.Contains(strings.ToLower(h), trustDomain) {
			return true
		}
		return false
	},
}

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer wsConn.Close()

	wsCtx := &WSConnectionContext{
		SessionPrefix: generateSessionPrefix(),
	}
	// === 本 WS 连接专属的会话管理（实现端口复用）===
	var (
		tcpSessions = make(map[string]*tcpProxySession)
		//udpSessions = make(map[string]*udpProxySession)
		sessionMu sync.Mutex // 会话表锁
		// 新增：消息通道，解耦读取和处理，支持并发
		msgChan  = make(chan []byte, 1024) // 带缓冲，防止阻塞
		stopChan = make(chan struct{})
	)

	go func() {
		defer close(msgChan)
		for {
			select {
			case <-stopChan:
				return
			default:
				t, p, err := wsConn.ReadMessage()
				if err != nil {
					//log.Println("Read error:", err)
					return
				}
				switch t {
				case websocket.PingMessage:
					wsCtx.writeMu.Lock()
					wsConn.WriteMessage(websocket.PongMessage, p)
					wsCtx.writeMu.Unlock()
				case websocket.CloseMessage:
					wsCtx.writeMu.Lock()
					wsConn.WriteMessage(websocket.CloseMessage, nil)
					wsCtx.writeMu.Unlock()
					return
				case websocket.TextMessage:
					wsCtx.writeMu.Lock()
					wsConn.WriteMessage(websocket.TextMessage, []byte("ok"))
					wsCtx.writeMu.Unlock()
				case websocket.BinaryMessage:
					// 解密后放入消息通道，由消费协程处理
					decrypted, err := DecryptWithGzip(p, Key)
					if err != nil {
						log.Println(err)
						continue
					}
					if len(decrypted) == 0 {
						continue
					}
					if decrypted[0] == 1 { // TCP
						select {
						case msgChan <- decrypted:
						case <-time.After(1 * time.Second): // 流量控制：超时丢弃，防止通道阻塞
							log.Println("msgChan full, drop message")
						}
					}
				}
			}
		}
	}()
	// 启动多协程消费消息（并发处理TCP请求）
	workerCount := 4 // 根据CPU调整
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for data := range msgChan {
				wsTCP(wsConn, data, &sessionMu, wsCtx, tcpSessions)
			}
		}()
	}
	// WS 关闭时清理
	cleanupDone := make(chan struct{})
	defer func() {
		close(stopChan)
		close(cleanupDone)
		wg.Wait() // 等待所有worker处理完成
		sessionMu.Lock()
		for _, s := range tcpSessions {
			if s.conn != nil {
				s.conn.Close()
			}
		}
		sessionMu.Unlock()
	}()

	// 启动清理协程（包含心跳检测）
	go sessionCleanupLoop(&sessionMu, tcpSessions, cleanupDone)
	// 启动心跳发送协程（服务端主动心跳）
	go heartbeatSendLoop(wsConn, wsCtx, stopChan)

	// 等待worker完成
	wg.Wait()
}

func WebsocketServer() {
	mux := http.NewServeMux()
	// path
	mux.HandleFunc(WebSocketPath, websocketHandler)
	mux.HandleFunc("/stats", statsHandler) // ← 新增统计接口
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"code": 200, "message": "视频流已启动"}`)
	})
	server := &http.Server{
		Addr:           ":43832",
		Handler:        mux,
		ReadTimeout:    10 * time.Second, // 防止慢攻击
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}
	log.Println("Server is listening on :43832")
	log.Fatal(server.ListenAndServe())
}

// 新增：统计接口
func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	type stat struct {
		FromClientBytes uint64 `json:"RX"`
		ToClientBytes   uint64 `json:"TX"`
		ActiveSessions  int32  `json:"active_sessions"`
	}
	resp := struct {
		//UDP       stat   `json:"udp"`
		TCP       stat   `json:"tcp"`
		Timestamp string `json:"timestamp"`
	}{
		/*
			UDP: stat{
				FromClientBytes: atomic.LoadUint64(&globalUDPFromClient),
				ToClientBytes:   atomic.LoadUint64(&globalUDPToClient),
				ActiveSessions:  atomic.LoadInt32(&globalUDPActive),
			},
		*/
		TCP: stat{
			FromClientBytes: atomic.LoadUint64(&globalTCPFromClient),
			ToClientBytes:   atomic.LoadUint64(&globalTCPToClient),
			ActiveSessions:  atomic.LoadInt32(&globalTCPActive),
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Println("stats encode error:", err)
	}
}

// 服务端主动发送心跳
func heartbeatSendLoop(wsConn *websocket.Conn, wsCtx *WSConnectionContext, stopChan chan struct{}) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// 发送空payload的TCP控制包作为心跳
			heartbeatData := &ProxyType{
				Type: 1,
				Len:  0,
			}
			bin, _ := heartbeatData.MarshalBinary()
			enc, _ := EncryptWithGzip(bin, Key)
			wsCtx.writeMu.Lock()
			_ = wsConn.WriteMessage(websocket.BinaryMessage, enc)
			wsCtx.writeMu.Unlock()
		case <-stopChan:
			return
		}
	}
}

// 清理循环（增加心跳检测）
func sessionCleanupLoop(sessionMu *sync.Mutex, tcpSessions map[string]*tcpProxySession, done chan struct{}) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleanupIdleSessions(sessionMu, tcpSessions)
		case <-done:
			return
		}
	}
}

func cleanupIdleSessions(sessionMu *sync.Mutex, tcpSessions map[string]*tcpProxySession) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	now := time.Now()
	for k, s := range tcpSessions {
		// 双重判断：空闲超时 或 心跳超时
		idleTimeout := now.Sub(s.LastActive) > sessionTimeout
		heartbeatTimeout := now.Sub(s.HeartbeatTime) > heartbeatTimeout
		if idleTimeout || heartbeatTimeout {
			if s.conn != nil {
				s.conn.Close()
			}
			delete(tcpSessions, k)
			incTCPActive(-1)
		}
	}
}
