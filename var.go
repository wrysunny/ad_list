package websocket_proxy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	Key           []byte = CalcSha256("ua#*qI8K&R!7u7@MZ#FQ") // 32 byte
	trustDomain   string = "speedtest.synology.pub"
	WebSocketPath string = "/security_stream_link/2987/t"

	globalUDPFromClient uint64
	globalUDPToClient   uint64
	globalUDPActive     int32
	globalTCPFromClient uint64
	globalTCPToClient   uint64
	globalTCPActive     int32
)

const (
	wsReadTimeout      = 45 * time.Second
	wsWriteTimeout     = 10 * time.Second
	tcpSessionTimeout  = 120 * time.Second
	udpSessionTimeout  = 60 * time.Second
	cleanupInterval    = 15 * time.Second
	tcpDialTimeout     = 10 * time.Second
	udpDialTimeout     = 5 * time.Second
	defaultWorkerCount = 4
)

// WS连接级会话标识
type WSConnectionContext struct {
	SessionPrefix string
	writeMu       sync.Mutex
}

type addr struct {
	Address [16]byte
	Port    uint16
}

type ProxyType struct {
	Type      uint8  // udp 0 tcp 1
	Len       uint16 // payload length
	Src       addr
	Dest      addr
	Payload   []byte
	SessionID string
}

type udpProxySession struct {
	mu         sync.Mutex
	conn       *net.UDPConn
	src        addr
	dest       addr
	LastActive time.Time
}

type tcpProxySession struct {
	mu            sync.Mutex
	conn          *net.TCPConn
	src           addr
	dest          addr
	LastActive    time.Time
	HeartbeatTime time.Time
	SessionID     string
}

func generateSessionPrefix() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func makeSessionKey(prefix string, src, dest addr) string {
	return fmt.Sprintf("%s_%x:%d->%x:%d", prefix, src.Address[:], src.Port, dest.Address[:], dest.Port)
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[ws-proxy] ")
}

func incUDPFromClient(delta uint64) { atomic.AddUint64(&globalUDPFromClient, delta) }
func incUDPToClient(delta uint64)   { atomic.AddUint64(&globalUDPToClient, delta) }
func incUDPActive(delta int32)      { atomic.AddInt32(&globalUDPActive, delta) }
func incTCPFromClient(delta uint64) { atomic.AddUint64(&globalTCPFromClient, delta) }
func incTCPToClient(delta uint64)   { atomic.AddUint64(&globalTCPToClient, delta) }
func incTCPActive(delta int32)      { atomic.AddInt32(&globalTCPActive, delta) }

func currentStats() map[string]any {
	return map[string]any{
		"tcp": map[string]any{
			"rx":              atomic.LoadUint64(&globalTCPFromClient),
			"tx":              atomic.LoadUint64(&globalTCPToClient),
			"active_sessions": atomic.LoadInt32(&globalTCPActive),
		},
		"udp": map[string]any{
			"rx":              atomic.LoadUint64(&globalUDPFromClient),
			"tx":              atomic.LoadUint64(&globalUDPToClient),
			"active_sessions": atomic.LoadInt32(&globalUDPActive),
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}
}

func CalcSha256(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return h[:]
}
