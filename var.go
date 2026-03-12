package websocket_proxy

import (
	"crypto/rand"
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

	// 全局流量统计（atomic 无锁高性能）
	globalUDPFromClient uint64
	globalUDPToClient   uint64
	globalUDPActive     int32
	globalTCPFromClient uint64
	globalTCPToClient   uint64
	globalTCPActive     int32
)

// 新增：WS连接级会话标识
type WSConnectionContext struct {
	SessionPrefix string     // 每个WS连接随机前缀，防止key冲突
	writeMu       sync.Mutex // 保留写锁，但每个WS连接独立
}

type addr struct {
	Address [16]byte
	Port    uint16
}
type ProxyType struct {
	Type      uint8  // udp 0 tcp 1
	Len       uint16 // length
	Src       addr
	Dest      addr
	Payload   []byte
	SessionID string
}

type udpProxySession struct {
	conn       *net.UDPConn
	src        addr
	dest       addr
	LastActive time.Time
}

type tcpProxySession struct {
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

// 会话唯一 key（支持端口复用）
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
