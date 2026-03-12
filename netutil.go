package websocket_proxy

import (
	"encoding/binary"
	"fmt"
	"net"
)

func addrFromIPPort(ip net.IP, port int) addr {
	var a addr
	ip16 := ip.To16()
	if ip16 != nil {
		copy(a.Address[:], ip16)
	}
	a.Port = uint16(port)
	return a
}

func ipFromAddr(a addr) net.IP {
	ip := net.IP(make([]byte, 16))
	copy(ip, a.Address[:])
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

func addrFromTCPAddr(a *net.TCPAddr) addr {
	return addrFromIPPort(a.IP, a.Port)
}

func addrFromUDPAddr(a *net.UDPAddr) addr {
	return addrFromIPPort(a.IP, a.Port)
}

func parseSocksAddr(buf []byte) (host string, port int, consumed int, err error) {
	if len(buf) < 1 {
		return "", 0, 0, fmt.Errorf("empty socks addr")
	}
	atyp := buf[0]
	off := 1
	switch atyp {
	case 1:
		if len(buf) < off+4+2 {
			return "", 0, 0, fmt.Errorf("invalid ipv4 addr")
		}
		host = net.IP(buf[off : off+4]).String()
		off += 4
	case 3:
		if len(buf) < off+1 {
			return "", 0, 0, fmt.Errorf("invalid domain addr")
		}
		ln := int(buf[off])
		off++
		if len(buf) < off+ln+2 {
			return "", 0, 0, fmt.Errorf("invalid domain payload")
		}
		host = string(buf[off : off+ln])
		off += ln
	case 4:
		if len(buf) < off+16+2 {
			return "", 0, 0, fmt.Errorf("invalid ipv6 addr")
		}
		host = net.IP(buf[off : off+16]).String()
		off += 16
	default:
		return "", 0, 0, fmt.Errorf("unsupported atyp %d", atyp)
	}
	port = int(binary.BigEndian.Uint16(buf[off : off+2]))
	off += 2
	return host, port, off, nil
}
