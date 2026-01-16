package tuicserver

import (
	"net"
	"sync"
)

type UdpSocket struct {
	mode      string
	socketMap map[uint16]*net.UDPConn
	sync.RWMutex
}

func NewUdpSocket(mode string) *UdpSocket {
	return &UdpSocket{
		mode:      mode,
		socketMap: make(map[uint16]*net.UDPConn),
	}
}

func (u *UdpSocket) Get(assocID uint16) *net.UDPConn {
	u.RLock()
	defer u.RUnlock()
	return u.socketMap[assocID]
}

func (u *UdpSocket) Set(assocID uint16, conn *net.UDPConn) {
	u.Lock()
	defer u.Unlock()
	u.socketMap[assocID] = conn
}

func (u *UdpSocket) Del(assocID uint16) {
	u.Lock()
	defer u.Unlock()
	if conn, ok := u.socketMap[assocID]; ok {
		_ = conn.Close()
		delete(u.socketMap, assocID)
	}
}

func (u *UdpSocket) Close() {
	u.Lock()
	defer u.Unlock()
	for _, conn := range u.socketMap {
		_ = conn.Close()
	}
	u.socketMap = make(map[uint16]*net.UDPConn)
}
