package raptorq

import (
	"encoding/binary"
	"net"
)

func SendMessage(msg []byte, peerID int) error {
	remoteAddr := getPeerAddrFromID(peerID)
	remoteAddr := net.JoinHostPort(peerList[idx].IP, peerList[idx].UDPPort)
	addr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		log.Printf("cannot resolve udp address %v", remoteAddr)
	}
	bytes_sent, err = pc.WriteTo(packet, addr)
	n, err := pc.WriteTo(msg, addr)
}

func getPeerAddrFromPeerID(peerID int) {

}

func (pid *PID) GetSize() int {
	return 2
}

func (pid *PID) GetValue() int {
	return pid.ID
}

func (pid *PID) GetBytes() []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, pid.ID)
	return buf
}

func (gid *GID) GetSize() int {
	return 1
}

func (gid *GID) GetBytes() []byte {
	buf := make([]byte, 1)
	binary.BigEndian.PutUint8(buf, gid.ID)
	return buf
}
