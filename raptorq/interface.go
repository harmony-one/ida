package raptorq

import (
	libraptorq "github.com/harmony-one/go-raptorq/pkg/raptorq"
	"net"
)

// RaptorQ interface.
type RaptorQ interface {
	GetEncoder(msg []byte) (libraptorq.Encoder, error)
	HandleConnectionEncoder(conn net.Conn, msg []byte)
	HandleConnectionDecoder(conn net.Conn, msg []byte)
}

// IDA interface.
//type IDA interface {
//	TakeRaptorQ(raptorQImp *RaptorQ)
//	Encode(msg Message, peers []p2p.Peer, done chan struct{}, timeout time.Duration) error
//}
