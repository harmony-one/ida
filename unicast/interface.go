package unicast

import raptorq "ida/raptorq"

type Node struct {
	UniCast
	SelfPeer raptorq.Peer
	PeerList []raptorq.Peer
	AllPeers []raptorq.Peer
}

// IDA broadcast using RaptorQ interface
type UniCast interface {
	BroadCast(msg []byte)
	ListeningOnUniCast()
}
