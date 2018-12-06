package raptorq

import (
	//	libraptorq "github.com/harmony-one/go-raptorq/pkg/raptorq"
	"context"
	libraptorq "ida/libfakeraptorq"
	"net"
	"time"
)

const (
	CommonOTI            byte          = 0
	SchemeSpecificOTI    byte          = 1
	EncodedSymbol        byte          = 2
	Received             byte          = 3
	SenderKey            byte          = 4
	PubKeySize           int           = 20
	Tau                  float32       = 0.4 // threshold rate of number of neighors decode message successfully
	HashSize             int           = 32  // sha256 hash size
	StopBroadCastTime    time.Duration = 7   // unit is second
	CacheClearInterval   time.Duration = 5   // clear cache every xx seconds
	EnforceClearInterval int64         = 30  // clear old cache eventually
	UDPCacheSize         int           = 4 * 1024 * 1024
)

type Peer struct {
	Ip      string
	TCPPort string
	UDPPort string
	PubKey  string
}

type HashKey [HashSize]byte

type Node struct {
	GossipIDA
	SelfPeer           Peer
	PeerList           []Peer
	AllPeers           []Peer
	SenderCache        map[HashKey]bool
	Cache              map[HashKey]*RaptorQImpl
	PeerDecodedCounter map[HashKey]int
}

type RaptorQImpl struct {
	SenderPubKey string
	RootHash     []byte
	Threshold    int
	CommonOTI    uint64
	SpecificOTI  uint32
	Encoder      *libraptorq.FakeEncoder
	Decoder      *libraptorq.FakeDecoder
	//Encoder         libraptorq.Encoder
	//Decoder         libraptorq.Decoder
	ReceivedSymbols map[uint32]bool
	Ready           bool
	InitTime        int64 //instance initiate time
	SuccessTime     int64 //success decode time, UnixNano time
}

// IDA broadcast using RaptorQ interface
type GossipIDA interface {
	BroadCast(msg []byte, pc net.PacketConn) (context.Context, context.CancelFunc, *RaptorQImpl)
	StopBroadCast(ctx context.Context, cancel context.CancelFunc, raptorq *RaptorQImpl)
	ListeningOnBroadCast(pc net.PacketConn)
}
