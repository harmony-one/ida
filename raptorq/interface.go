package raptorq

import (
	"context"
	libraptorq "github.com/harmony-one/go-raptorq/pkg/raptorq"
	"net"
	"sync"
	"time"
)

const (
	Meta                 byte          = 1
	EncodedSymbol        byte          = 2
	Received             byte          = 3
	SenderKey            byte          = 4
	PubKeySize           int           = 20
	Tau                  float32       = 0.8  // threshold rate of number of neighors decode message successfully
	HashSize             int           = 20   // sha1 hash size
	StopBroadCastTime    time.Duration = 1500 // unit is second
	CacheClearInterval   time.Duration = 2500 // clear cache every xx seconds
	EnforceClearInterval int64         = 3000 // clear old cache eventually
	UDPCacheSize         int           = 4 * 1024 * 1024
	MaxBlockSize         int           = 88 * 1024 // 75kb
)

type Peer struct {
	Ip      string
	TCPPort string
	UDPPort string
	PubKey  string
	Sid     int
}

type HashKey [HashSize]byte

type Node struct {
	//	GossipIDA
	SelfPeer           Peer
	PeerList           []Peer
	AllPeers           []Peer
	SenderCache        map[HashKey]bool
	Cache              map[HashKey]*RaptorQImpl
	PeerDecodedCounter map[HashKey]map[int]int
	T0                 float64 // network delay parameter
	T1                 float64 // network delay parameter
	Base               float64 // network delay parameter
	mux                sync.Mutex
}

type RaptorQImpl struct {
	SenderPubKey string
	RootHash     []byte
	NumBlocks    int
	MaxBlockSize int
	Threshold    int
	CommonOTI    map[int]uint64
	SpecificOTI  map[int]uint32
	//Encoder      *libraptorq.FakeEncoder
	//Decoder      *libraptorq.FakeDecoder
	Encoder         map[int]libraptorq.Encoder
	Decoder         map[int]libraptorq.Decoder
	ReceivedSymbols map[int]map[uint32]bool
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
