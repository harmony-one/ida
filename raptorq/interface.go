package raptorq

import (
	"context"
	libraptorq "github.com/harmony-one/go-raptorq/pkg/raptorq"
	"net"
	"sync"
	"time"
)

const (
	Received             byte          = 0
	pubKeySize           int           = 20
	stopBroadCastTime    time.Duration = 100 // unit is second
	cacheClearInterval   time.Duration = 250 // clear cache every xx seconds
	enforceClearInterval int64         = 300 // clear old cache eventually
	udpCacheSize         int           = 2 * 1024
	normalChunkSize      int           = 100 * 1200
	symbolSize           int           = 1200 // must be multiple of Al(=4) required by RFC6330

	HashSize  int     = 20  // sha1 hash size
	Threshold float32 = 0.8 // threshold rate of number of neighors decode message successfully
)

type PID struct {
	PeerID
	ID uint16
}

type Peer struct {
	IP      string
	TCPPort string
	UDPPort string
	PubKey  string
	ID      PID
}

type GID struct {
	GroupID
	ID uint8
}

type HashKey [HashSize]byte

type Node struct {
	BroadCaster

	SelfPeer           Peer
	groupID            GroupID // currently assume one node only belongs to one group
	InitialDelayTime   float64 // sender delay parameter
	MaxDelayTime       float64 // sender delay parameter
	ExpBase            float64 // sender delay parameter
	RelayTime          float64 // gossip delay parameter
	Hop                int
	SenderCache        map[HashKey]bool
	Cache              map[HashKey]*RaptorQImpl
	PeerDecodedCounter map[HashKey]map[int]int

	mux sync.Mutex
}

type RaptorQImpl struct {
	Encoder map[int]libraptorq.Encoder
	Decoder map[int]libraptorq.Decoder

	senderID        PeerID
	messageGroupID  GroupID
	rootHash        []byte
	numChunks       int
	threshold       int
	receivedSymbols map[int]map[uint32]bool
	numDecoded      int
	initTime        int64 //instance initiate time
	successTime     int64 //success decode time, UnixNano time
	mux             sync.Mutex
	stats           map[int]float64 // for benchmark purpose
}

type GroupID interface {
	GetBytes() []byte
	GetSize() int
}

type PeerID interface {
	GetBytes() []byte
	GetSize() int
}

type UDPNetwork struct {
	Network
	pc net.UDPConn
}

// IDA broadcast main interface
type BroadCaster interface {
	BroadCast(msg []byte, groupID GroupID, network Network) (context.CancelFunc, *RaptorQImpl)
	StopBroadCast(cancel context.CancelFunc, raptorq *RaptorQImpl)
	Gossip(network Network)
}

type Network interface {
	GetGroupSize(groupID int) int
	GetPeerList(selfID PeerID, groupID GroupID) []PeerID
	Receive() ([]byte, PeerID, error) // get sender's peerID
	SendMessage(msg []byte, peerID PeerID) error
}
