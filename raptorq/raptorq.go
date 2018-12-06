package raptorq

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	//	raptorfactory "github.com/harmony-one/go-raptorq/pkg/defaults"
	raptorfactory "ida/libfakeraptorq"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"time"
)

func (node *Node) ListeningOnBroadCast(pc net.PacketConn) {
	go node.Gossip(pc)
	go node.ClearCache()

	addr := net.JoinHostPort("127.0.0.1", node.SelfPeer.TCPPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("cannot listening to the port %s", node.SelfPeer.TCPPort)
		return
	}
	log.Printf("server start listening on tcp port %s", node.SelfPeer.TCPPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("cannot accept connection")
			return
		}
		clientinfo := conn.RemoteAddr().String()
		log.Printf("accept connection from %s", clientinfo)
		go node.HandleMetaData(conn)
	}

}

func (node *Node) BroadCast(msg []byte, pc net.PacketConn) (context.Context, context.CancelFunc, *RaptorQImpl) {
	raptorq := RaptorQImpl{}
	raptorq.Threshold = int(Tau * float32(len(node.AllPeers)))
	log.Printf("threshold value is %v", raptorq.Threshold)
	raptorq.SenderPubKey = node.SelfPeer.PubKey
	raptorq.RootHash = GetRootHash(msg)
	raptorq.InitTime = time.Now().UnixNano()
	err := raptorq.SetEncoder(msg)
	if err != nil {
		log.Printf("cannot create raptorq encoder")
		return nil, nil, nil
	}

	// not support Z > 1 at this moment
	Z := raptorq.Encoder.NumSourceBlocks()
	if Z != 1 {
		log.Printf("we don't support more than one source block yet")
		return nil, nil, nil
	}

	hashkey := ConvertToFixedSize(raptorq.RootHash)
	node.SenderCache[hashkey] = true

	for _, peer := range node.AllPeers {
		// send metadata
		if node.SelfPeer.PubKey == peer.PubKey {
			continue
		}
		tcpaddr := net.JoinHostPort(peer.Ip, peer.TCPPort)
		conn, err := net.Dial("tcp", tcpaddr)
		if err != nil {
			log.Printf("cannot connect to peer %v:%v", peer.Ip, peer.TCPPort)
			continue
		}
		log.Printf("connection established to peer %s", tcpaddr)
		go SendMetaData(&raptorq, conn, msg)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go node.BroadCastEncodedSymbol(ctx, &raptorq, pc, msg)
	return ctx, cancel, &raptorq
}

func (node *Node) StopBroadCast(ctx context.Context, cancel context.CancelFunc, raptorq *RaptorQImpl) {
	defer cancel()
	hashkey := ConvertToFixedSize(raptorq.RootHash)
	for start := time.Now(); time.Since(start) < StopBroadCastTime*time.Second; {
		if node.PeerDecodedCounter[hashkey] >= raptorq.Threshold {
			log.Printf("broadcast finished")
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (node *Node) ClearCache() {
	OneSec := int64(1000000000)
	for {
		time.Sleep(CacheClearInterval * time.Second)
		currentTime := time.Now().UnixNano()
		for k, v := range node.Cache {
			if v.SuccessTime > 0 && currentTime-v.SuccessTime > int64(CacheClearInterval)*OneSec {
				delete(node.Cache, k)
				log.Printf("file hash %v cache deleted", k)
			} else if currentTime-v.InitTime > EnforceClearInterval*OneSec {
				delete(node.Cache, k)
				log.Printf("file hash %v cache eventually deleted", k)
			}
		}
	}
}

//return 32 byte of the sha256 sum of message
func GetRootHash(msg []byte) []byte {
	x := sha256.Sum256(msg)
	return x[:]
}

func ConvertToFixedSize(buf []byte) [HashSize]byte {
	var arr [HashSize]byte
	copy(arr[:], buf[:HashSize])
	return arr
}

func (raptorq *RaptorQImpl) ConstructPubKey() []byte {
	pubkey := raptorq.SenderPubKey
	payload, err := hex.DecodeString(pubkey)
	if err != nil {
		log.Fatal("cannot convert pubkey to byte array")
	}
	mtype := []byte{SenderKey}
	packet := append(mtype, payload...)
	packet = append(raptorq.RootHash, packet...)
	return packet
}

func (raptorq *RaptorQImpl) ConstructCommonOTI() []byte {
	oti := raptorq.Encoder.CommonOTI()
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, oti)
	mtype := []byte{CommonOTI}
	packet := append(mtype, payload...)
	packet = append(raptorq.RootHash, packet...)
	return packet
}

func (raptorq *RaptorQImpl) ConstructSpecificOTI() []byte {
	oti := raptorq.Encoder.SchemeSpecificOTI()
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, oti)
	mtype := []byte{SchemeSpecificOTI}
	packet := append(mtype, payload...)
	packet = append(raptorq.RootHash, packet...)
	return packet
}

func (raptorq *RaptorQImpl) ConstructSymbolPack(esi uint32) ([]byte, error) {
	T := raptorq.Encoder.SymbolSize()
	symbol := make([]byte, int(T))
	_, err := raptorq.Encoder.Encode(0, esi, symbol)
	if err != nil {
		return nil, err
	}
	//log.Printf("encoded esi=%+v symbol=%+v n=%+v err=%+v", esi, symbol, n, err)
	esiheader := make([]byte, 4)
	binary.BigEndian.PutUint32(esiheader, esi)
	payload := append(esiheader, symbol...)
	packet := append([]byte{EncodedSymbol}, payload...)
	packet = append(raptorq.RootHash, packet...)
	return packet, nil
}

// Specification of RaptorQ FEC is defined in RFC6330
func (raptorq *RaptorQImpl) SetEncoder(msg []byte) error {
	encf := raptorfactory.DefaultEncoderFactory()

	// each source block, the size is limit to a 40 bit integer 946270874880 = 881.28 GB
	//there are some hidden restrictions: WS/T >=10
	// the following setup can make sure Z=1 when F less than 10000000

	// Al: symbol alignment parameter
	var Al uint8 = 4
	// WS: working memory, maxSubBlockSize, assume it to be 4MB
	var WS uint32 = 4194304 //1024*1024*Al
	// T: symbol size, can take it to be maximum payload size, multiple of Al
	var T uint16 = 256
	// minimum sub-symbol size, must be a multiple of Al
	var minSubSymbolSize uint16 = uint16(Al)

	encoder, err := encf.New(msg, T, minSubSymbolSize, WS, Al)
	if err == nil {
		raptorq.Encoder = &encoder
	}
	return err
}

func (raptorq *RaptorQImpl) SetDecoder(commonoti uint64, specificoti uint32) error {
	decf := raptorfactory.DefaultDecoderFactory()
	decoder, err := decf.New(commonoti, specificoti)
	if err == nil {
		raptorq.Decoder = &decoder
	}
	return err
}

func SendMetaData(raptorq *RaptorQImpl, conn net.Conn, msg []byte) {
	timeoutDuration := 1 * time.Second
	conn.SetWriteDeadline(time.Now().Add(timeoutDuration))
	defer conn.Close()
	commonoti := raptorq.ConstructCommonOTI()
	log.Printf("send commonoti %v", commonoti)
	_, err := conn.Write(commonoti)
	if err != nil {
		log.Printf("send commonoti failed at peer %v with error %s", conn.RemoteAddr(), err)
		return
	}

	specificoti := raptorq.ConstructSpecificOTI()
	log.Printf("send specificoti %v", specificoti)
	_, err = conn.Write(specificoti)
	if err != nil {
		log.Printf("send scheme specific oti failed at peer %v with error %s", conn.RemoteAddr(), err)
		return
	}

	pubkey := raptorq.ConstructPubKey()
	log.Printf("send pubkey %v", pubkey)
	_, err = conn.Write(pubkey)
	if err != nil {
		log.Printf("send pubkey failed at peer %v with error %s", conn.RemoteAddr(), err)
	}
}

func (node *Node) BroadCastEncodedSymbol(ctx context.Context, raptorq *RaptorQImpl, pc net.PacketConn, msg []byte) {
	var esi uint32
	peerList := node.PeerList
	L := len(peerList)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// for prototype, use fixed time duration after K symbols sent
			if esi > uint32(raptorq.Encoder.MinSymbols(0)) {
				time.Sleep(20 * time.Millisecond)
			}
			symbol, err := raptorq.ConstructSymbolPack(esi)
			if err != nil {
				log.Printf("raptorq encoding error: %s", err)
				return //chao: return or continue
			}
			idx := int(esi) % L
			remoteAddr := net.JoinHostPort(peerList[idx].Ip, peerList[idx].UDPPort)
			addr, err := net.ResolveUDPAddr("udp", remoteAddr)
			if err != nil {
				log.Printf("cannot resolve udp address %v", remoteAddr)
			}
			pc.WriteTo(symbol, addr)
			log.Printf("symbol %v sent", esi)
			esi++
		}
	}
}

func (node *Node) RelayEncodedSymbol(pc net.PacketConn, symbol []byte) {
	for _, peer := range node.PeerList {
		remoteAddr := net.JoinHostPort(peer.Ip, peer.UDPPort)
		addr, err := net.ResolveUDPAddr("udp", remoteAddr)
		if err != nil {
			log.Printf("cannot resolve udp address %v", remoteAddr)
		}
		esi := binary.BigEndian.Uint32(symbol[HashSize+1 : HashSize+5])
		log.Printf("relay symbol %v to %v", esi, addr)
		pc.WriteTo(symbol, addr)
	}
}

func (node *Node) Gossip(pc net.PacketConn) {
	var buffer []byte = make([]byte, UDPCacheSize)
	for {
		n, addr, err := pc.ReadFrom(buffer)
		if err != nil {
			log.Printf("gossip receive response from peer %v with error %s", addr, err)
			continue
		} else if n < HashSize+1 {
			log.Printf("gossip need received at least %d byte from peer %v", HashSize+2, addr)
			continue
		}
		hash := buffer[0:HashSize]
		hashkey := ConvertToFixedSize(hash)
		// not gossip its own message
		if node.SenderCache[hashkey] {
			continue
		}
		raptorq := node.InitRaptorQIfNotExist(hash)
		if buffer[HashSize] != EncodedSymbol {
			continue
		}

		esi := binary.BigEndian.Uint32(buffer[HashSize+1 : HashSize+5])
		symbol := buffer[HashSize+5 : n]
		// just relay once
		if raptorq.ReceivedSymbols[esi] {
			continue
		} else {
			raptorq.ReceivedSymbols[esi] = true
			log.Printf("symbol %v received from %v", esi, addr)
			go node.RelayEncodedSymbol(pc, buffer[:n])
			if raptorq.SuccessTime > 0 {
				continue
			}
			if raptorq.Ready {
				raptorq.Decoder.Decode(0, esi, symbol)
				if raptorq.Decoder.IsSourceObjectReady() {
					log.Printf("source object ready for hashkey %v", hashkey)
					raptorq.SuccessTime = time.Now().UnixNano()
					go node.ResponseSuccess(hash, raptorq.SuccessTime)
					go WriteReceivedMessage(raptorq)
				}
			}
		}
	}
}

func (node *Node) InitRaptorQIfNotExist(hash []byte) *RaptorQImpl {
	//hashkey := hex.EncodeToString(hash)
	hashkey := ConvertToFixedSize(hash)
	if node.Cache[hashkey] == nil {
		log.Printf("raptorq initialized with hash %v", hashkey)
		raptorq := RaptorQImpl{}
		raptorq.Threshold = int(Tau * float32(len(node.AllPeers)))
		raptorq.RootHash = hash
		raptorq.ReceivedSymbols = make(map[uint32]bool)
		raptorq.InitTime = time.Now().UnixNano()
		node.Cache[hashkey] = &raptorq
	}
	return node.Cache[hashkey]
}

func (node *Node) HandleMetaData(conn net.Conn) {
	var hash []byte
	defer conn.Close()
	c := bufio.NewReader(conn)
	for {
		buf := make([]byte, HashSize)
		n, err := io.ReadFull(c, buf)
		if err != nil { // why this happens
			log.Printf("metadata received %v size message", n)
			log.Printf("metadata unable to get root hash of the message: %v", err)
			return
		}
		raptorq := node.InitRaptorQIfNotExist(buf)
		hash = raptorq.RootHash // repeated here
		mtype, _ := c.ReadByte()
		switch mtype {
		case CommonOTI:
			eightBytes := make([]byte, 8)
			_, err := io.ReadFull(c, eightBytes)
			if err != nil {
				log.Printf("common oti read error")
				return
			}
			raptorq.CommonOTI = binary.BigEndian.Uint64(eightBytes)

		case SchemeSpecificOTI:
			fourBytes := make([]byte, 4)
			_, err := io.ReadFull(c, fourBytes)
			if err != nil {
				log.Printf("schemespecific oti read error")
				return
			}
			raptorq.SpecificOTI = binary.BigEndian.Uint32(fourBytes)
		case SenderKey:
			enoughBytes := make([]byte, PubKeySize)
			n, err := io.ReadFull(c, enoughBytes)
			if err != nil {
				log.Printf("pubkey read error")
				return
			}
			raptorq.SenderPubKey = hex.EncodeToString(enoughBytes[:n])
			hashkey := ConvertToFixedSize(hash)
			raptorq := node.Cache[hashkey]
			raptorq.SetDecoder(raptorq.CommonOTI, raptorq.SpecificOTI)
			raptorq.Ready = true
			log.Printf("raptorq ready")
		case Received:
			hashkey := ConvertToFixedSize(hash)
			node.PeerDecodedCounter[hashkey] = node.PeerDecodedCounter[hashkey] + 1
			log.Printf("decoded confirmation received ")
			//TODO: add received timestamp for latency estimate
			return
		default:
			log.Printf("unknown meta data type")

		}
	}
}

// this is used for stop sender, will be replaced by consensus algorithm later
func (node *Node) ResponseSuccess(hash []byte, timestamp int64) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(timestamp))
	okmsg := append(hash, Received)
	okmsg = append(okmsg, b...)
	hashkey := ConvertToFixedSize(hash)
	senderPubKey := node.Cache[hashkey].SenderPubKey
	for _, peer := range node.AllPeers {
		if peer.PubKey != senderPubKey {
			continue
		}
		tcpaddr := net.JoinHostPort(peer.Ip, peer.TCPPort)
		conn, err := net.Dial("tcp", tcpaddr)
		if err != nil {
			log.Printf("dial to tcp addr %v failed with %v", tcpaddr, err)
		}
		_, err = conn.Write(okmsg)
		if err != nil {
			log.Printf("send received message to sender %v failed with %v", tcpaddr, err)
		}
		return
	}
}

func WriteReceivedMessage(raptorq *RaptorQImpl) {
	if !raptorq.Decoder.IsSourceObjectReady() {
		log.Printf("source object is not ready")
		return
	}
	F := raptorq.Decoder.TransferLength()
	buf := make([]byte, F)
	_, err := raptorq.Decoder.SourceObject(buf)
	if err != nil {
		log.Printf("decode object failed")
		return
	}
	fileloc := "received/" + raptorq.SenderPubKey + "_" + strconv.FormatUint(uint64(raptorq.SuccessTime), 10)
	ioutil.WriteFile(fileloc, buf, 0644)
}
