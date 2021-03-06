package raptorq

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	raptorfactory "github.com/harmony-one/go-raptorq/pkg/defaults"
	libraptorq "github.com/harmony-one/go-raptorq/pkg/raptorq"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"
)

func (node *Node) ListeningOnBroadCast(pc net.PacketConn) {
	go node.Gossip(pc)
	go node.ClearCache()

	addr := net.JoinHostPort("", node.SelfPeer.TCPPort)
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

func (node *Node) BroadCast(msg []byte, pc net.PacketConn) (map[int]interface{}, *RaptorQImpl) {
	raptorq := RaptorQImpl{}
	raptorq.Threshold = int(Tau * float32(len(node.AllPeers)))
	log.Printf("threshold value is %v", raptorq.Threshold)
	raptorq.SenderPubKey = node.SelfPeer.PubKey
	raptorq.RootHash = GetRootHash(msg)
	raptorq.Encoder = make(map[int]libraptorq.Encoder)
	raptorq.Stats = make(map[int]float64)
	raptorq.MaxBlockSize = MaxBlockSize
	err := raptorq.SetEncoder(msg)
	log.Printf("encoder created")
	if err != nil {
		log.Printf("cannot create raptorq encoder")
		return nil, nil
	}

	hashkey := ConvertToFixedSize(raptorq.RootHash)
	node.SenderCache[hashkey] = true

	var wg sync.WaitGroup
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
		timeoutDuration := 2 * time.Second
		conn.SetWriteDeadline(time.Now().Add(timeoutDuration))

		wg.Add(1)
		go SendMetaData(&raptorq, conn, &wg)
	}
	wg.Wait()

	raptorq.InitTime = time.Now().UnixNano()
	cancels := make(map[int]interface{})
	for z := 0; z < raptorq.NumBlocks; z++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels[z] = cancel
		go node.BroadCastEncodedSymbol(ctx, &raptorq, pc, z)
	}
	return cancels, &raptorq
}

//func (node *Node) ReportUnfinishedBlocks(raptorq *RaptorQImpl, stop chan bool) {
//	hashkey := ConvertToFixedSize(raptorq.RootHash)
//	for {
//		select {
//		case <-stop:
//			log.Printf("stop received")
//			return
//		default:
//			time.Sleep(5 * time.Second)
//			counter := 0
//			for z := 0; z < raptorq.NumBlocks; z++ {
//				if node.PeerDecodedCounter[hashkey][z] < raptorq.Threshold {
//					counter++
//					log.Printf("block %v broadcast not finished", z)
//				}
//			}
//			log.Printf("total blocks: %v, unfinished blocks: %v", raptorq.NumBlocks, counter)
//		}
//	}
//}

func (node *Node) StopBroadCast(cancels map[int]interface{}, raptorq *RaptorQImpl) {
	//stop := make(chan bool)
	//go node.ReportUnfinishedBlocks(raptorq, stop)

	hashkey := ConvertToFixedSize(raptorq.RootHash)
	canceled := make(map[int]bool)
	for start := time.Now(); time.Since(start) < StopBroadCastTime*time.Second; {
		for z := 0; z < raptorq.NumBlocks; z++ {
			if canceled[z] {
				continue
			}
			if node.PeerDecodedCounter[hashkey][z] >= raptorq.Threshold {
				delta := float64(time.Now().UnixNano()-raptorq.InitTime) / 1000000
				raptorq.mux.Lock()
				raptorq.Stats[z] = delta
				raptorq.mux.Unlock()
				cancels[z].(context.CancelFunc)()
				canceled[z] = true
			}
		}
		if len(canceled) >= raptorq.NumBlocks {
			//stop <- true
			log.Printf("t0/t1/base/t2/hop: %v ms, %v ms, %v, %v ms, %v", node.T0, node.T1, node.Base, node.T2, node.Hop)
			for z, delta := range raptorq.Stats {
				log.Printf("block %v broadcast finished with time elapse = %v ms", z, delta)
			}
			log.Printf("totol broadcast time: %v ms", float64(time.Now().UnixNano()-raptorq.InitTime)/1000000)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (node *Node) ClearCache() {
	OneSec := int64(1000000000)
	node.mux.Lock()
	locked := true
	defer func() {
		if locked {
			node.mux.Unlock()
		}
	}()
	for {
		locked = false
		node.mux.Unlock()
		time.Sleep(CacheClearInterval * time.Second)
		locked = true
		node.mux.Lock()
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

//return 20 byte of the sha1 sum of message
func GetRootHash(msg []byte) []byte {
	x := sha1.Sum(msg)
	return x[:]
}

func ConvertToFixedSize(buf []byte) [HashSize]byte {
	var arr [HashSize]byte
	copy(arr[:], buf[:HashSize])
	return arr
}

func (raptorq *RaptorQImpl) ConstructMetaData() []byte {
	// TODO: optimize overhead of oti later
	packet := append(raptorq.RootHash, Meta)
	pubkey, err := hex.DecodeString(raptorq.SenderPubKey)
	packet = append(packet, pubkey...)
	Z := make([]byte, 4)
	binary.BigEndian.PutUint32(Z, uint32(raptorq.NumBlocks))
	packet = append(packet, Z...)
	var a, b int
	if raptorq.NumBlocks > 1 {
		a = raptorq.NumBlocks - 2
		b = raptorq.NumBlocks - 1
	}
	for i := a; i <= b; i++ {
		commonoti := make([]byte, 8)
		binary.BigEndian.PutUint64(commonoti, raptorq.Encoder[i].CommonOTI())
		specificoti := make([]byte, 4)
		binary.BigEndian.PutUint32(specificoti, raptorq.Encoder[i].SchemeSpecificOTI())
		if err != nil {
			log.Fatal("cannot convert pubkey to byte array")
		}
		packet = append(packet, commonoti...)
		packet = append(packet, specificoti...)
	}
	return packet
}

func symDebug(prefix string, z int, esi uint32, symbol []byte) {
	symhash := sha1.Sum(symbol)
	symhh := make([]byte, hex.EncodedLen(len(symhash)))
	hex.Encode(symhh, symhash[:])
	log.Printf("%s: z=%+v esi=%+v len=%v symhh=%s", prefix, z, esi, len(symbol), symhh)
}

func (raptorq *RaptorQImpl) ConstructSymbolPack(z int, esi uint32, hop int) ([]byte, error) {
	T := raptorq.Encoder[z].SymbolSize()
	symbol := make([]byte, int(T))
	_, err := raptorq.Encoder[z].Encode(0, esi, symbol)
	if err != nil {
		return nil, err
	}
	symDebug("encoded", z, esi, symbol)
	packet := make([]byte, 0)
	packet = append(packet, raptorq.RootHash...)
	packet = append(packet, byte(hop))
	Z := make([]byte, 4)
	binary.BigEndian.PutUint32(Z, uint32(z))
	packet = append(packet, Z...)
	esiheader := make([]byte, 4)
	binary.BigEndian.PutUint32(esiheader, esi)
	packet = append(packet, esiheader...)
	packet = append(packet, symbol...)
	return packet, nil
}

// Specification of RaptorQ FEC is defined in RFC6330
func (raptorq *RaptorQImpl) SetEncoder(msg []byte) error {
	encf := raptorfactory.DefaultEncoderFactory()

	// each source block, the size is limit to a 40 bit integer 946270874880 = 881.28 GB
	//there are some hidden restrictions: WS/T >=10
	// Al: symbol alignment parameter
	var Al uint8 = 4
	// T: symbol size, can take it to be maximum payload size, multiple of Al
	var T uint16 = 1024
	// WS: working memory, maxSubBlockSize, assume it to be 8KB
	var WS uint32 = 32 * 1024
	// minimum sub-symbol size is SS, must be a multiple of Al
	var minSubSymbolSize uint16 = 1 //T / uint16(Al)

	F := len(msg)
	B := raptorq.MaxBlockSize
	if F <= B {
		raptorq.NumBlocks = 1
	} else if F%B == 0 {
		raptorq.NumBlocks = F / B
	} else {
		raptorq.NumBlocks = F/B + 1
	}

	for i := 0; i < raptorq.NumBlocks; i++ {
		a := i * B
		b := (i + 1) * B
		if i == raptorq.NumBlocks-1 {
			b = F
		}
		piece := msg[a:b]
		log.Printf("sha1 hash of block %v is %v", i, GetRootHash(piece))
		encoder, err := encf.New(piece, T, minSubSymbolSize, WS, Al)
		log.Printf("encoder %v is created with size %v", i, b-a)
		if err == nil {
			raptorq.Encoder[i] = encoder
		} else {
			return err
		}
	}
	log.Printf("number of blocks = %v, K0=%v", raptorq.NumBlocks, raptorq.Encoder[0].MinSymbols(0))
	log.Printf("encoder creation time is %v ms", (time.Now().UnixNano()-raptorq.InitTime)/1000000)
	return nil
}

func (raptorq *RaptorQImpl) SetDecoder() error {
	var idx int
	decf := raptorfactory.DefaultDecoderFactory()
	if raptorq.NumBlocks == 1 {
		decoder, err := decf.New(raptorq.CommonOTI[0], raptorq.SpecificOTI[0])
		if err == nil {
			raptorq.Decoder[0] = decoder
		} else {
			return err
		}
		return nil
	}

	for i := 0; i < raptorq.NumBlocks; i++ {
		if i < raptorq.NumBlocks-1 {
			idx = 0
		} else {
			idx = 1
		}
		decoder, err := decf.New(raptorq.CommonOTI[idx], raptorq.SpecificOTI[idx])
		if err == nil {
			raptorq.Decoder[i] = decoder
		} else {
			return err
		}
	}
	return nil
}

func SendMetaData(raptorq *RaptorQImpl, conn net.Conn, wg *sync.WaitGroup) {
	defer conn.Close()
	defer wg.Done()
	metadata := raptorq.ConstructMetaData()
	_, err := conn.Write(metadata)
	if err != nil {
		log.Printf("send metadata failed at peer %v with error %s", conn.RemoteAddr(), err)
		return
	}
	log.Printf("metadata send to %v", conn.RemoteAddr())
}

func ExpBackoffDelay(t0 float64, t1 float64, base float64) func(int, int) time.Duration {
	// t0,t1 is in milliseconds
	max_k := math.Log2(t1/t0) / math.Log2(base) //result cap by t1
	return func(k int, k0 int) time.Duration {
		delta := float64(k - k0)
		power := math.Max(delta, 0)
		power = math.Min(power, max_k)
		return time.Duration(1000000 * t0 * math.Pow(base, power))
	}
}

func (node *Node) BroadCastEncodedSymbol(ctx context.Context, raptorq *RaptorQImpl, pc net.PacketConn, z int) {
	var esi uint32
	peerList := node.PeerList
	L := len(peerList)
	var n int
	backoff := ExpBackoffDelay(node.T0, node.T1, node.Base)
	k0 := int(raptorq.Encoder[z].MinSymbols(0))
	for {
		select {
		case <-ctx.Done():
			log.Printf("block %v broadcast stopped", z)
			return
		default:
			k := int(esi)
			time.Sleep(backoff(k, k0))

			symbol, err := raptorq.ConstructSymbolPack(z, esi, node.Hop)
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
			n, err = pc.WriteTo(symbol, addr)
			if err != nil {
				log.Printf("broadcast encoded symbol written error %v with %v symbol written", err, n)
			}
			if esi%100 == 0 {
				log.Printf("block %v symbol %v sent to %v", z, esi, remoteAddr)
			}
		}
		esi++
	}
}

func (node *Node) RelayEncodedSymbol(pc net.PacketConn, packet []byte) {
	hop := packet[HashSize]
	if hop == 0 {
		return
	} else {
		packet[HashSize] = packet[HashSize] - 1
	}

	L := len(node.PeerList)
	idx0 := rand.Intn(L)
	for i, _ := range node.PeerList {
		idx := (i + idx0) % L
		peer := node.PeerList[idx]
		remoteAddr := net.JoinHostPort(peer.Ip, peer.UDPPort)
		addr, err := net.ResolveUDPAddr("udp", remoteAddr)
		if err != nil {
			log.Printf("cannot resolve udp address %v", remoteAddr)
		}
		//	esi := binary.BigEndian.Uint32(packet[HashSize+1 : HashSize+5])
		//log.Printf("relay symbol %v to %v", esi, addr)
		time.Sleep(time.Duration(node.T2 * 1000000))
		n, err := pc.WriteTo(packet, addr)
		if err != nil {
			log.Printf("relay symbol failed at %v with %v bytes written", addr, n)
		}
	}
}

func (node *Node) Gossip(pc net.PacketConn) {
	var buffer []byte = make([]byte, UDPCacheSize)
	for {
		n, addr, err := pc.ReadFrom(buffer)
		if err != nil {
			log.Printf("gossip receive response from peer %v with error %s", addr, err)
			continue
		} else if n < HashSize+9 {
			log.Printf("gossip need received at least %d byte from peer %v", HashSize+9, addr)
			continue
		}
		copybuffer := make([]byte, n)
		copy(copybuffer, buffer[:n])

		hash := copybuffer[0:HashSize]
		hashkey := ConvertToFixedSize(hash)
		// not gossip its own message
		if node.SenderCache[hashkey] {
			continue
		}
		raptorq := node.InitRaptorQIfNotExist(hash)

		z := int(binary.BigEndian.Uint32(copybuffer[HashSize+1 : HashSize+5]))
		esi := binary.BigEndian.Uint32(copybuffer[HashSize+5 : HashSize+9])
		symbol := copybuffer[HashSize+9 : n]
		symDebug("received", z, esi, symbol)

		if _, ok := raptorq.ReceivedSymbols[z]; !ok {
			raptorq.ReceivedSymbols[z] = make(map[uint32]bool)
		}

		// just relay once
		if raptorq.ReceivedSymbols[z][esi] {
			continue
		}
		raptorq.ReceivedSymbols[z][esi] = true
		//		if len(raptorq.ReceivedSymbols[z])%50 == 0 && !raptorq.Decoder[z].IsSourceObjectReady() {
		//			log.Printf("node %v received source block %v , %v symbols, latest symbol esi = %v", node.SelfPeer.Sid, z, len(raptorq.ReceivedSymbols[z]), esi)
		//		}
		if _, ok := raptorq.Decoder[z]; !ok {
			log.Printf("symbol esi %v skipped because decoder not exist for block %v", esi, z)
			continue
		}

		if !raptorq.Decoder[z].IsSourceObjectReady() {
			raptorq.Decoder[z].Decode(0, esi, symbol)
		}
		go node.RelayEncodedSymbol(pc, copybuffer[:n])
	}
}

func (node *Node) HandleDecodeSuccess(hash []byte, z int, ch chan uint8) {
	sbn, ok := <-ch
	log.Printf("ready channel returned sbn=%+v ok=%+v", sbn, ok)
	hashkey := ConvertToFixedSize(hash)
	node.mux.Lock()
	defer node.mux.Unlock()
	raptorq := node.Cache[hashkey]
	raptorq.mux.Lock()
	defer raptorq.mux.Unlock()
	raptorq.NumDecoded++
	numDecoded := raptorq.NumDecoded
	go node.ResponseSuccess(hash, z)
	log.Printf("source object is ready for block %v", z)
	F := raptorq.Decoder[z].TransferLength()
	buf := make([]byte, F)
	raptorq.Decoder[z].SourceObject(buf)
	log.Printf("sha1 hash for block %v is %v", z, GetRootHash(buf))
	if numDecoded >= raptorq.NumBlocks {
		raptorq.SuccessTime = time.Now().UnixNano()
		go WriteReceivedMessage(raptorq)
	}
}

func (node *Node) AddDecodingReadyChan(hash []byte) {
	hashkey := ConvertToFixedSize(hash)
	node.mux.Lock()
	defer node.mux.Unlock()
	raptorq := node.Cache[hashkey]
	raptorq.mux.Lock()
	defer raptorq.mux.Unlock()
	Z := raptorq.NumBlocks
	var ready []chan uint8
	for z := 0; z < Z; z++ {
		ready = append(ready, make(chan uint8))
		raptorq.Decoder[z].AddReadyBlockChan(ready[z])
	}
	for z, _ := range ready {
		go node.HandleDecodeSuccess(hash, z, ready[z])
	}
}

func (node *Node) InitRaptorQIfNotExist(hash []byte) *RaptorQImpl {
	//hashkey := hex.EncodeToString(hash)
	hashkey := ConvertToFixedSize(hash)
	node.mux.Lock()
	defer node.mux.Unlock()
	if node.Cache[hashkey] == nil {
		log.Printf("raptorq initialized with hash %v", hashkey)
		raptorq := RaptorQImpl{}
		raptorq.Threshold = int(Tau * float32(len(node.AllPeers)))
		raptorq.RootHash = hash
		raptorq.MaxBlockSize = MaxBlockSize
		raptorq.ReceivedSymbols = make(map[int]map[uint32]bool)
		raptorq.Decoder = make(map[int]libraptorq.Decoder)
		raptorq.CommonOTI = make(map[int]uint64)
		raptorq.SpecificOTI = make(map[int]uint32)
		raptorq.InitTime = time.Now().UnixNano()
		node.Cache[hashkey] = &raptorq
	}
	return node.Cache[hashkey]
}

func (node *Node) HandleMetaData(conn net.Conn) {
	var hash []byte
	defer conn.Close()
	c := bufio.NewReader(conn)
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
	case Meta:
		enoughBytes := make([]byte, PubKeySize)
		var n int
		n, err = io.ReadFull(c, enoughBytes)
		if err != nil {
			log.Printf("pubkey read error")
			return
		}
		raptorq.SenderPubKey = hex.EncodeToString(enoughBytes[:n])

		Z := make([]byte, 4)
		_, err := io.ReadFull(c, Z)
		if err != nil {
			log.Printf("number of blocks decoding error")
		}
		raptorq.NumBlocks = int(binary.BigEndian.Uint32(Z))
		var b int
		if raptorq.NumBlocks > 1 {
			b = 1
		}
		for i := 0; i <= b; i++ {

			eightBytes := make([]byte, 8)
			_, err := io.ReadFull(c, eightBytes)
			if err != nil {
				log.Printf("common oti read error")
				return
			}
			raptorq.CommonOTI[i] = binary.BigEndian.Uint64(eightBytes)

			fourBytes := make([]byte, 4)
			_, err = io.ReadFull(c, fourBytes)
			if err != nil {
				log.Printf("schemespecific oti read error")
				return
			}
			raptorq.SpecificOTI[i] = binary.BigEndian.Uint32(fourBytes)
		}
		err = raptorq.SetDecoder()
		if err != nil {
			log.Printf("unable to set decoders for raptorq")
		}
		hashkey := ConvertToFixedSize(hash)
		node.mux.Lock()
		defer node.mux.Unlock()
		node.Cache[hashkey] = raptorq
		go node.AddDecodingReadyChan(hash)
		log.Printf("metadata received, raptorq ready")
	case Received:
		hashkey := ConvertToFixedSize(hash)
		Z := make([]byte, 4)
		_, err := io.ReadFull(c, Z)
		z := int(binary.BigEndian.Uint32(Z))
		node.mux.Lock()
		if _, ok := node.PeerDecodedCounter[hashkey]; !ok {
			node.PeerDecodedCounter[hashkey] = make(map[int]int)
		}
		node.PeerDecodedCounter[hashkey][z] = node.PeerDecodedCounter[hashkey][z] + 1
		node.mux.Unlock()
		sid := make([]byte, 4)
		_, err = io.ReadFull(c, sid)
		if err != nil {
			log.Printf("node sid read error")
		}
		log.Printf("block %v decoded confirmation received from %v", z, binary.BigEndian.Uint32(sid))
		//TODO: add received timestamp for latency estimate
		return
	default:
		log.Printf("unknown meta data type")

	}
}

// this is used for stop sender, will be replaced by consensus algorithm later
func (node *Node) ResponseSuccess(hash []byte, z int) {
	okmsg := make([]byte, 0)
	okmsg = append(okmsg, hash...)
	okmsg = append(okmsg, Received)
	Z := make([]byte, 4)
	binary.BigEndian.PutUint32(Z, uint32(z))
	okmsg = append(okmsg, Z...)
	sid := make([]byte, 4)
	binary.BigEndian.PutUint32(sid, uint32(node.SelfPeer.Sid))
	okmsg = append(okmsg, sid...)
	hashkey := ConvertToFixedSize(hash)
	node.mux.Lock()
	raptorq := node.Cache[hashkey]
	node.mux.Unlock()
	senderPubKey := raptorq.SenderPubKey
	for _, peer := range node.AllPeers {
		if peer.PubKey != senderPubKey {
			continue
		}
		tcpaddr := net.JoinHostPort(peer.Ip, peer.TCPPort)
		conn, err := net.Dial("tcp", tcpaddr)
		if err != nil {
			log.Printf("dial to tcp addr %v failed with %v", tcpaddr, err)
			backoff := ExpBackoffDelay(1000, 15000, 1.35)
			for i := 0; i < 10; i++ {
				time.Sleep(backoff(i, 0))
				conn, err = net.Dial("tcp", tcpaddr)
				if err == nil {
					break
				}
				log.Printf("dial to tcp addr %v failed with %v (retry %v)", tcpaddr, err, i)
			}
			log.Printf("retry exhausted")
		}
		if err == nil && conn != nil {
			_, err = conn.Write(okmsg)
			log.Printf("node %v send okay message for block %v to sender %v", node.SelfPeer.Sid, z, tcpaddr)
			if err != nil {
				log.Printf("send received message to sender %v failed with %v", tcpaddr, err)
			}
		}
		return
	}
}

func WriteReceivedMessage(raptorq *RaptorQImpl) {
	if raptorq.NumDecoded < raptorq.NumBlocks {
		log.Printf("source object is not ready")
		return
	}
	var F int
	for i := 0; i < raptorq.NumBlocks; i++ {
		F += int(raptorq.Decoder[i].TransferLength())
	}
	log.Printf("writing decoded source file with %v bytes......", F)
	buf := make([]byte, F)
	var offset int
	for i := 0; i < raptorq.NumBlocks; i++ {
		size := int(raptorq.Decoder[i].TransferLength())
		_, err := raptorq.Decoder[i].SourceObject(buf[offset : offset+size])
		if err != nil {
			log.Printf("decode object failed at block %v with blocksize %v", i, size)
			return
		}
		offset += size
	}
	fileloc := "received/" + raptorq.SenderPubKey + "_" + strconv.FormatUint(uint64(raptorq.SuccessTime), 10)
	ioutil.WriteFile(fileloc, buf, 0644)
}
