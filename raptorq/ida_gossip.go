package raptorq

import (
	"bufio"
	"context"
	"encoding/binary"
	libraptorq "github.com/harmony-one/go-raptorq/pkg/raptorq"
	"io"
	"log"
	"math/rand"
	"net"
	"time"
)

func (node *Node) Gossip(network Network) {
	for {
		buffer, peerID, err := network.Receive()
		if err != nil {
			log.Printf("gossip receive response from peer %v with error %s", peerID, err)
			continue
		}
		n := len(buffer)
		minimumSize := HashSize + peerID.GetSize() + symbolSize + 18 // we don't know groupID size yet
		if n <= minimumSize {
			log.Printf("gossip received %v bytes, require at least %v bytes", n, requiredSize)
			continue
		}
		copybuffer := make([]byte, n)
		copy(copybuffer, buffer[:n])

		//decoding
		offset := 0
		hash := getNextSlice(msg, &offset, HashSize)
		hashkey := ConvertToFixedSize(hash)
		// not gossip its own message
		if node.SenderCache[hashkey] {
			continue
		}
		groupIDSize := int(getNextSlice(msg, &offset, 1))
		tmpbuf := getNextSlice(msg, &offset, groupIDSize)
		// ignore wrong group message, TODO: node supports multiple groupIDs
		if !byteArrayCompare(tmpbuf, node.groupID.GetBytes()) {
			continue
		}
		if n != minimumSize+groupIDSize {
			log.Printf("gossip received %v bytes, we need %v bytes", n, miniumSize+groupIDSize)
			continue
		}
		raptorq := node.InitRaptorQIfNotExist(hash)
		raptorq.messageGroupID = &GID{ID: binary.BigEndian.Uint8(tmpbuf)}

		tmpbuf := getNextSlice(copybuffer, &offset, peerID.GetSize())
		//TODO: support arbitray size of PeerID
		raptorq.senderID = &PID{ID: binary.BigEndian.Uint16(tmpbuf)}

		tmpbuf = getNextSlice(copybuffer, &offset, 4)
		raptorq.numChunks = int(binary.BigEndian.Uint32(tmpbuf))
		tmpbuf = getNextSlice(copybuffer, &offset, 4)
		chunkID := int(binary.BigEndian.Uint32(tmpbuf))
		tmpbuf = getNextSlice(copybuffer, &offset, 4)
		chunk_size := append(make([]byte, 4), tmpbuf...)
		chunkSize := binary.BigEndian.Uint64(chunk_size)
		tmpbuf = getNextSlice(copybuffer, &offset, 4)
		symbolID := binary.BigEndian.Uint32(tmpbuf)
		symbol := getNextSlice(copybuffer, &offset, symbolSize)
		symDebug("received", chunkID, symbolID, symbol)
		err = raptorq.setDecoderIfNotExist(chunkID, chunkSize, node)

		if err != nil {
			log.Printf("unable to set decoder for chunkID=%v, with chunkSize=%v", chunkID, chunkSize)
			continue
		}

		if _, ok := raptorq.receivedSymbols[chunkID]; !ok {
			raptorq.receivedSymbols[chunkID] = make(map[uint32]bool)
		}

		// just relay once
		if raptorq.receivedSymbols[chunkID][symbolID] {
			continue
		}
		raptorq.receivedSymbols[chunkID][symbolID] = true

		if !raptorq.Decoder[chunkID].IsSourceObjectReady() {
			raptorq.Decoder[chunkID].Decode(0, symbolID, symbol)
			log.Printf("decode symbol %v", symbolID)
		}
		go node.RelayEncodedSymbol(network, copybuffer[:n], groupID)
	}
}

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
		go node.HandleResponse(conn)
	}
}

func (node *Node) BroadCast(msg []byte, pc net.PacketConn) (map[int]interface{}, *RaptorQImpl) {
	//init raptorq encoder
	raptorq := RaptorQImpl{}
	raptorq.threshold = int(Threshold * float32(len(node.AllPeers)))
	log.Printf("threshold value is %v", raptorq.threshold)
	raptorq.senderID = node.SelfPeer.Sid
	raptorq.rootHash = GetRootHash(msg)
	raptorq.Encoder = make(map[int]libraptorq.Encoder)
	raptorq.stats = make(map[int]float64)
	raptorq.numChunks = getNumChunks(msg)
	raptorq.initTime = time.Now().UnixNano()

	hashkey := ConvertToFixedSize(raptorq.rootHash)
	node.SenderCache[hashkey] = true
	cancels := make(map[int]interface{})
	for z := 0; z < raptorq.numChunks; z++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels[z] = cancel
		go node.BroadCastEncodedSymbol(ctx, msg, &raptorq, pc, z)
	}
	return cancels, &raptorq
}

func (node *Node) StopBroadCast(cancels map[int]interface{}, raptorq *RaptorQImpl) {
	//stop := make(chan bool)
	//go node.ReportUnfinishedBlocks(raptorq, stop)

	hashkey := ConvertToFixedSize(raptorq.rootHash)
	canceled := make(map[int]bool)
	for start := time.Now(); time.Since(start) < stopBroadCastTime*time.Second; {
		for z := 0; z < raptorq.numChunks; z++ {
			if canceled[z] {
				continue
			}
			if node.PeerDecodedCounter[hashkey][z] >= raptorq.threshold {
				delta := float64(time.Now().UnixNano()-raptorq.initTime) / 1000000
				raptorq.mux.Lock()
				raptorq.stats[z] = delta
				raptorq.mux.Unlock()
				cancels[z].(context.CancelFunc)()
				canceled[z] = true
				log.Printf("***** chunkID %v canceled", z)
			}
		}
		if len(canceled) >= raptorq.numChunks {
			//stop <- true
			log.Printf("t0/t1/base/t2/hop: %v ms, %v ms, %v, %v ms, %v", node.InitialDelayTime, node.MaxDelayTime, node.ExpBase, node.RelayTime, node.Hop)
			for z, delta := range raptorq.stats {
				log.Printf("block %v broadcast finished with time elapse = %v ms", z, delta)
			}
			log.Printf("total broadcast time: %v ms", float64(time.Now().UnixNano()-raptorq.initTime)/1000000)
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
		time.Sleep(cacheClearInterval * time.Second)
		locked = true
		node.mux.Lock()
		currentTime := time.Now().UnixNano()
		for k, v := range node.Cache {
			if v.successTime > 0 && currentTime-v.successTime > int64(cacheClearInterval)*OneSec {
				delete(node.Cache, k)
				log.Printf("file hash %v cache deleted", k)
			} else if currentTime-v.initTime > enforceClearInterval*OneSec {
				delete(node.Cache, k)
				log.Printf("file hash %v cache eventually deleted", k)
			}
		}
	}
}

func (node *Node) BroadCastEncodedSymbol(ctx context.Context, msg []byte, raptorq *RaptorQImpl, pc net.PacketConn, chunkID int) {
	var symbolID uint32
	peerList := node.PeerList
	var bytes_sent int
	backoff := expBackoffDelay(node.InitialDelayTime, node.MaxDelayTime, node.ExpBase)
	err := raptorq.setEncoderIfNotExist(msg, chunkID)
	if err != nil {
		log.Printf("unable to create encoder for chunkID=%v", chunkID)
	}
	k0 := int(raptorq.Encoder[chunkID].MinSymbols(0))
	for {
		select {
		case <-ctx.Done():
			log.Printf("chunkID=%v broadcast stopped", chunkID)
			return
		default:
			k := int(symbolID)
			time.Sleep(backoff(k, k0))

			packet, err := raptorq.encodeMessage(msg, chunkID, symbolID, node.Hop)
			if err != nil {
				log.Printf("raptorq encoding error: %s", err)
				return //chao: return or continue
			}
			idx := int(symbolID) % len(peerList)
			remoteAddr := net.JoinHostPort(peerList[idx].IP, peerList[idx].UDPPort)
			addr, err := net.ResolveUDPAddr("udp", remoteAddr)
			if err != nil {
				log.Printf("cannot resolve udp address %v", remoteAddr)
			}
			bytes_sent, err = pc.WriteTo(packet, addr)
			if err != nil {
				log.Printf("broadcast encoded symbol written error %v with %v symbol written", err, bytes_sent)
			}
			if err == nil && bytes_sent < len(packet) {
				log.Printf("udp write with only %v bytes, with original %v bytes", bytes_sent, len(packet))
			}
			if symbolID%100 == 0 {
				log.Printf("chunkID=%v,  symbolID=%v sent to %v", chunkID, symbolID, remoteAddr)
			}
		}
		symbolID++
	}
}

func (node *Node) RelayEncodedSymbol(network Network, packet []byte, groupID GroupID) {
	hop := packet[HashSize]
	if hop == 0 {
		return
	} else {
		packet[HashSize] = packet[HashSize] - 1
	}

	peerList := network.GetPeerList(node.SelfPeer.ID, groupID)

	idx0 := rand.Intn(len(node.PeerList))
	for i, _ := range node.PeerList {
		idx := (i + idx0) % len(node.PeerList)
		peer := node.PeerList[idx]
		remoteAddr := net.JoinHostPort(peer.IP, peer.UDPPort)
		addr, err := net.ResolveUDPAddr("udp", remoteAddr)
		if err != nil {
			log.Printf("cannot resolve udp address %v", remoteAddr)
		}
		time.Sleep(time.Duration(node.RelayTime * 1000000))
		n, err := pc.WriteTo(packet, addr)
		if err != nil {
			log.Printf("relay symbol failed at %v with %v bytes written", addr, n)
		}
		if err == nil && n < len(packet) {
			log.Printf("relay symbol write only %v bytes, need write %v bytes", n, len(packet))
		}
	}
}
func (node *Node) HandleDecodeSuccess(hash []byte, chunkID int, ch chan uint8) {
	sbn, ok := <-ch
	log.Printf("ready channel returned sbn=%+v ok=%+v", sbn, ok)
	hashkey := ConvertToFixedSize(hash)
	node.mux.Lock()
	defer node.mux.Unlock()
	raptorq := node.Cache[hashkey]
	raptorq.mux.Lock()
	defer raptorq.mux.Unlock()
	raptorq.numDecoded++
	numDecoded := raptorq.numDecoded
	go node.ResponseSuccess(hash, chunkID)
	log.Printf("source object is ready for block %v", chunkID)
	F := raptorq.Decoder[chunkID].TransferLength()
	buf := make([]byte, F)
	raptorq.Decoder[chunkID].SourceObject(buf)
	log.Printf("sha1 hash for block %v is %v", chunkID, GetRootHash(buf))
	if numDecoded >= raptorq.numChunks {
		raptorq.successTime = time.Now().UnixNano()
		WriteReceivedMessage(raptorq)
		//	delete(node.Cache, hashkey) // release resources after receive the file
	}
}

func (node *Node) HandleResponse(conn net.Conn) {
	defer conn.Close()
	c := bufio.NewReader(conn)
	hash := make([]byte, HashSize)
	n, err := io.ReadFull(c, hash)
	if err != nil {
		log.Printf("response received %v size message with err %v", n, err)
		return
	}
	hashkey := ConvertToFixedSize(hash)
	//message is not sent by the node
	if _, ok := node.SenderCache[hashkey]; !ok {
		return
	}
	mtype, _ := c.ReadByte()
	switch mtype {
	case Received:
		chunk_id := make([]byte, 4)
		_, err := io.ReadFull(c, chunk_id)
		chunkID := int(binary.BigEndian.Uint32(chunk_id))
		node.mux.Lock()
		if _, ok := node.PeerDecodedCounter[hashkey]; !ok {
			node.PeerDecodedCounter[hashkey] = make(map[int]int)
		}
		node.PeerDecodedCounter[hashkey][chunkID] = node.PeerDecodedCounter[hashkey][chunkID] + 1
		node.mux.Unlock()
		sid := make([]byte, 4)
		_, err = io.ReadFull(c, sid)
		if err != nil {
			log.Printf("node sid read error")
		}
		log.Printf("chunkID=%v decoded confirmation received from %v", chunkID, binary.BigEndian.Uint32(sid))
		return
	default:
		log.Printf("tcp received unknown data type")
	}
}

// this is used for stop sender, will be replaced by consensus algorithm later
func (node *Node) ResponseSuccess(hash []byte, chunkID int) {
	// |hash(20)|Received(1)|chunkID(4)|peerId(4)|
	okmsg := make([]byte, 0)
	okmsg = append(okmsg, hash...)
	okmsg = append(okmsg, Received)
	chunk_id := make([]byte, 4)
	binary.BigEndian.PutUint32(chunk_id, uint32(chunkID))
	okmsg = append(okmsg, chunk_id...)
	sid := make([]byte, 4)
	binary.BigEndian.PutUint32(sid, uint32(node.SelfPeer.Sid))
	okmsg = append(okmsg, sid...)
	hashkey := ConvertToFixedSize(hash)
	node.mux.Lock()
	raptorq := node.Cache[hashkey]
	node.mux.Unlock()
	for _, peer := range node.AllPeers {
		if peer.Sid != raptorq.senderID {
			continue
		}
		tcpaddr := net.JoinHostPort(peer.IP, peer.TCPPort)
		conn, err := net.Dial("tcp", tcpaddr)
		if err != nil {
			log.Printf("dial to tcp addr %v failed with %v", tcpaddr, err)
			backoff := expBackoffDelay(1000, 15000, 1.35)
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
			log.Printf("node %v send okay message for chunkID=%v to sender %v", node.SelfPeer.Sid, chunkID, tcpaddr)
			if err != nil {
				log.Printf("send received message to sender %v failed with %v", tcpaddr, err)
			}
		}
		return
	}
}
