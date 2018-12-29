package raptorq

import (
	"encoding/binary"
	raptorfactory "github.com/harmony-one/go-raptorq/pkg/defaults"
	libraptorq "github.com/harmony-one/go-raptorq/pkg/raptorq"
	"io/ioutil"
	"log"
	"strconv"
	"time"
)

func (raptorq *RaptorQImpl) encodeMessage(msg []byte, chunkID int, symbolID uint32, hop int) ([]byte, error) {
	// |HashSize(20)|groupID(1+1)|senderID(2)|numChunks(4)|chunkID(4)|chunkSize(4)|symbolID(4)|symbol(1200)|hop(1)|
	T := raptorq.Encoder[chunkID].SymbolSize()
	symbol := make([]byte, int(T))
	_, err := raptorq.Encoder[chunkID].Encode(0, symbolID, symbol)
	if err != nil {
		return nil, err
	}
	symDebug("encoded", chunkID, symbolID, symbol)
	packet := make([]byte, 0)
	packet = append(packet, raptorq.rootHash...)

	packet = append(packet, byte(raptorq.groupID.GetSize())) // assume the size of groupID has less than 256 bit
	packet = append(packet, raptorq.groupID.GetBytes()...)
	packet = append(packet, raptorq.senderID.GetBytes()...)

	num_chunks := make([]byte, 4)
	binary.BigEndian.PutUint32(num_chunks, uint32(raptorq.numChunks))
	packet = append(packet, num_chunks...)

	chunk_id := make([]byte, 4)
	binary.BigEndian.PutUint32(chunk_id, uint32(chunkID))
	packet = append(packet, chunk_id...)

	chunkSize := getChunkSize(msg, chunkID)
	chunk_size := make([]byte, 4)
	binary.BigEndian.PutUint32(chunk_size, uint32(chunkSize))
	packet = append(packet, chunk_size...)

	symbol_id := make([]byte, 4)
	binary.BigEndian.PutUint32(symbol_id, symbolID)
	packet = append(packet, symbol_id...)
	packet = append(packet, symbol...)

	packet = append(packet, byte(hop))

	return packet, nil
}

// Specification of RaptorQ FEC is defined in RFC6330
// return the TransferLength/ChunkSize
func (raptorq *RaptorQImpl) setEncoderIfNotExist(msg []byte, chunkID int) error {
	if _, ok := raptorq.Encoder[chunkID]; ok {
		return nil
	}

	encf := raptorfactory.DefaultEncoderFactory()
	// each source block, the size is limit to a 40 bit integer 946270874880 = 881.28 GB
	//there are some hidden restrictions: WS/T >=10
	// Al: symbol alignment parameter
	var Al uint8 = 4
	// T: symbol size, can take it to be maximum payload size, multiple of Al
	var T uint16 = uint16(symbolSize)
	// WS: working memory, maxSubBlockSize
	var WS uint32 = 2 * uint32(normalChunkSize)
	// minimum sub-symbol size is SS, must be a multiple of Al
	var minSubSymbolSize uint16 = T // then N=1

	t0 := time.Now().UnixNano()
	a := chunkID * normalChunkSize
	b := a + getChunkSize(msg, chunkID)
	piece := msg[a:b]
	encoder, err := encf.New(piece, T, minSubSymbolSize, WS, Al)
	log.Printf("encoder for chunkID=%v is created with size %v", chunkID, b-a)
	log.Printf("DEBUG:****** encoder for common: %v, specific: %v", encoder.CommonOTI(), encoder.SchemeSpecificOTI())
	log.Printf("****: N: %v", encoder.NumSubBlocks())
	log.Printf("****: Al: %v", encoder.SymbolAlignmentParameter())

	if err == nil {
		raptorq.Encoder[chunkID] = encoder
	} else {
		return err
	}
	log.Printf("numChunks=%v, chunkID=%v, numMinSymbols=%v", raptorq.numChunks, chunkID, raptorq.Encoder[chunkID].MinSymbols(0))
	log.Printf("encoder for chunkID %v creation time is %v ms", chunkID, (time.Now().UnixNano()-t0)/1000000)
	return nil
}

func (raptorq *RaptorQImpl) constructCommonOTI(transferLength uint64) uint64 {
	// CommonOTI = |Transfer Length (5)|Reserved(1)|Symbol Size(2)| 8 bytes
	commonOTI := make([]byte, 0)

	transfer_length := make([]byte, 8)
	binary.BigEndian.PutUint64(transfer_length, transferLength)
	commonOTI = append(commonOTI, transfer_length[3:8]...)
	commonOTI = append(commonOTI, byte(0))

	symbol_size := make([]byte, 2)
	binary.BigEndian.PutUint16(symbol_size, uint16(symbolSize))
	commonOTI = append(commonOTI, symbol_size...)

	return binary.BigEndian.Uint64(commonOTI)
}

func (raptorq *RaptorQImpl) constructSpecificOTI() uint32 {
	// SpecificOTI = |Z(1)|N(2)|Al(1)| 4 bytes
	specificOTI := make([]byte, 0)
	specificOTI = append(specificOTI, byte(1))
	specificOTI = append(specificOTI, 0x00, 0x01)
	specificOTI = append(specificOTI, 0x01) // TODO: should be 0x04, here is a hack caused by libraptorq binding issue
	return binary.BigEndian.Uint32(specificOTI)
}

func (raptorq *RaptorQImpl) setDecoderIfNotExist(chunkID int, chunkSize uint64, node *Node) error {
	raptorq.mux.Lock()
	defer raptorq.mux.Unlock()
	if _, ok := raptorq.Decoder[chunkID]; ok {
		return nil
	}
	decf := raptorfactory.DefaultDecoderFactory()
	commonOTI := raptorq.constructCommonOTI(chunkSize)
	specificOTI := raptorq.constructSpecificOTI()
	log.Printf("DEBUG******: commonOTI: %v, specific: %v", commonOTI, specificOTI)

	decoder, err := decf.New(commonOTI, specificOTI)
	if err == nil {
		raptorq.Decoder[chunkID] = decoder
	} else {
		return err
	}
	ready := make(chan uint8)
	raptorq.Decoder[chunkID].AddReadyBlockChan(ready)
	go node.HandleDecodeSuccess(raptorq.rootHash, chunkID, ready)
	return nil
}

func (node *Node) getRaptorQ(hash []byte) *RaptorQImpl {
	hashkey := ConvertToFixedSize(hash)
	node.mux.Lock()
	defer node.mux.Unlock()
	snapshot := node.Cache[hashkey]
	return snapshot
}

func (node *Node) InitRaptorQIfNotExist(hash []byte) *RaptorQImpl {
	// init raptorq decoder
	node.mux.Lock()
	defer node.mux.Unlock()
	if node.Cache[hashkey] == nil {
		log.Printf("raptorq initialized with hash %v", hashkey)
		raptorq := RaptorQImpl{}
		raptorq.threshold = int(Threshold * float32(len(node.AllPeers)))
		raptorq.rootHash = hash
		raptorq.receivedSymbols = make(map[int]map[uint32]bool)
		raptorq.initTime = time.Now().UnixNano()
		raptorq.Decoder = make(map[int]libraptorq.Decoder)
		node.Cache[hashkey] = &raptorq
	}
	return node.Cache[hashkey]
}

func WriteReceivedMessage(raptorq *RaptorQImpl) {
	if raptorq.numDecoded < raptorq.numChunks {
		log.Printf("source object is not ready")
		return
	}
	var F int
	for i := 0; i < raptorq.numChunks; i++ {
		F += int(raptorq.Decoder[i].TransferLength())
	}
	log.Printf("writing decoded source file with %v bytes......", F)
	buf := make([]byte, F)
	var offset int
	for i := 0; i < raptorq.numChunks; i++ {
		size := int(raptorq.Decoder[i].TransferLength())
		_, err := raptorq.Decoder[i].SourceObject(buf[offset : offset+size])
		if err != nil {
			log.Printf("decode object failed at chunkID=%v with chunkSize=%v", i, size)
			return
		}
		offset += size
	}
	fileloc := "received/" + strconv.Itoa(raptorq.senderID) + "_" + strconv.FormatUint(uint64(raptorq.successTime), 10)
	ioutil.WriteFile(fileloc, buf, 0644)
}
