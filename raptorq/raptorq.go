package raptorq

import (
	"bufio"
	"bytes"
	"encoding/binary"
	raptorfactory "github.com/harmony-one/go-raptorq/pkg/defaults"
	libraptorq "github.com/harmony-one/go-raptorq/pkg/raptorq"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"strconv"
	"time"
)

//func BroadcastRaptorQ(gid int, msg []byte) {
//
//}

const (
	CommonOTI         byte = 0
	SchemeSpecificOTI byte = 1
	EncodedSymbol     byte = 2
	Received          byte = 3
)

type Peer struct {
	Ip   string
	Port string
}

type RaptorQImpl struct {
	Encoder libraptorq.Encoder
	Decoder libraptorq.Decoder
	Timeout time.Duration
}

func PrepareMessageToEncode(content []byte, K uint16) []byte {
	protocolVersion := byte(1)
	opcode := byte(1)

	Kr := make([]byte, 2)
	binary.BigEndian.PutUint16(Kr, K)

	datasize := make([]byte, 4)
	N := len(content)
	binary.BigEndian.PutUint32(datasize, uint32(N))

	msg := bytes.NewBuffer([]byte{})
	msg.WriteByte(protocolVersion)
	msg.WriteByte(opcode)
	msg.Write(Kr)
	msg.Write(datasize)
	msg.Write(content)
	return msg.Bytes()
}

func (raptorq *RaptorQImpl) ConstructCommonOTI() []byte {
	oti := raptorq.Encoder.CommonOTI()
	header := make([]byte, 8)
	binary.BigEndian.PutUint64(header, oti)
	mtype := []byte{CommonOTI}
	header = append(mtype, header...)
	return header
}

func (raptorq *RaptorQImpl) ConstructSpecificOTI() []byte {
	oti := raptorq.Encoder.SchemeSpecificOTI()
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, oti)
	mtype := []byte{SchemeSpecificOTI}
	header = append(mtype, header...)
	return header
}

func (raptorq *RaptorQImpl) ConstructSymbolPack(esi uint32) ([]byte, error) {
	T := raptorq.Encoder.SymbolSize()
	symbol := make([]byte, int(T))
	n, err := raptorq.Encoder.Encode(0, esi, symbol)
	log.Printf("encoded esi=%+v symbol=%+v n=%+v err=%+v", esi, symbol, n, err)
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, esi)
	packed := append(header, symbol...)
	return packed, err
}

// Specification of RaptorQ FEC is defined in RFC6330
func (raptorq *RaptorQImpl) GetEncoder(msg []byte) (libraptorq.Encoder, error) {
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
	return encoder, err
}

func (raptorq *RaptorQImpl) HandleConnectionEncoder(conn net.Conn, msg []byte) {
	encoder, err := raptorq.GetEncoder(msg)
	if err != nil {
		log.Printf("cannot create raptorq encoder")
	}
	raptorq.Encoder = encoder

	defer conn.Close()
	c := bufio.NewReader(conn)
	commonoti := raptorq.ConstructCommonOTI()
	_, err = conn.Write(commonoti)
	if err != nil {
		log.Printf("send commonoti failed: %s", err)
		return
	}

	specificoti := raptorq.ConstructSpecificOTI()
	_, err = conn.Write(specificoti)
	if err != nil {
		log.Printf("send scheme specific oti failed: %s", err)
		return
	}

	// not support Z > 1 at this moment
	Z := raptorq.Encoder.NumSourceBlocks()
	if Z != 1 {
		log.Printf("we don't support more than one source block yet")
		return
	}

	var esi uint32
	var received bool

	go func() {
		var err error
		for err == nil {
			mtype, err := c.ReadByte()
			if err != nil {
				log.Printf("encoder final stage receive response error: %s", err)
				return
			} else if mtype == Received {
				log.Printf("message sent")
				received = true
			}
		}
	}()

	for !received {
		// for prototype, use fixed time duration after K symbols sent
		if esi > uint32(raptorq.Encoder.MinSymbols(0)) {
			time.Sleep(10 * time.Millisecond)
		}
		symbol, err := raptorq.ConstructSymbolPack(esi)
		esi++
		if err != nil {
			log.Printf("raptorq encoding error: %s", err)
			return
		}
		_, err = conn.Write(symbol)
		if err != nil {
			log.Printf("symbol sending error: %s", err)
			return
		}
	}

}

func (raptorq *RaptorQImpl) HandleConnectionDecoder(conn net.Conn, msg []byte) {
	defer conn.Close()
	c := bufio.NewReader(conn)
	var commonoti uint64
	var specificoti uint32

	for {
		mtype, _ := c.ReadByte()
		switch mtype {
		case CommonOTI:
			eightBytes := make([]byte, 8)
			_, err := io.ReadFull(c, eightBytes)
			if err != nil {
				log.Printf("common oti read error")
				return
			}
			commonoti = binary.BigEndian.Uint64(eightBytes)

		case SchemeSpecificOTI:
			fourBytes := make([]byte, 4)
			_, err := io.ReadFull(c, fourBytes)
			if err != nil {
				log.Printf("schemespecific oti read error")
				return
			}
			specificoti = binary.BigEndian.Uint32(fourBytes)

		default:

		}

		if commonoti > 0 && specificoti > 0 {
			break
		}
	}
	encf := raptorfactory.DefaultDecoderFactory()
	decoder, err := encf.New(commonoti, specificoti)
	if err != nil {
		log.Printf("decoder generation error")
	}
	raptorq.Decoder = decoder
	T := raptorq.Decoder.SymbolSize()
	log.Printf("simbol size %v", int(T))

	symbol := make([]byte, int(T))
	fourBytes := make([]byte, 4)
	var esi uint32
	for {
		_, err := c.Read(fourBytes)
		if err != nil {
			log.Printf("receive esi failed")
		}
		esi = binary.BigEndian.Uint32(fourBytes)
		_, err = c.Read(symbol)
		if err != nil {
			log.Printf("receive symbol failed")
		}
		log.Printf("received encoding symbol, ID=%+v, contents=%+v", esi, symbol)
		raptorq.Decoder.Decode(0, esi, symbol)
		if raptorq.Decoder.IsSourceObjectReady() {
			_, err := conn.Write([]byte{Received})
			if err != nil {
				log.Printf("send received message failed", err)
			}
			F := raptorq.Decoder.TransferLength()
			log.Printf("transfer file size: %v", F)
			buf := make([]byte, F)
			_, err = raptorq.Decoder.SourceObject(buf)
			r := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
			fileloc := "received/" + strconv.FormatUint(r.Uint64(), 10)
			clientinfo := conn.RemoteAddr().String()
			log.Printf("writing from client %s to file %s\n", clientinfo, fileloc)
			ioutil.WriteFile(fileloc, buf, 0644)
			return
		}
	}

}
