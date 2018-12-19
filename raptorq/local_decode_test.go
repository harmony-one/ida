package raptorq

import (
	raptorfactory "github.com/harmony-one/go-raptorq/pkg/defaults"
	libraptorq "github.com/harmony-one/go-raptorq/pkg/raptorq"
	"io/ioutil"
	"log"
	"reflect"
	"testing"
	"time"
)

func PrepareEncoder(msg []byte) *RaptorQImpl {
	raptorq := RaptorQImpl{}
	raptorq.MaxBlockSize = MaxBlockSize
	raptorq.RootHash = GetRootHash(msg)
	raptorq.Decoder = make(map[int]libraptorq.Decoder)
	raptorq.CommonOTI = make(map[int]uint64)
	raptorq.SpecificOTI = make(map[int]uint32)
	raptorq.Encoder = make(map[int]libraptorq.Encoder)
	raptorq.MaxBlockSize = MaxBlockSize
	err := raptorq.SetEncoder(msg)
	if err != nil {
		log.Printf("cannot create raptorq encoder")
		return nil
	}
	log.Printf("encoder created")

	return &raptorq
}

func (raptorq *RaptorQImpl) PrepareDecoder() error {
	decf := raptorfactory.DefaultDecoderFactory()
	for i := 0; i < raptorq.NumBlocks; i++ {
		decoder, err := decf.New(raptorq.Encoder[i].CommonOTI(), raptorq.Encoder[i].SchemeSpecificOTI())
		if err == nil {
			raptorq.Decoder[i] = decoder
		} else {
			return err
		}
	}
	return nil
}

func HandleSuccess(raptorq *RaptorQImpl, z int, ch chan uint8) {
	<-ch
	raptorq.mux.Lock()
	raptorq.NumDecoded++
	numDecoded := raptorq.NumDecoded
	raptorq.mux.Unlock()
	log.Printf("source object is ready for block %v", z)
	if numDecoded >= raptorq.NumBlocks {
		go DecodeAndCompare(raptorq)
	}
}

func DecodeAndCompare(raptorq *RaptorQImpl) {
	var F int
	for i := 0; i < raptorq.NumBlocks; i++ {
		F += int(raptorq.Decoder[i].TransferLength())
	}
	log.Printf("decoding file....")
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
	decodehash := GetRootHash(buf)

	log.Printf("hash: %v", raptorq.RootHash)
	log.Printf("decode hash: %v", decodehash)
	if !reflect.DeepEqual(decodehash, raptorq.RootHash) {
		panic("decoded file not match the original file")
	} else {
		log.Printf("they are equal")
	}
	fileloc := "decoder_result.pdf"
	log.Printf("writing decoding file...")
	ioutil.WriteFile(fileloc, buf, 0644)
	log.Printf("writing finished...")
}

func DecodeFile(raptorq *RaptorQImpl) {
	var ready []chan uint8
	for z := 0; z < raptorq.NumBlocks; z++ {
		ready = append(ready, make(chan uint8))
		raptorq.Decoder[z].AddReadyBlockChan(ready[z])
	}
	for z, _ := range ready {
		go HandleSuccess(raptorq, z, ready[z])
	}

	var numRepairSymbols = 2
	for z := 0; z < raptorq.NumBlocks; z++ {
		go func(z int) {
			T := raptorq.Encoder[z].SymbolSize()
			k0 := int(raptorq.Encoder[z].MinSymbols(0))
			for i := 0; i < k0+numRepairSymbols; i++ { //should be enough for decoding
				esi := uint32(i)
				symbol := make([]byte, int(T))
				_, err := raptorq.Encoder[z].Encode(0, esi, symbol)
				if err != nil {
					panic("cannot encode symbol")
				}
				raptorq.Decoder[z].Decode(0, esi, symbol)
				time.Sleep(5 * time.Millisecond)
			}
		}(z)
	}
}

func TestLocalDecode(t *testing.T) {

	filename := "./test.pdf"
	filecontent, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("file read error: %v", err)
	}

	raptorq := PrepareEncoder(filecontent)
	err = raptorq.PrepareDecoder()
	if err != nil {
		t.Errorf("cannot create decoder: %v", err)
	}
	DecodeFile(raptorq)
	time.Sleep(20 * time.Second)
}
