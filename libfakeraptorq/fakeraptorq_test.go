package libfakeraptorq

import (
	"log"
	"math/rand"
	"testing"
	"time"
)

func GetEncoder(msg []byte) *FakeEncoder {

	encf := DefaultEncoderFactory()
	var Al uint8 = 4
	// WS: working memory, maxSubBlockSize, assume it to be 4MB
	var WS uint32 = 4194304 //1024*1024*Al
	// T: symbol size, can take it to be maximum payload size, multiple of Al
	var T uint16 = 256
	// minimum sub-symbol size, must be a multiple of Al
	var minSubSymbolSize uint16 = uint16(Al)

	encoder, err := encf.New(msg, T, minSubSymbolSize, WS, Al)
	if err != nil {
		log.Printf("cannot generate encoder")
		return nil
	}
	return &encoder
}

func GetDecoder(commonoti uint64, specificoti uint32) *FakeDecoder {
	decf := DefaultDecoderFactory()
	decoder, err := decf.New(commonoti, specificoti)
	if err != nil {
		log.Printf("cannot create decoder")
		return nil
	}
	return &decoder

}

func TestEncoding(t *testing.T) {
	N := 1000
	buf := make([]byte, N)
	rand.Seed(time.Now().UnixNano())
	rand.Read(buf)

	encoder := GetEncoder(buf)
	commonoti := encoder.CommonOTI()
	specificoti := encoder.SchemeSpecificOTI()
	decoder := GetDecoder(commonoti, specificoti)
	T := decoder.T
	FS := decoder.N
	K := FS/T + 1
	symbol := make([]byte, int(T))
	var esi uint32
	for i := 0; i < K; i++ {
		_, err := encoder.Encode(0, esi, symbol)
		if err != nil {
			return
		}
		decoder.Decode(0, esi, symbol)
		esi++
	}

	log.Printf("%v", decoder.IsSourceObjectReady())
}
