package libfakeraptorq

import (
	"errors"
	"log"
	"math"
)

func DefaultEncoderFactory() *FakeEncoderFactory {
	return &FakeEncoderFactory{}
}

func DefaultDecoderFactory() *FakeDecoderFactory {
	return &FakeDecoderFactory{}
}

type FakeEncoder struct {
	symbolSize       uint16
	minSubSymbolSize uint16
	maxSubBlockSize  uint32
	alignment        uint8
	msg              []byte
}

//fake decoder
type FakeDecoder struct {
	N           int //filesize
	T           int //symbolsize
	decodedSize int
	success     bool
	msg         []byte
}

type FakeEncoderFactory struct {
}
type FakeDecoderFactory struct {
}

func (*FakeEncoderFactory) New(input []byte, symbolSize uint16, minSubSymbolSize uint16,
	maxSubBlockSize uint32, alignment uint8) (enc FakeEncoder, err error) {
	enc = FakeEncoder{msg: input, symbolSize: symbolSize, minSubSymbolSize: minSubSymbolSize,
		maxSubBlockSize: maxSubBlockSize, alignment: alignment}
	return enc, nil
}

func (*FakeDecoderFactory) New(commonOTI uint64, schemeSpecificOTI uint32) (
	decoder FakeDecoder, err error) {
	enc := FakeDecoder{N: int(commonOTI), T: int(schemeSpecificOTI)}
	enc.msg = make([]byte, enc.N)
	return enc, nil
}

func (enc *FakeEncoder) NumSourceBlocks() uint8 {
	return 1
}

func (enc *FakeEncoder) CommonOTI() uint64 {
	return uint64(len(enc.msg))
}

func (enc *FakeEncoder) SchemeSpecificOTI() uint32 {
	return uint32(enc.symbolSize)
}

func (enc *FakeEncoder) SymbolSize() uint16 {
	return enc.symbolSize
}

func (enc *FakeEncoder) MinSymbols(sbn uint8) uint16 {
	N := len(enc.msg)
	T := int(enc.symbolSize)
	tmp := math.Ceil(float64(N) / float64(T))
	return uint16(tmp)
}
func (enc *FakeEncoder) Encode(sbn uint8, esi uint32, buf []byte) (written uint, err error) {
	if sbn != 0 {
		err := errors.New("sbn must be 0")
		return 0, err
	}
	N := len(enc.msg)
	T := int(enc.symbolSize)
	if N <= T {
		err := errors.New("ops, fake encoder cannot handle filesize less than symbolsize case")
		return 0, err
	}
	tmp := math.Ceil(float64(N) / float64(T))
	K := int(tmp) //number of pieces
	idx := int(esi) % K
	if idx != K-1 {
		copy(buf, enc.msg[idx*T:(idx+1)*T])
		return uint(T), nil
	} else {
		copy(buf, enc.msg[idx*T:])
		return uint(N % T), nil
	}
}

func (dec *FakeDecoder) Decode(sbn uint8, esi uint32, symbol []byte) {
	if sbn != 0 {
		log.Printf("sbn must be 0")
	}
	tmp := math.Ceil(float64(dec.N) / float64(dec.T))
	K := int(tmp) //number of pieces
	log.Printf("number of pieces %v", K)
	idx := int(esi) % K
	lastPiece := dec.N % dec.T
	if idx != K-1 {
		copy(dec.msg[idx*dec.T:(idx+1)*dec.T], symbol)
		dec.decodedSize += dec.T
	} else {
		copy(dec.msg[idx*dec.T:], symbol[:lastPiece])
		dec.decodedSize += lastPiece
	}
	if dec.decodedSize >= dec.N {
		dec.success = true
	}
	//log.Printf("%v decoded, to be decoded %v", dec.decodedSize, dec.N-dec.decodedSize)
}

func (dec *FakeDecoder) IsSourceObjectReady() bool {
	return dec.success
}

func (dec *FakeDecoder) TransferLength() uint64 {
	return uint64(dec.N)
}

func (dec *FakeDecoder) SourceObject(buf []byte) (n int, err error) {
	if len(buf) < dec.N {
		return 0, errors.New("buf size is too small")
	}
	copy(buf, dec.msg)
	return dec.N, nil
}
