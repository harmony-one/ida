package raptorq

import (
	"crypto/sha1"
	"encoding/hex"
	"log"
	"math"
	"time"
)

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

func getChunkSize(msg []byte, chunkID int) int {
	numChunks := getNumChunks(msg)
	if chunkID >= numChunks {
		return 0
	}
	a := chunkID * normalChunkSize
	b := (chunkID + 1) * normalChunkSize
	if chunkID == numChunks-1 {
		b = len(msg)
	}
	return b - a
}

func getNumChunks(msg []byte) int {
	F := len(msg)
	B := normalChunkSize
	if F <= B {
		return 1
	} else if F%B == 0 {
		return F / B
	} else {
		return F/B + 1
	}
}

func expBackoffDelay(initialDelayTime float64, maxDelayTime float64, expBase float64) func(int, int) time.Duration {
	// delay time unit is milliseconds
	max_k := math.Log2(maxDelayTime/initialDelayTime) / math.Log2(expBase) //result cap by maxDelayTime
	return func(k int, k0 int) time.Duration {
		delta := float64(k - k0)
		power := math.Max(delta, 0)
		power = math.Min(power, max_k)
		return time.Duration(1000000 * initialDelayTime * math.Pow(expBase, power))
	}
}

func symDebug(prefix string, chunkID int, symbolID uint32, symbol []byte) {
	symhash := sha1.Sum(symbol)
	symhh := make([]byte, hex.EncodedLen(len(symhash)))
	hex.Encode(symhh, symhash[:])
	log.Printf("%s: chunkID=%+v symbolID=%+v len=%v symbolHash=%s", prefix, chunkID, symbolID, len(symbol), symhh)
}

func getNextSlice(buffer []byte, offset *int, length int) []byte {
	if offset+length > len(buffer) {
		return nil
	}
	slice := buffer[offset : offset+length]
	*offset += length
	return slice
}

func byteArrayCompare(a []byte, b []byte) bool {
	// If one is nil, the other must also be nil.
	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
