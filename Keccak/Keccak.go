package Keccak

import (
	"encoding/binary"
	"math"
	"sync"
)

type Keccak struct {
	state    []uint64
	disposed bool
	mu       sync.Mutex
}

const keccakRounds = 24

var roundConstants = []uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var rhoOffsets = []int{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

func New() *Keccak {
	return &Keccak{
		state: make([]uint64, 25),
	}
}

func (k *Keccak) Hash(input []byte, outputLengthBits int) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.disposed {
		return nil, ErrObjectDisposed
	}

	k.initializeState()

	rateInBytes := (1600 - 2*outputLengthBits) / 8
	paddedMessage := k.pad(input, rateInBytes)
	k.absorb(paddedMessage, rateInBytes)
	return k.squeeze(outputLengthBits / 8), nil
}

var ErrObjectDisposed = &customError{"Object is disposed"}

type customError struct {
	msg string
}

func (e *customError) Error() string {
	return e.msg
}

func (k *Keccak) initializeState() {
	for i := range k.state {
		k.state[i] = 0
	}
}

func (k *Keccak) absorb(message []byte, rateInBytes int) {
	blockSize := rateInBytes

	for offset := 0; offset < len(message); offset += blockSize {
		for i := 0; i < blockSize/8; i++ {
			if offset+i*8+8 <= len(message) {
				k.state[i] ^= binary.LittleEndian.Uint64(message[offset+i*8 : offset+i*8+8])
			}
		}
		k.keccakF()
	}
}

func (k *Keccak) squeeze(outputLength int) []byte {
	output := make([]byte, outputLength)
	offset := 0

	for outputLength > 0 {
		bytesToOutput := int(math.Min(float64(outputLength), 200))

		buffer := make([]byte, 8)
		for i := 0; i < bytesToOutput/8; i++ {
			binary.LittleEndian.PutUint64(buffer, k.state[i])
			copy(output[offset+i*8:], buffer)
		}

		if bytesToOutput%8 != 0 {
			lastIndex := bytesToOutput / 8
			binary.LittleEndian.PutUint64(buffer, k.state[lastIndex])
			copy(output[offset+lastIndex*8:offset+bytesToOutput], buffer[:bytesToOutput%8])
		}

		offset += bytesToOutput
		outputLength -= bytesToOutput

		if outputLength > 0 {
			k.keccakF()
		}
	}

	return output
}

func (k *Keccak) keccakF() {
	for round := 0; round < keccakRounds; round++ {
		c := make([]uint64, 5)
		d := make([]uint64, 5)

		for i := 0; i < 5; i++ {
			c[i] = k.state[i] ^ k.state[i+5] ^ k.state[i+10] ^ k.state[i+15] ^ k.state[i+20]
		}

		for i := 0; i < 5; i++ {
			d[i] = c[(i+4)%5] ^ rol(c[(i+1)%5], 1)
		}

		for i := 0; i < 25; i += 5 {
			for j := 0; j < 5; j++ {
				k.state[i+j] ^= d[j]
			}
		}

		b := make([]uint64, 25)
		for i := 0; i < 25; i++ {
			b[i] = rol(k.state[i], rhoOffsets[i])
		}

		for i := 0; i < 25; i += 5 {
			for j := 0; j < 5; j++ {
				k.state[i+j] = b[i+j] ^ (^b[i+((j+1)%5)] & b[i+((j+2)%5)])
			}
		}

		k.state[0] ^= roundConstants[round]
	}
}

func rol(x uint64, n int) uint64 {
	return (x << uint(n)) | (x >> uint(64-n))
}

func (k *Keccak) pad(input []byte, rateInBytes int) []byte {
	paddingLength := rateInBytes - (len(input) % rateInBytes)
	padded := make([]byte, len(input)+paddingLength)
	copy(padded, input)
	padded[len(input)] = 0x06
	padded[len(padded)-1] |= 0x80
	return padded
}

func (k *Keccak) Dispose() {
	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.disposed {
		if k.state != nil {
			for i := range k.state {
				k.state[i] = 0
			}
			k.state = nil
		}
		k.disposed = true
	}
}
