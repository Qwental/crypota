package des

import (
	"encoding/binary"
	"fmt"
	"github.com/Qwental/crypota/internal/bitops"
)

type DESKeyScheduler struct {
	subkeys [16]uint64
}

func NewDESKeyScheduler() *DESKeyScheduler {
	return &DESKeyScheduler{}
}

func (ks *DESKeyScheduler) GenerateRoundKeys(key []byte) ([][]byte, error) {
	if len(key) != 8 {
		return nil, fmt.Errorf("DES key must be 8 bytes, got %d", len(key))
	}

	config := bitops.PermuteConfig{
		Indexing:  bitops.MSBFirst,
		Numbering: bitops.OneBased,
	}

	permutedKey, err := bitops.Permute(key, PC1, config)
	if err != nil {
		return nil, fmt.Errorf("PC1 permutation failed: %w", err)
	}

	keyUint64 := binary.BigEndian.Uint64(append(make([]byte, 1), permutedKey...))
	
	C := uint32(keyUint64 >> 29)
	D := uint32((keyUint64 >> 1) & 0x0FFFFFFF)

	leftRotations := ksRotate(C)
	rightRotations := ksRotate(D)

	roundKeys := make([][]byte, 16)

	for round := 0; round < 16; round++ {
		cd := (uint64(leftRotations[round]) << 28) | uint64(rightRotations[round])
		cdBytes := uint56ToBytes(cd)

		roundKey, err := bitops.Permute(cdBytes, PC2, config)
		if err != nil {
			return nil, fmt.Errorf("PC2 permutation failed in round %d: %w", round, err)
		}

		roundKeys[round] = roundKey
	}

	return roundKeys, nil
}

func ksRotate(in uint32) []uint32 {
	out := make([]uint32, 16)
	last := in

	for i := 0; i < 16; i++ {
		shift := LeftShifts[i]
		left := (last << (4 + shift)) >> 4
		right := (last << 4) >> (32 - shift)
		out[i] = left | right
		last = out[i]
	}

	return out
}

func uint56ToBytes(value uint64) []byte {
	bytes := make([]byte, 7)
	for i := 0; i < 7; i++ {
		bytes[i] = byte(value >> (48 - i*8))
	}
	return bytes
}
