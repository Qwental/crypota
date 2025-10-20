package des

import (
	"encoding/binary"
	"fmt"
	"github.com/Qwental/crypota/internal/bitops"
)

type DESKeyScheduler struct{}

func NewDESKeyScheduler() *DESKeyScheduler {
	return &DESKeyScheduler{}
}

func leftRotate28(value uint32, n int) uint32 {
	n = n % 28
	return ((value << n) | (value >> (28 - n))) & 0x0FFFFFFF
}

func (ks *DESKeyScheduler) GenerateRoundKeys(key []byte) ([][]byte, error) {
	if len(key) != 8 {
		return nil, fmt.Errorf("DES key must be 8 bytes, got %d", len(key))
	}

	config := bitops.PermuteConfig{
		Indexing:  bitops.MSBFirst,
		Numbering: bitops.OneBased,
	}

	// PC-1 64 в 56 бит
	permutedKeyBytes, err := bitops.Permute(key, PC1, config)
	if err != nil {
		return nil, fmt.Errorf("PC1 permutation failed: %w", err)
	}

	var key56bit uint64
	paddedBytes := make([]byte, 8)
	copy(paddedBytes[1:], permutedKeyBytes)	// Добавляем нулевой байт в начало, чтобы получилось 8 байт

	key56bit = binary.BigEndian.Uint64(paddedBytes)

	C := uint32(key56bit >> 28)
	D := uint32(key56bit & 0x0FFFFFFF)

	roundKeys := make([][]byte, 16)

	for round := 0; round < 16; round++ {
		C = leftRotate28(C, LeftShifts[round])
		D = leftRotate28(D, LeftShifts[round])

		cd56bit := (uint64(C) << 28) | uint64(D)

		cdBytes := make([]byte, 7)
		binary.BigEndian.PutUint64(paddedBytes, cd56bit)
		copy(cdBytes, paddedBytes[1:])

		// PC-2 56 в  48 бит
		roundKey, err := bitops.Permute(cdBytes, PC2, config)
		if err != nil {
			return nil, fmt.Errorf("PC2 permutation failed in round %d: %w", round, err)
		}

		roundKeys[round] = roundKey
	}

	return roundKeys, nil
}
