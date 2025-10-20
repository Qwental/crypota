package feistel

import (
	"fmt"
	"github.com/Qwental/crypota/internal/interfaces"
)

type FeistelCipher struct {
	keyScheduler  interfaces.KeyScheduler
	roundFunction interfaces.RoundFunction
	numRounds     int
	blockSize     int
	roundKeys     [][]byte
}

func NewFeistelCipher(
	keyScheduler interfaces.KeyScheduler,
	roundFunction interfaces.RoundFunction,
	numRounds int,
	blockSize int,
) *FeistelCipher {
	return &FeistelCipher{
		keyScheduler:  keyScheduler,
		roundFunction: roundFunction,
		numRounds:     numRounds,
		blockSize:     blockSize,
	}
}

func (fc *FeistelCipher) SetKey(key []byte) error {
	roundKeys, err := fc.keyScheduler.GenerateRoundKeys(key)
	if err != nil {
		return fmt.Errorf("key schedule failed: %w", err)
	}
	fc.roundKeys = roundKeys
	return nil
}

func (fc *FeistelCipher) EncryptBlock(plaintext []byte) ([]byte, error) {
	if len(plaintext) != fc.blockSize {
		return nil, fmt.Errorf("invalid block size: expected %d, got %d", fc.blockSize, len(plaintext))
	}
	if fc.roundKeys == nil {
		return nil, fmt.Errorf("round keys not initialized")
	}

	halfSize := fc.blockSize / 2
	leftBytes := make([]byte, halfSize)
	rightBytes := make([]byte, halfSize)
	copy(leftBytes, plaintext[:halfSize])
	copy(rightBytes, plaintext[halfSize:])

	// Раунды Фейстеля
	for round := 0; round < fc.numRounds; round++ {
		fOutput, err := fc.roundFunction.Apply(rightBytes, fc.roundKeys[round])
		if err != nil {
			return nil, fmt.Errorf("round %d failed: %w", round, err)
		}

		newLeft := make([]byte, halfSize)
		copy(newLeft, rightBytes)

		newRight := make([]byte, halfSize)
		for i := 0; i < halfSize; i++ {
			newRight[i] = leftBytes[i] ^ fOutput[i]
		}

		leftBytes = newLeft
		rightBytes = newRight
	}

	// Swap
	result := append(rightBytes, leftBytes...)
	return result, nil
}

func (fc *FeistelCipher) DecryptBlock(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != fc.blockSize {
		return nil, fmt.Errorf("invalid block size: expected %d, got %d", fc.blockSize, len(ciphertext))
	}
	if fc.roundKeys == nil {
		return nil, fmt.Errorf("round keys not initialized")
	}

	halfSize := fc.blockSize / 2
	leftBytes := make([]byte, halfSize)
	rightBytes := make([]byte, halfSize)
	copy(leftBytes, ciphertext[:halfSize])
	copy(rightBytes, ciphertext[halfSize:])

	// Раунды в обратном порядке
	for round := fc.numRounds - 1; round >= 0; round-- {
		fOutput, err := fc.roundFunction.Apply(rightBytes, fc.roundKeys[round])
		if err != nil {
			return nil, fmt.Errorf("round %d failed: %w", round, err)
		}

		newLeft := make([]byte, halfSize)
		copy(newLeft, rightBytes)

		newRight := make([]byte, halfSize)
		for i := 0; i < halfSize; i++ {
			newRight[i] = leftBytes[i] ^ fOutput[i]
		}

		leftBytes = newLeft
		rightBytes = newRight
	}

	// Swap
	result := append(rightBytes, leftBytes...)
	return result, nil
}
