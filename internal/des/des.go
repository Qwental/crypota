package des

import (
	"fmt"
	"github.com/Qwental/crypota/internal/bitops"
	"github.com/Qwental/crypota/internal/feistel"
	"github.com/Qwental/crypota/internal/interfaces"
)

const (
	DESBlockSize = 8
	DESNumRounds = 16
)

type DESCipher struct {
	feistel *feistel.FeistelCipher
}

func NewDESCipher() interfaces.BlockCipher {
	keyScheduler := NewDESKeyScheduler()
	roundFunction := NewDESRoundFunction()

	feistelCipher := feistel.NewFeistelCipher(
		keyScheduler,
		roundFunction,
		DESNumRounds,
		DESBlockSize,
	)

	return &DESCipher{
		feistel: feistelCipher,
	}
}

func (d *DESCipher) SetKey(key []byte) error {
	if len(key) != 8 {
		return fmt.Errorf("DES key must be 8 bytes, got %d", len(key))
	}
	return d.feistel.SetKey(key)
}

func (d *DESCipher) EncryptBlock(plaintext []byte) ([]byte, error) {
	if len(plaintext) != DESBlockSize {
		return nil, fmt.Errorf("block size must be %d bytes, got %d", DESBlockSize, len(plaintext))
	}

	config := bitops.PermuteConfig{
		Indexing:  bitops.MSBFirst,
		Numbering: bitops.OneBased,
	}

	// IP
	permutedBlock, err := bitops.Permute(plaintext, IP, config)
	if err != nil {
		return nil, fmt.Errorf("initial permutation failed: %w", err)
	}

	// Сеть Фейстеля
	feistelOutput, err := d.feistel.EncryptBlock(permutedBlock)
	if err != nil {
		return nil, fmt.Errorf("feistel encryption failed: %w", err)
	}

	// FP
	ciphertext, err := bitops.Permute(feistelOutput, FP, config)
	if err != nil {
		return nil, fmt.Errorf("final permutation failed: %w", err)
	}

	return ciphertext, nil
}

func (d *DESCipher) DecryptBlock(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != DESBlockSize {
		return nil, fmt.Errorf("block size must be %d bytes, got %d", DESBlockSize, len(ciphertext))
	}

	config := bitops.PermuteConfig{
		Indexing:  bitops.MSBFirst,
		Numbering: bitops.OneBased,
	}

	//  IP
	permutedBlock, err := bitops.Permute(ciphertext, IP, config)
	if err != nil {
		return nil, fmt.Errorf("initial permutation failed: %w", err)
	}

	// Сеть Фейстеля
	feistelOutput, err := d.feistel.DecryptBlock(permutedBlock)
	if err != nil {
		return nil, fmt.Errorf("feistel decryption failed: %w", err)
	}

	//  FP
	plaintext, err := bitops.Permute(feistelOutput, FP, config)
	if err != nil {
		return nil, fmt.Errorf("final permutation failed: %w", err)
	}

	return plaintext, nil
}

func (d *DESCipher) BlockSize() int {
	return DESBlockSize
}

