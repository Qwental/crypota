package deal

import (
	"fmt"
	"sync"

	"github.com/Qwental/crypota/internal/des"
	"github.com/Qwental/crypota/internal/interfaces"
)

const (
	DEALBlockSize = 16
)

// в стандарте написано что "Let K0 = 0x0123456789abcdef (hex notation) is a fixed DES-key"
var fixedKey = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

type DEALCipher struct {
	keySize   int
	numRounds int
	roundKeys [][]byte
	desCipher interfaces.BlockCipher
	mu        sync.RWMutex
}

func NewDEALCipher(keySize int) (interfaces.BlockCipher, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("DEAL key size must be 16, 24 or 32 bytes, got %d", keySize)
	}

	numRounds := 6
	if keySize == 32 {
		numRounds = 8
	}

	desCipher := des.NewDESCipher()

	return &DEALCipher{
		keySize:   keySize,
		numRounds: numRounds,
		desCipher: desCipher,
	}, nil
}

func (d *DEALCipher) generateRoundKeys(key []byte) ([][]byte, error) {
	if len(key) != d.keySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", d.keySize, len(key))
	}

	keyGenDES := des.NewDESCipher()
	if err := keyGenDES.SetKey(fixedKey); err != nil {
		return nil, err
	}

	numKeyBlocks := len(key) / 8
	keyBlocks := make([][]byte, numKeyBlocks)
	for i := 0; i < numKeyBlocks; i++ {
		keyBlocks[i] = make([]byte, 8)
		copy(keyBlocks[i], key[i*8:(i+1)*8])
	}

	roundKeys := make([][]byte, d.numRounds)
	prevRoundKey := make([]byte, 8)

	for round := 0; round < d.numRounds; round++ {
		keyBlockIndex := round % numKeyBlocks
		input := make([]byte, 8)
		copy(input, keyBlocks[keyBlockIndex])

		for i := 0; i < 8; i++ {
			input[i] ^= prevRoundKey[i]
		}

		if round >= numKeyBlocks {
			hConstant := generateHConstant(1 + round - numKeyBlocks)
			for i := 0; i < 8; i++ {
				input[i] ^= hConstant[i]
			}
		}

		encrypted, err := keyGenDES.EncryptBlock(input)
		if err != nil {
			return nil, err
		}

		roundKeys[round] = encrypted
		prevRoundKey = encrypted
	}

	return roundKeys, nil
}

func generateHConstant(bitPosition int) []byte {
	h := make([]byte, 8)
	byteIndex := bitPosition / 8
	bitIndex := bitPosition % 8
	if byteIndex < 8 {
		h[byteIndex] = 1 << bitIndex
	}
	return h
}

func (d *DEALCipher) SetKey(key []byte) error {
	if len(key) != d.keySize {
		return fmt.Errorf("key must be %d bytes, got %d", d.keySize, len(key))
	}

	roundKeys, err := d.generateRoundKeys(key)
	if err != nil {
		return err
	}

	d.mu.Lock()
	d.roundKeys = roundKeys
	d.mu.Unlock()

	return nil
}

func (d *DEALCipher) EncryptBlock(plaintext []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(plaintext) != DEALBlockSize {
		return nil, fmt.Errorf("block size must be %d bytes, got %d", DEALBlockSize, len(plaintext))
	}

	if d.roundKeys == nil {
		return nil, fmt.Errorf("key not set")
	}

	left := make([]byte, 8)
	right := make([]byte, 8)
	copy(left, plaintext[0:8])
	copy(right, plaintext[8:16])

	for round := 0; round < d.numRounds; round++ {
		if err := d.desCipher.SetKey(d.roundKeys[round]); err != nil {
			return nil, err
		}

		fOutput, err := d.desCipher.EncryptBlock(left)
		if err != nil {
			return nil, err
		}

		newRight := make([]byte, 8)
		for i := 0; i < 8; i++ {
			newRight[i] = fOutput[i] ^ right[i]
		}

		left, right = newRight, left
	}

	ciphertext := make([]byte, DEALBlockSize)
	copy(ciphertext[0:8], left)
	copy(ciphertext[8:16], right)

	return ciphertext, nil
}

func (d *DEALCipher) DecryptBlock(ciphertext []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(ciphertext) != DEALBlockSize {
		return nil, fmt.Errorf("block size must be %d bytes, got %d", DEALBlockSize, len(ciphertext))
	}

	if d.roundKeys == nil {
		return nil, fmt.Errorf("key not set")
	}

	left := make([]byte, 8)
	right := make([]byte, 8)
	copy(left, ciphertext[0:8])
	copy(right, ciphertext[8:16])

	for round := d.numRounds - 1; round >= 0; round-- {
		left, right = right, left

		if err := d.desCipher.SetKey(d.roundKeys[round]); err != nil {
			return nil, err
		}

		fOutput, err := d.desCipher.EncryptBlock(left)
		if err != nil {
			return nil, err
		}

		newRight := make([]byte, 8)
		for i := 0; i < 8; i++ {
			newRight[i] = fOutput[i] ^ right[i]
		}

		right = newRight
	}

	plaintext := make([]byte, DEALBlockSize)
	copy(plaintext[0:8], left)
	copy(plaintext[8:16], right)

	return plaintext, nil
}

func (d *DEALCipher) BlockSize() int {
	return DEALBlockSize
}
