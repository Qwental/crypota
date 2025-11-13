package rijndael

import (
	"fmt"
	"sync"
)

type RijndaelCipher struct {
	blockSize int
	keySize   int
	numRounds int
	roundKeys [][]byte
	sbox      *SBox
	modPoly   byte
	mu        sync.RWMutex
}

func NewRijndaelCipher(blockSize, keySize int, modPoly byte) (*RijndaelCipher, error) {
	if blockSize != 16 && blockSize != 24 && blockSize != 32 {
		return nil, fmt.Errorf("invalid block size: %d (must be 16, 24, or 32)", blockSize)
	}
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid key size: %d (must be 16, 24, or 32)", keySize)
	}

	numRounds := calculateNumRounds(blockSize, keySize)

	return &RijndaelCipher{
		blockSize: blockSize,
		keySize:   keySize,
		numRounds: numRounds,
		modPoly:   modPoly,
	}, nil
}

func calculateNumRounds(blockSize, keySize int) int {
	nb := blockSize / 4
	nk := keySize / 4

	maxNkNb := nk
	if nb > nk {
		maxNkNb = nb
	}
	return maxNkNb + 6
}

func (r *RijndaelCipher) SetKey(key []byte) error {
	if len(key) != r.keySize {
		return fmt.Errorf("key size mismatch: expected %d, got %d", r.keySize, len(key))
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.sbox == nil {
		r.sbox = NewSBox(r.modPoly)
	}

	keygen := NewRijndaelKeyScheduler(r.blockSize, r.keySize, r.sbox)
	roundKeys, err := keygen.GenerateRoundKeys(key)
	if err != nil {
		return err
	}

	r.roundKeys = roundKeys
	return nil
}

func (r *RijndaelCipher) EncryptBlock(plaintext []byte) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(plaintext) != r.blockSize {
		return nil, fmt.Errorf("block size mismatch: expected %d, got %d", r.blockSize, len(plaintext))
	}

	if r.roundKeys == nil || r.sbox == nil {
		return nil, fmt.Errorf("key not set")
	}

	nb := r.blockSize / 4
	state := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		state[i] = make([]byte, nb)
		for j := 0; j < nb; j++ {
			state[i][j] = plaintext[j*4+i]
		}
	}

	state = addRoundKey(state, r.roundKeys[0])

	for round := 1; round < r.numRounds; round++ {
		state = subBytes(state, r.sbox, false)
		state = shiftRows(state, false)
		state = mixColumns(state, r.modPoly, false)
		state = addRoundKey(state, r.roundKeys[round])
	}

	state = subBytes(state, r.sbox, false)
	state = shiftRows(state, false)
	state = addRoundKey(state, r.roundKeys[r.numRounds])

	ciphertext := make([]byte, r.blockSize)
	for i := 0; i < 4; i++ {
		for j := 0; j < nb; j++ {
			ciphertext[j*4+i] = state[i][j]
		}
	}

	return ciphertext, nil
}

func (r *RijndaelCipher) DecryptBlock(ciphertext []byte) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(ciphertext) != r.blockSize {
		return nil, fmt.Errorf("block size mismatch: expected %d, got %d", r.blockSize, len(ciphertext))
	}

	if r.roundKeys == nil || r.sbox == nil {
		return nil, fmt.Errorf("key not set")
	}

	nb := r.blockSize / 4
	state := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		state[i] = make([]byte, nb)
		for j := 0; j < nb; j++ {
			state[i][j] = ciphertext[j*4+i]
		}
	}

	state = addRoundKey(state, r.roundKeys[r.numRounds])

	for round := r.numRounds - 1; round > 0; round-- {
		state = shiftRows(state, true)
		state = subBytes(state, r.sbox, true)
		state = addRoundKey(state, r.roundKeys[round])
		state = mixColumns(state, r.modPoly, true)
	}

	state = shiftRows(state, true)
	state = subBytes(state, r.sbox, true)
	state = addRoundKey(state, r.roundKeys[0])

	plaintext := make([]byte, r.blockSize)
	for i := 0; i < 4; i++ {
		for j := 0; j < nb; j++ {
			plaintext[j*4+i] = state[i][j]
		}
	}

	return plaintext, nil
}

func (r *RijndaelCipher) BlockSize() int {
	return r.blockSize
}

func addRoundKey(state [][]byte, roundKey []byte) [][]byte {
	nb := len(state[0])
	result := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = make([]byte, nb)
		for j := 0; j < nb; j++ {
			result[i][j] = state[i][j] ^ roundKey[j*4+i]
		}
	}
	return result
}
