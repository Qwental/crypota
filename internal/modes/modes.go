package modes

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/Qwental/crypota/internal/interfaces"
)

//  определяет режим шифрования
type CipherMode int

const (
	ECB CipherMode = iota
	CBC
	PCBC
	CFB
	OFB
	CTR
	RandomDelta
)

//  интерфейс для режима шифрования
type Mode interface {
	Encrypt(cipher interfaces.BlockCipher, plaintext []byte) ([]byte, error)
	Decrypt(cipher interfaces.BlockCipher, ciphertext []byte) ([]byte, error)
}


type ECBMode struct{}

func (m *ECBMode) Encrypt(cipher interfaces.BlockCipher, plaintext []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("plaintext length must be multiple of block size")
	}

	ciphertext := make([]byte, len(plaintext))
	numBlocks := len(plaintext) / blockSize

	// Параллельное шифрование блоков
	var wg sync.WaitGroup
	errChan := make(chan error, numBlocks)

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(blockIdx int) {
			defer wg.Done()
			offset := blockIdx * blockSize
			block := plaintext[offset : offset+blockSize]

			encryptedBlock, err := cipher.EncryptBlock(block)
			if err != nil {
				errChan <- fmt.Errorf("block %d encryption failed: %w", blockIdx, err)
				return
			}

			copy(ciphertext[offset:offset+blockSize], encryptedBlock)
		}(i)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func (m *ECBMode) Decrypt(cipher interfaces.BlockCipher, ciphertext []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	numBlocks := len(ciphertext) / blockSize

	var wg sync.WaitGroup
	errChan := make(chan error, numBlocks)

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(blockIdx int) {
			defer wg.Done()
			offset := blockIdx * blockSize
			block := ciphertext[offset : offset+blockSize]

			decryptedBlock, err := cipher.DecryptBlock(block)
			if err != nil {
				errChan <- fmt.Errorf("block %d decryption failed: %w", blockIdx, err)
				return
			}

			copy(plaintext[offset:offset+blockSize], decryptedBlock)
		}(i)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return nil, err
	}

	return plaintext, nil
}


type CBCMode struct {
	iv []byte
}

func NewCBCMode(iv []byte) *CBCMode {
	return &CBCMode{iv: iv}
}

func (m *CBCMode) Encrypt(cipher interfaces.BlockCipher, plaintext []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("plaintext length must be multiple of block size")
	}
	if len(m.iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	ciphertext := make([]byte, len(plaintext))
	prevBlock := make([]byte, blockSize)
	copy(prevBlock, m.iv)

	for i := 0; i < len(plaintext); i += blockSize {
		block := make([]byte, blockSize)
		copy(block, plaintext[i:i+blockSize])

		for j := 0; j < blockSize; j++ {
			block[j] ^= prevBlock[j]
		}

		encryptedBlock, err := cipher.EncryptBlock(block)
		if err != nil {
			return nil, err
		}

		copy(ciphertext[i:i+blockSize], encryptedBlock)
		copy(prevBlock, encryptedBlock)
	}

	return ciphertext, nil
}

func (m *CBCMode) Decrypt(cipher interfaces.BlockCipher, ciphertext []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}
	if len(m.iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	plaintext := make([]byte, len(ciphertext))
	prevBlock := make([]byte, blockSize)
	copy(prevBlock, m.iv)

	for i := 0; i < len(ciphertext); i += blockSize {
		block := ciphertext[i : i+blockSize]

		decryptedBlock, err := cipher.DecryptBlock(block)
		if err != nil {
			return nil, err
		}

		for j := 0; j < blockSize; j++ {
			decryptedBlock[j] ^= prevBlock[j]
		}

		copy(plaintext[i:i+blockSize], decryptedBlock)
		copy(prevBlock, block)
	}

	return plaintext, nil
}

type CTRMode struct {
	iv []byte
}

func NewCTRMode(iv []byte) *CTRMode {
	return &CTRMode{iv: iv}
}

func (m *CTRMode) Encrypt(cipher interfaces.BlockCipher, plaintext []byte) ([]byte, error) {
	return m.process(cipher, plaintext)
}

func (m *CTRMode) Decrypt(cipher interfaces.BlockCipher, ciphertext []byte) ([]byte, error) {
	return m.process(cipher, ciphertext)
}

func (m *CTRMode) process(cipher interfaces.BlockCipher, data []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(m.iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	output := make([]byte, len(data))
	numBlocks := (len(data) + blockSize - 1) / blockSize

	// Параллельная обработка счетчиков
	var wg sync.WaitGroup
	errChan := make(chan error, numBlocks)

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(blockIdx int) {
			defer wg.Done()

			blockCounter := make([]byte, blockSize)
			copy(blockCounter, m.iv)
			incrementCounter(blockCounter, blockIdx)

			encryptedCounter, err := cipher.EncryptBlock(blockCounter)
			if err != nil {
				errChan <- err
				return
			}

			offset := blockIdx * blockSize
			end := offset + blockSize
			if end > len(data) {
				end = len(data)
			}

			for j := offset; j < end; j++ {
				output[j] = data[j] ^ encryptedCounter[j-offset]
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return nil, err
	}

	return output, nil
}

func incrementCounter(counter []byte, value int) {
	for i := len(counter) - 1; i >= 0 && value > 0; i-- {
		sum := int(counter[i]) + value
		counter[i] = byte(sum & 0xFF)
		value = sum >> 8
	}
}


type PCBCMode struct {
	iv []byte
}

func NewPCBCMode(iv []byte) *PCBCMode {
	return &PCBCMode{iv: iv}
}

func (m *PCBCMode) Encrypt(cipher interfaces.BlockCipher, plaintext []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("plaintext length must be multiple of block size")
	}
	if len(m.iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	ciphertext := make([]byte, len(plaintext))
	prevXOR := make([]byte, blockSize)
	copy(prevXOR, m.iv)

	for i := 0; i < len(plaintext); i += blockSize {
		block := make([]byte, blockSize)
		copy(block, plaintext[i:i+blockSize])

		for j := 0; j < blockSize; j++ {
			block[j] ^= prevXOR[j]
		}

		encryptedBlock, err := cipher.EncryptBlock(block)
		if err != nil {
			return nil, err
		}

		copy(ciphertext[i:i+blockSize], encryptedBlock)

		for j := 0; j < blockSize; j++ {
			prevXOR[j] = plaintext[i+j] ^ encryptedBlock[j]
		}
	}

	return ciphertext, nil
}

func (m *PCBCMode) Decrypt(cipher interfaces.BlockCipher, ciphertext []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}
	if len(m.iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	plaintext := make([]byte, len(ciphertext))
	prevXOR := make([]byte, blockSize)
	copy(prevXOR, m.iv)

	for i := 0; i < len(ciphertext); i += blockSize {
		block := ciphertext[i : i+blockSize]

		decryptedBlock, err := cipher.DecryptBlock(block)
		if err != nil {
			return nil, err
		}

		for j := 0; j < blockSize; j++ {
			decryptedBlock[j] ^= prevXOR[j]
		}

		copy(plaintext[i:i+blockSize], decryptedBlock)

		for j := 0; j < blockSize; j++ {
			prevXOR[j] = decryptedBlock[j] ^ block[j]
		}
	}

	return plaintext, nil
}

type CFBMode struct {
	iv []byte
}

func NewCFBMode(iv []byte) *CFBMode {
	return &CFBMode{iv: iv}
}

func (m *CFBMode) Encrypt(cipher interfaces.BlockCipher, plaintext []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(m.iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	ciphertext := make([]byte, len(plaintext))
	prevBlock := make([]byte, blockSize)
	copy(prevBlock, m.iv)

	for i := 0; i < len(plaintext); i += blockSize {
		encryptedBlock, err := cipher.EncryptBlock(prevBlock)
		if err != nil {
			return nil, err
		}

		end := i + blockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		currentSize := end - i

		for j := 0; j < currentSize; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ encryptedBlock[j]
		}

		if currentSize == blockSize {
			copy(prevBlock, ciphertext[i:i+blockSize])
		} else {
			copy(prevBlock, prevBlock[currentSize:])
			copy(prevBlock[blockSize-currentSize:], ciphertext[i:end])
		}
	}

	return ciphertext, nil
}

func (m *CFBMode) Decrypt(cipher interfaces.BlockCipher, ciphertext []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(m.iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	plaintext := make([]byte, len(ciphertext))
	prevBlock := make([]byte, blockSize)
	copy(prevBlock, m.iv)

	for i := 0; i < len(ciphertext); i += blockSize {
		encryptedBlock, err := cipher.EncryptBlock(prevBlock)
		if err != nil {
			return nil, err
		}

		end := i + blockSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		currentSize := end - i

		for j := 0; j < currentSize; j++ {
			plaintext[i+j] = ciphertext[i+j] ^ encryptedBlock[j]
		}

		if currentSize == blockSize {
			copy(prevBlock, ciphertext[i:i+blockSize])
		} else {
			copy(prevBlock, prevBlock[currentSize:])
			copy(prevBlock[blockSize-currentSize:], ciphertext[i:end])
		}
	}

	return plaintext, nil
}

type OFBMode struct {
	iv []byte
}

func NewOFBMode(iv []byte) *OFBMode {
	return &OFBMode{iv: iv}
}

func (m *OFBMode) Encrypt(cipher interfaces.BlockCipher, plaintext []byte) ([]byte, error) {
	return m.process(cipher, plaintext)
}

func (m *OFBMode) Decrypt(cipher interfaces.BlockCipher, ciphertext []byte) ([]byte, error) {
	return m.process(cipher, ciphertext)
}

func (m *OFBMode) process(cipher interfaces.BlockCipher, data []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(m.iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	output := make([]byte, len(data))
	feedback := make([]byte, blockSize)
	copy(feedback, m.iv)

	for i := 0; i < len(data); i += blockSize {
		encryptedFeedback, err := cipher.EncryptBlock(feedback)
		if err != nil {
			return nil, err
		}

		end := i + blockSize
		if end > len(data) {
			end = len(data)
		}

		for j := i; j < end; j++ {
			output[j] = data[j] ^ encryptedFeedback[j-i]
		}

		copy(feedback, encryptedFeedback)
	}

	return output, nil
}

type RandomDeltaMode struct {
	iv []byte
}

func NewRandomDeltaMode(iv []byte) *RandomDeltaMode {
	return &RandomDeltaMode{iv: iv}
}

func (m *RandomDeltaMode) Encrypt(cipher interfaces.BlockCipher, plaintext []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(m.iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	numBlocks := (len(plaintext) + blockSize - 1) / blockSize
	deltas := make([][]byte, numBlocks)
	for i := 0; i < numBlocks; i++ {
		deltas[i] = make([]byte, blockSize)
		rand.Read(deltas[i])
	}

	ciphertext := make([]byte, len(deltas)*blockSize+len(plaintext))
	offset := 0
	for _, delta := range deltas {
		copy(ciphertext[offset:offset+blockSize], delta)
		offset += blockSize
	}

	prevBlock := make([]byte, blockSize)
	copy(prevBlock, m.iv)

	for i := 0; i < len(plaintext); i += blockSize {
		block := make([]byte, blockSize)
		end := i + blockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		copy(block, plaintext[i:end])

		deltaIdx := i / blockSize
		for j := 0; j < len(block); j++ {
			block[j] ^= prevBlock[j] ^ deltas[deltaIdx][j]
		}

		encryptedBlock, err := cipher.EncryptBlock(block)
		if err != nil {
			return nil, err
		}

		copy(ciphertext[offset:offset+len(block)], encryptedBlock[:len(block)])
		copy(prevBlock, encryptedBlock)
		offset += len(block)
	}

	return ciphertext, nil
}

func (m *RandomDeltaMode) Decrypt(cipher interfaces.BlockCipher, ciphertext []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(m.iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	numBlocks := (len(ciphertext) / blockSize) / 2
	if numBlocks == 0 {
		return nil, fmt.Errorf("invalid ciphertext length")
	}

	deltas := make([][]byte, numBlocks)
	offset := 0
	for i := 0; i < numBlocks; i++ {
		deltas[i] = make([]byte, blockSize)
		copy(deltas[i], ciphertext[offset:offset+blockSize])
		offset += blockSize
	}

	dataLen := len(ciphertext) - offset
	plaintext := make([]byte, dataLen)
	prevBlock := make([]byte, blockSize)
	copy(prevBlock, m.iv)

	for i := 0; i < dataLen; i += blockSize {
		end := i + blockSize
		if end > dataLen {
			end = dataLen
		}
		block := ciphertext[offset+i : offset+end]

		decryptedBlock, err := cipher.DecryptBlock(block)
		if err != nil {
			return nil, err
		}

		deltaIdx := i / blockSize
		for j := 0; j < len(decryptedBlock); j++ {
			decryptedBlock[j] ^= prevBlock[j] ^ deltas[deltaIdx][j]
		}

		copy(plaintext[i:end], decryptedBlock[:end-i])
		copy(prevBlock, block)
	}

	return plaintext, nil
}

func GenerateIV(size int) ([]byte, error) {
	iv := make([]byte, size)
	_, err := rand.Read(iv)
	return iv, err
}
