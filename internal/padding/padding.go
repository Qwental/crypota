package padding

import (
	"crypto/rand"
	"fmt"
)

type PaddingMode int

const (
	Zeros PaddingMode = iota
	ANSIX923
	PKCS7
	ISO10126
)

func Pad(data []byte, blockSize int, mode PaddingMode) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, fmt.Errorf("invalid block size: %d", blockSize)
	}

	paddingLen := blockSize - (len(data) % blockSize)

	padded := make([]byte, len(data)+paddingLen)
	copy(padded, data)

	switch mode {
	case Zeros:
	case ANSIX923:
		for i := len(data); i < len(padded)-1; i++ {
			padded[i] = 0
		}
		padded[len(padded)-1] = byte(paddingLen)
	case PKCS7:
		for i := len(data); i < len(padded); i++ {
			padded[i] = byte(paddingLen)
		}
	case ISO10126:
		if _, err := rand.Read(padded[len(data) : len(padded)-1]); err != nil {
			return nil, err
		}
		padded[len(padded)-1] = byte(paddingLen)
	default:
		return nil, fmt.Errorf("unknown padding mode: %d", mode)
	}

	return padded, nil
}

func Unpad(data []byte, mode PaddingMode) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot unpad empty data")
	}

	paddingLen := int(data[len(data)-1])

	if paddingLen == 0 || paddingLen > len(data) {
		return nil, fmt.Errorf("invalid padding length: %d", paddingLen)
	}

	switch mode {
	case Zeros:
		i := len(data) - 1
		for i >= 0 && data[i] == 0 {
			i--
		}
		return data[:i+1], nil
	case ANSIX923:
		for i := len(data) - paddingLen; i < len(data)-1; i++ {
			if data[i] != 0 {
				return nil, fmt.Errorf("invalid ANSI X9.23 padding")
			}
		}
		return data[:len(data)-paddingLen], nil
	case PKCS7:
		for i := len(data) - paddingLen; i < len(data); i++ {
			if data[i] != byte(paddingLen) {
				return nil, fmt.Errorf("invalid PKCS7 padding")
			}
		}
		return data[:len(data)-paddingLen], nil
	case ISO10126:
		return data[:len(data)-paddingLen], nil
	default:
		return nil, fmt.Errorf("unknown padding mode: %d", mode)
	}
}
