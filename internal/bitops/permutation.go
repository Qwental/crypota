package bitops

import "fmt"

type BitIndexing int //  определяет способ индексации битов

const (
	LSBFirst BitIndexing = iota // LSBFirst биты  от младшего к старшему
	MSBFirst                    // MSBFirst биты  от старшего к младшему
)

type BitNumbering int //  определяет номер начального бита

const (
	ZeroBased BitNumbering = iota // нумерация  с 0
	OneBased                      // нумерация с 1
)

// PermuteConfig содержит конфигурацию для перестановки битов
type PermuteConfig struct {
	Indexing  BitIndexing
	Numbering BitNumbering
}

// перестановку битов согласно P-блоку
func Permute(data []byte, pBlock []int, config PermuteConfig) ([]byte, error) {
	totalBits := len(data) * 8
	outputBits := len(pBlock)

	if outputBits == 0 {
		return nil, fmt.Errorf("P-block cannot be empty")
	}

	// байты в биты
	bits := bytesToBits(data, config.Indexing == LSBFirst)

	outputBitArray := make([]int, outputBits)
	for i, srcBitNum := range pBlock {
		// Корректируем номер бита с учетом нумерации
		if config.Numbering == OneBased {
			srcBitNum--
		}

		if srcBitNum < 0 || srcBitNum >= totalBits {
			return nil, fmt.Errorf("bit index %d out of range [0, %d)", srcBitNum, totalBits)
		}

		outputBitArray[i] = bits[srcBitNum]
	}

	return bitsToBytes(outputBitArray, config.Indexing == LSBFirst), nil
}

func bytesToBits(bytes []byte, indexFromLSB bool) []int {
	bits := make([]int, 0, len(bytes)*8)

	for _, b := range bytes {
		if indexFromLSB {
			// От младшего к старшему
			for i := 0; i < 8; i++ {
				bits = append(bits, int((b>>i)&1))
			}
		} else {
			// От старшего к младшему
			for i := 7; i >= 0; i-- {
				bits = append(bits, int((b>>i)&1))
			}
		}
	}

	return bits
}

func bitsToBytes(bits []int, indexFromLSB bool) []byte {
	numBytes := (len(bits) + 7) / 8
	result := make([]byte, numBytes)

	for i := 0; i < len(bits); i += 8 {
		end := i + 8
		if end > len(bits) {
			end = len(bits)
		}

		chunk := bits[i:end]
		var b byte

		if indexFromLSB {
			// От младшего к старшему
			for j := len(chunk) - 1; j >= 0; j-- {
				b = (b << 1) | byte(chunk[j])
			}
		} else {
			// От старшего к младшему
			for j := 0; j < len(chunk); j++ {
				b = (b << 1) | byte(chunk[j])
			}
		}

		result[i/8] = b
	}

	return result
}
