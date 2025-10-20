package des

import (
	"fmt"
	"github.com/Qwental/crypota/internal/bitops"
)

type DESRoundFunction struct{}

func NewDESRoundFunction() *DESRoundFunction {
	return &DESRoundFunction{}
}

func (rf *DESRoundFunction) Apply(block []byte, roundKey []byte) ([]byte, error) {
	if len(block) != 4 {
		return nil, fmt.Errorf("DES round function expects 4 bytes (32 bits), got %d", len(block))
	}
	if len(roundKey) != 6 {
		return nil, fmt.Errorf("DES round key must be 6 bytes (48 bits), got %d", len(roundKey))
	}

	config := bitops.PermuteConfig{
		Indexing:  bitops.MSBFirst,
		Numbering: bitops.OneBased,
	}

	// E  32 в 48 
	expanded, err := bitops.Permute(block, E, config)
	if err != nil {
		return nil, fmt.Errorf("expansion failed: %w", err)
	}

	// + с ключем
	for i := 0; i < 6; i++ {
		expanded[i] ^= roundKey[i]
	}

	// S 48 в 32 
	sboxOutput := make([]byte, 4)
	for i := 0; i < 8; i++ {
		bitPos := i * 6
		byteIdx := bitPos / 8
		bitInByte := bitPos % 8

		var sixBits uint8
		if bitInByte <= 2 {
			sixBits = (expanded[byteIdx] >> (2 - bitInByte)) & 0x3F
		} else {
			high := expanded[byteIdx] << (bitInByte - 2)
			low := expanded[byteIdx+1] >> (10 - bitInByte)
			sixBits = (high | low) & 0x3F
		}

		// row = 2*b1 + b6
		row := ((sixBits & 0x20) >> 4) | (sixBits & 0x01)
		col := (sixBits >> 1) & 0x0F
		sboxValue := SBoxes[i][row][col]

		if i%2 == 0 {
			sboxOutput[i/2] = sboxValue << 4
		} else {
			sboxOutput[i/2] |= sboxValue
		}
	}


	result, err := bitops.Permute(sboxOutput, P, config)
	if err != nil {
		return nil, fmt.Errorf("P permutation failed: %w", err)
	}

	return result, nil
}
