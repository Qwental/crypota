package rijndael

import (
	"github.com/Qwental/crypota/internal/gfield"
)

func subBytes(state [][]byte, sbox *SBox, inverse bool) [][]byte {
	nb := len(state[0])
	result := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = make([]byte, nb)
		for j := 0; j < nb; j++ {
			if inverse {
				result[i][j] = sbox.InvSub(state[i][j])
			} else {
				result[i][j] = sbox.Sub(state[i][j])
			}
		}
	}
	return result
}

func shiftRows(state [][]byte, inverse bool) [][]byte {
	nb := len(state[0])
	result := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = make([]byte, nb)
	}

	for r := 0; r < 4; r++ {
		var shift int
		if nb == 4 {
			shift = r
		} else if nb == 6 {
			shift = []int{0, 1, 2, 3}[r]
		} else {
			shift = []int{0, 1, 3, 4}[r]
		}

		for c := 0; c < nb; c++ {
			var sourceCol int
			if inverse {
				sourceCol = (c + shift) % nb
			} else {
				sourceCol = (c - shift + nb) % nb
			}
			result[r][c] = state[r][sourceCol]
		}
	}

	return result
}

func mixColumns(state [][]byte, modPoly byte, inverse bool) [][]byte {
	nb := len(state[0])
	result := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = make([]byte, nb)
	}

	var matrix [][]byte
	if inverse {
		matrix = [][]byte{
			{0x0e, 0x0b, 0x0d, 0x09},
			{0x09, 0x0e, 0x0b, 0x0d},
			{0x0d, 0x09, 0x0e, 0x0b},
			{0x0b, 0x0d, 0x09, 0x0e},
		}
	} else {
		matrix = [][]byte{
			{0x02, 0x03, 0x01, 0x01},
			{0x01, 0x02, 0x03, 0x01},
			{0x01, 0x01, 0x02, 0x03},
			{0x03, 0x01, 0x01, 0x02},
		}
	}

	for c := 0; c < nb; c++ {
		for r := 0; r < 4; r++ {
			var sum byte
			for k := 0; k < 4; k++ {
				prod := gfield.MultiplyByMod(matrix[r][k], state[k][c], modPoly)
				sum ^= prod
			}
			result[r][c] = sum
		}
	}

	return result
}
