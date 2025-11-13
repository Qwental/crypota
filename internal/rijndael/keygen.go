package rijndael

import (
	"fmt"

	"github.com/Qwental/crypota/internal/gfield"
)

type RijndaelKeyScheduler struct {
	blockSize int
	keySize   int
	sbox      *SBox
}

func NewRijndaelKeyScheduler(blockSize, keySize int, sbox *SBox) *RijndaelKeyScheduler {
	return &RijndaelKeyScheduler{
		blockSize: blockSize,
		keySize:   keySize,
		sbox:      sbox,
	}
}

func (ks *RijndaelKeyScheduler) GenerateRoundKeys(key []byte) ([][]byte, error) {
	if len(key) != ks.keySize {
		return nil, fmt.Errorf("key size mismatch")
	}

	nk := ks.keySize / 4
	nb := ks.blockSize / 4
	nr := calculateNumRounds(ks.blockSize, ks.keySize)

	w := make([][]byte, nb*(nr+1))
	for i := 0; i < len(w); i++ {
		w[i] = make([]byte, 4)
	}

	for i := 0; i < nk; i++ {
		w[i] = []byte{key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]}
	}

	for i := nk; i < nb*(nr+1); i++ {
		temp := make([]byte, 4)
		copy(temp, w[i-1])

		if i%nk == 0 {
			temp = ks.subWord(ks.rotWord(temp))
			temp[0] ^= rcon(i / nk)
		} else if nk > 6 && i%nk == 4 {
			temp = ks.subWord(temp)
		}

		for j := 0; j < 4; j++ {
			w[i][j] = w[i-nk][j] ^ temp[j]
		}
	}

	roundKeys := make([][]byte, nr+1)
	for r := 0; r <= nr; r++ {
		roundKeys[r] = make([]byte, nb*4)
		for c := 0; c < nb; c++ {
			for row := 0; row < 4; row++ {
				roundKeys[r][c*4+row] = w[r*nb+c][row]
			}
		}
	}

	return roundKeys, nil
}

func (ks *RijndaelKeyScheduler) rotWord(word []byte) []byte {
	return []byte{word[1], word[2], word[3], word[0]}
}

func (ks *RijndaelKeyScheduler) subWord(word []byte) []byte {
	result := make([]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = ks.sbox.Sub(word[i])
	}
	return result
}

func rcon(i int) byte {
	if i == 0 {
		return 0
	}

	val := byte(1)
	for j := 1; j < i; j++ {
		val = gfield.MultiplyByMod(val, 0x02, 0x1B)
	}
	return val
}
