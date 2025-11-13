package rijndael

import (
	"sync"

	"github.com/Qwental/crypota/internal/gfield"
)

type SBox struct {
	forward  []byte
	inverse  []byte
	modPoly  byte
	initOnce sync.Once
}

func NewSBox(modPoly byte) *SBox {
	return &SBox{
		modPoly: modPoly,
	}
}

func (s *SBox) initialize() {
	s.initOnce.Do(func() {
		s.forward = make([]byte, 256)
		s.inverse = make([]byte, 256)

		for i := 0; i < 256; i++ {
			val := byte(i)

			var invVal byte
			if val == 0 {
				invVal = 0
			} else {
				invVal = gfield.Inverse(val, s.modPoly)
			}

			result := invVal
			result ^= ((invVal << 1) | (invVal >> 7)) & 0xFF
			result ^= ((invVal << 2) | (invVal >> 6)) & 0xFF
			result ^= ((invVal << 3) | (invVal >> 5)) & 0xFF
			result ^= ((invVal << 4) | (invVal >> 4)) & 0xFF
			result ^= 0x63

			s.forward[i] = result
		}

		for i := 0; i < 256; i++ {
			s.inverse[s.forward[i]] = byte(i)
		}
	})
}

func (s *SBox) Sub(val byte) byte {
	s.initialize()
	return s.forward[val]
}

func (s *SBox) InvSub(val byte) byte {
	s.initialize()
	return s.inverse[val]
}
