package deal

import (
	"github.com/Qwental/crypota/internal/interfaces"
)

//  адаптирует DES для использования в качестве раундовой функции DEAL
type DESAdapter struct {
	desCipher interfaces.BlockCipher
}

func NewDESAdapter(desCipher interfaces.BlockCipher) *DESAdapter {
	return &DESAdapter{
		desCipher: desCipher,
	}
}

// Apply применяет DES как раундовую функцию
func (adapter *DESAdapter) Apply(block []byte, roundKey []byte) ([]byte, error) {
	if err := adapter.desCipher.SetKey(roundKey); err != nil {
		return nil, err
	}
	
	return adapter.desCipher.EncryptBlock(block)
}
