package interfaces

//  интерфейс для генерации раундовых ключей
type KeyScheduler interface {
	GenerateRoundKeys(key []byte) ([][]byte, error)
}

//  интерфейс для раундовой функции шифрования
type RoundFunction interface {
	
	Apply(block []byte, roundKey []byte) ([]byte, error) // Apply применяет раундовое преобразование к блоку данных
}

//  интерфейс для симметричного шифрования 
type BlockCipher interface {
	SetKey(key []byte) error	
	EncryptBlock(plaintext []byte) ([]byte, error)	
	DecryptBlock(ciphertext []byte) ([]byte, error)	
	BlockSize() int
}
