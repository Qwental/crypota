package deal

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/Qwental/crypota/internal/context"
	"github.com/Qwental/crypota/internal/modes"
	"github.com/Qwental/crypota/internal/padding"
)

// TestDEAL_EncryptDecrypt_RoundTrip проверяет базовый цикл шифрования-дешифрования для одного блока.
func TestDEAL_EncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := make([]byte, 16)
	for i := range plaintext {
		plaintext[i] = byte(i * 2)
	}

	cipher, err := NewDEALCipher(16)
	if err != nil {
		t.Fatalf("Не удалось создать DEAL-шифр: %v", err)
	}

	err = cipher.SetKey(key)
	if err != nil {
		t.Fatalf("Не удалось установить ключ: %v", err)
	}

	ciphertext, err := cipher.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("Ошибка шифрования блока: %v", err)
	}

	decrypted, err := cipher.DecryptBlock(ciphertext)
	if err != nil {
		t.Fatalf("Ошибка дешифрования блока: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Дешифрование не удалось: получено %x, ожидалось %x", decrypted, plaintext)
	}
}

// TestDEAL_AllKeySizesAndModes - это комплексный тест, который проверяет все размеры ключей DEAL
// со всеми режимами шифрования и разными размерами входных данных.
func TestDEAL_AllKeySizesAndModes(t *testing.T) {
	keySizes := []int{16, 24, 32} // 128, 192, 256 бит

	modesToTest := []struct {
		mode modes.CipherMode
		name string
	}{
		{modes.ECB, "ECB"},
		{modes.CBC, "CBC"},
		{modes.PCBC, "PCBC"},
		{modes.CFB, "CFB"},
		{modes.OFB, "OFB"},
		{modes.CTR, "CTR"},
	}

	// Различные размеры данных для проверки, включая некратные размеру блока
	plaintextSizes := []int{15, 16, 32, 100, 2048}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("KeySize-%d", keySize*8), func(t *testing.T) {
			for _, modeInfo := range modesToTest {
				t.Run(fmt.Sprintf("Mode-%s", modeInfo.name), func(t *testing.T) {
					for _, size := range plaintextSizes {
						t.Run(fmt.Sprintf("Plaintext-%d-bytes", size), func(t *testing.T) {
							// 1. Подготовка данных
							key := make([]byte, keySize)
							rand.Read(key)

							plaintext := make([]byte, size)
							rand.Read(plaintext)

							// 2. Создание шифра
							cipher, err := NewDEALCipher(keySize)
							if err != nil {
								t.Fatalf("Не удалось создать DEAL-шифр: %v", err)
							}

							// 3. Создание контекста шифрования
							var iv []byte
							if modeInfo.mode != modes.ECB {
								iv = make([]byte, cipher.BlockSize())
								rand.Read(iv)
							}

							ctx, err := context.NewCipherContext(
								cipher,
								key,
								modeInfo.mode,
								padding.PKCS7,
								iv,
							)
							if err != nil {
								t.Fatalf("Не удалось создать контекст шифрования: %v", err)
							}

							// 4. Шифрование и дешифрование
							ciphertext, err := ctx.Encrypt(plaintext)
							if err != nil {
								t.Fatalf("Ошибка шифрования: %v", err)
							}

							decrypted, err := ctx.Decrypt(ciphertext)
							if err != nil {
								t.Fatalf("Ошибка дешифрования: %v", err)
							}

							// 5. Проверка результата
							if !bytes.Equal(decrypted, plaintext) {
								t.Errorf("Дешифрованный текст не совпадает с исходным")
								t.Errorf("  Исходный (%d): %x...", len(plaintext), plaintext[:min(16, len(plaintext))])
								t.Errorf("  Полученный (%d): %x...", len(decrypted), decrypted[:min(16, len(decrypted))])
							}
						})
					}
				})
			}
		})
	}
}

// Вспомогательная функция для безопасного среза
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
