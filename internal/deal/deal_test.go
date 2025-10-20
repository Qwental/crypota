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

func TestDEAL_AllKeySizesAndModes(t *testing.T) {
	keySizes := []int{16, 24, 32}

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

	plaintextSizes := []int{15, 16, 32, 100, 2048}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("KeySize-%d", keySize*8), func(t *testing.T) {
			for _, modeInfo := range modesToTest {
				t.Run(fmt.Sprintf("Mode-%s", modeInfo.name), func(t *testing.T) {
					for _, size := range plaintextSizes {
						t.Run(fmt.Sprintf("Plaintext-%d-bytes", size), func(t *testing.T) {
							key := make([]byte, keySize)
							rand.Read(key)

							plaintext := make([]byte, size)
							rand.Read(plaintext)

							cipher, err := NewDEALCipher(keySize)
							if err != nil {
								t.Fatalf("Не удалось создать DEAL-шифр: %v", err)
							}

							var iv []byte
							if modeInfo.mode != modes.ECB {
								iv = make([]byte, cipher.BlockSize())
								rand.Read(iv)
							}

							ctx, err := context.NewCipherContext(cipher, key, modeInfo.mode, padding.PKCS7, iv)
							if err != nil {
								t.Fatalf("Не удалось создать контекст шифрования: %v", err)
							}

							ciphertext, err := ctx.Encrypt(plaintext)
							if err != nil {
								t.Fatalf("Ошибка шифрования: %v", err)
							}

							decrypted, err := ctx.Decrypt(ciphertext)
							if err != nil {
								t.Logf("--- DEBUG INFO ON FAILURE ---")
								t.Logf("Key: %x", key)
								if iv != nil {
									t.Logf("IV: %x", iv)
								}
								t.Logf("Plaintext (%d bytes): %x", len(plaintext), plaintext)
								t.Logf("Ciphertext (%d bytes): %x", len(ciphertext), ciphertext)
								t.Fatalf("Ошибка дешифрования: %v", err)
							}

							if !bytes.Equal(decrypted, plaintext) {
								t.Errorf("Дешифрованный текст не совпадает с исходным.")
								t.Logf("--- DEBUG INFO ON MISMATCH ---")
								t.Logf("Key: %x", key)
								if iv != nil {
									t.Logf("IV: %x", iv)
								}
								t.Logf("Plaintext (%d bytes): %x", len(plaintext), plaintext)
								t.Logf("Ciphertext (%d bytes): %x", len(ciphertext), ciphertext)
								t.Logf("Decrypted (%d bytes): %x", len(decrypted), decrypted)

								for i := 0; i < len(plaintext); i++ {
									if i >= len(decrypted) {
										t.Errorf("Длина дешифрованного текста (%d) меньше исходного (%d).", len(decrypted), len(plaintext))
										break
									}
									if decrypted[i] != plaintext[i] {
										t.Errorf("Первое несовпадение на байте %d: ожидалось %02x, получено %02x", i, plaintext[i], decrypted[i])
										break
									}
								}
								if len(decrypted) > len(plaintext) {
									t.Errorf("Длина дешифрованного текста (%d) больше исходного (%d).", len(decrypted), len(plaintext))
								}
							}
						})
					}
				})
			}
		})
	}
}
