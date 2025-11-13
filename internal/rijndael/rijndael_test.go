package rijndael

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/Qwental/crypota/internal/context"
	"github.com/Qwental/crypota/internal/modes"
	"github.com/Qwental/crypota/internal/padding"
)

func TestRijndael128x128(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)

	cipher, err := NewRijndaelCipher(16, 16, 0x1B)
	if err != nil {
		t.Fatalf("NewRijndaelCipher failed: %v", err)
	}

	if err := cipher.SetKey(key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	plaintext := []byte("1234567890123456")
	ciphertext, err := cipher.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	decrypted, err := cipher.DecryptBlock(ciphertext)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Round-trip failed")
	}
}

func TestRijndaelAllSizes(t *testing.T) {
	sizes := []int{16, 24, 32}

	for _, blockSize := range sizes {
		for _, keySize := range sizes {
			t.Run("", func(t *testing.T) {
				key := make([]byte, keySize)
				rand.Read(key)

				cipher, err := NewRijndaelCipher(blockSize, keySize, 0x1B)
				if err != nil {
					t.Fatalf("NewRijndaelCipher failed: %v", err)
				}

				if err := cipher.SetKey(key); err != nil {
					t.Fatalf("SetKey failed: %v", err)
				}

				plaintext := make([]byte, blockSize)
				rand.Read(plaintext)

				ciphertext, err := cipher.EncryptBlock(plaintext)
				if err != nil {
					t.Fatalf("EncryptBlock failed: %v", err)
				}

				decrypted, err := cipher.DecryptBlock(ciphertext)
				if err != nil {
					t.Fatalf("DecryptBlock failed: %v", err)
				}

				if !bytes.Equal(plaintext, decrypted) {
					t.Errorf("Round-trip failed")
				}
			})
		}
	}
}

func TestRijndaelWithContext(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)

	cipher, err := NewRijndaelCipher(16, 16, 0x1B)
	if err != nil {
		t.Fatalf("NewRijndaelCipher failed: %v", err)
	}

	iv := make([]byte, 16)
	rand.Read(iv)

	ctx, err := context.NewCipherContext(cipher, key, modes.CBC, padding.PKCS7, iv)
	if err != nil {
		t.Fatalf("NewCipherContext failed: %v", err)
	}

	plaintext := []byte("Hello, Rijndael! This is a test message for CBC mode.")

	ciphertext, err := ctx.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := ctx.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Round-trip with context failed")
	}
}

func TestRijndaelCustomModulus(t *testing.T) {
	moduli := []byte{0x1B, 0xF5}

	for _, mod := range moduli {
		t.Run("", func(t *testing.T) {
			key := make([]byte, 16)
			rand.Read(key)

			cipher, err := NewRijndaelCipher(16, 16, mod)
			if err != nil {
				t.Fatalf("NewRijndaelCipher failed: %v", err)
			}

			if err := cipher.SetKey(key); err != nil {
				t.Fatalf("SetKey failed: %v", err)
			}

			plaintext := make([]byte, 16)
			rand.Read(plaintext)

			ciphertext, err := cipher.EncryptBlock(plaintext)
			if err != nil {
				t.Fatalf("EncryptBlock failed: %v", err)
			}

			decrypted, err := cipher.DecryptBlock(ciphertext)
			if err != nil {
				t.Fatalf("DecryptBlock failed: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("Round-trip with custom modulus failed")
			}
		})
	}
}

func TestRijndaelComprehensive(t *testing.T) {
	blockSizes := []int{16, 24, 32}
	keySizes := []int{16, 24, 32}
	paddingModes := []struct {
		Mode padding.PaddingMode
		Name string
	}{
		{padding.Zeros, "Zeros"},
		{padding.ANSIX923, "ANSIX923"},
		{padding.PKCS7, "PKCS7"},
		{padding.ISO10126, "ISO10126"},
	}
	cipherModes := []struct {
		Mode modes.CipherMode
		Name string
	}{
		{modes.ECB, "ECB"},
		{modes.CBC, "CBC"},
		{modes.PCBC, "PCBC"},
		{modes.CFB, "CFB"},
		{modes.OFB, "OFB"},
		{modes.CTR, "CTR"},
	}

	plaintext := []byte("This is a comprehensive test for Rijndael encryption with various configurations.")

	for _, blockSize := range blockSizes {
		for _, keySize := range keySizes {
			for _, pm := range paddingModes {
				for _, cm := range cipherModes {
					testName := fmt.Sprintf("Block%d_Key%d_%s_%s", blockSize, keySize, pm.Name, cm.Name)
					t.Run(testName, func(t *testing.T) {
						key := make([]byte, keySize)
						if _, err := rand.Read(key); err != nil {
							t.Fatalf("Failed to generate random key: %v", err)
						}

						cipher, err := NewRijndaelCipher(blockSize, keySize, 0x1B)
						if err != nil {
							t.Fatalf("NewRijndaelCipher failed: %v", err)
						}

						var iv []byte
						if cm.Mode != modes.ECB {
							iv = make([]byte, blockSize)
							if _, err := rand.Read(iv); err != nil {
								t.Fatalf("Failed to generate IV: %v", err)
							}
						}

						ctx, err := context.NewCipherContext(
							cipher,
							key,
							cm.Mode,
							pm.Mode,
							iv,
						)
						if err != nil {
							t.Fatalf("NewCipherContext failed: %v", err)
						}

						ciphertext, err := ctx.Encrypt(plaintext)
						if err != nil {
							t.Fatalf("Encrypt failed: %v", err)
						}

						decrypted, err := ctx.Decrypt(ciphertext)
						if err != nil {
							t.Fatalf("Decrypt failed: %v", err)
						}

						if !bytes.Equal(plaintext, decrypted) {
							t.Errorf("Decryption result does not match original plaintext")
						}
					})
				}
			}
		}
	}
}
