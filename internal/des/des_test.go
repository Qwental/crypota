package des

import (
	"bytes"
	"crypto/des"
	"encoding/hex"
	"testing"
)


func TestDESAgainstStandardLibrary(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		plaintext string
	}{
		{
			name:      "Test vector 1",
			key:       "133457799BBCDFF1",
			plaintext: "0123456789ABCDEF",
		},
		{
			name:      "Test vector 2",
			key:       "0101010101010101",
			plaintext: "0000000000000000",
		},
		{
			name:      "Test vector 3",
			key:       "FEDCBA9876543210",
			plaintext: "FEDCBA9876543210",
		},
		{
			name:      "Test vector 4",
			key:       "0123456789ABCDEF",
			plaintext: "0011223344556677",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tt.key)
			plaintext, _ := hex.DecodeString(tt.plaintext)

			t.Logf("Key:       %s", tt.key)
			t.Logf("Plaintext: %s", tt.plaintext)

			// Шифруем стандартной библиотекой Go
			stdCipher, err := des.NewCipher(key)
			if err != nil {
				t.Fatalf("Standard DES NewCipher failed: %v", err)
			}
			stdCiphertext := make([]byte, len(plaintext))
			stdCipher.Encrypt(stdCiphertext, plaintext)
			t.Logf("Standard library ciphertext: %s", hex.EncodeToString(stdCiphertext))

			// Шифруем нашей реализацией
			ourCipher := NewDESCipher()
			if err := ourCipher.SetKey(key); err != nil {
				t.Fatalf("Our DES SetKey failed: %v", err)
			}
			ourCiphertext, err := ourCipher.EncryptBlock(plaintext)
			if err != nil {
				t.Fatalf("Our DES EncryptBlock failed: %v", err)
			}
			t.Logf("Our implementation ciphertext: %s", hex.EncodeToString(ourCiphertext))

			// Сравниваем шифртекст
			if !bytes.Equal(stdCiphertext, ourCiphertext) {
				t.Errorf("Encryption mismatch")
				t.Errorf("  Standard: %s", hex.EncodeToString(stdCiphertext))
				t.Errorf("  Ours:     %s", hex.EncodeToString(ourCiphertext))
			} else {
				t.Logf("Encryption matches standard library")
			}

			// Проверяем дешифрование
			ourPlaintext, err := ourCipher.DecryptBlock(ourCiphertext)
			if err != nil {
				t.Fatalf("Our DES DecryptBlock failed: %v", err)
			}

			if !bytes.Equal(plaintext, ourPlaintext) {
				t.Errorf("Decryption failed")
				t.Errorf("  Expected: %s", hex.EncodeToString(plaintext))
				t.Errorf("  Got:      %s", hex.EncodeToString(ourPlaintext))
			} else {
				t.Logf("Decryption successful")
			}
		})
	}
}

// TestDESStandardVector официальный тест-вектор DES
func TestDESStandardVector(t *testing.T) {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	expectedCiphertext := []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05}

	t.Logf("Key:       %s", hex.EncodeToString(key))
	t.Logf("Plaintext: %s", hex.EncodeToString(plaintext))
	t.Logf("Expected:  %s", hex.EncodeToString(expectedCiphertext))

	cipher := NewDESCipher()
	if err := cipher.SetKey(key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	encrypted, err := cipher.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	t.Logf("Got:       %s", hex.EncodeToString(encrypted))

	if !bytes.Equal(encrypted, expectedCiphertext) {
		t.Errorf("Encryption failed")
		t.Errorf("  Expected: %s", hex.EncodeToString(expectedCiphertext))
		t.Errorf("  Got:      %s", hex.EncodeToString(encrypted))
	} else {
		t.Logf("Encryption matches standard")
	}

	decrypted, err := cipher.DecryptBlock(encrypted)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	t.Logf("Decrypted: %s", hex.EncodeToString(decrypted))

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decryption failed")
		t.Errorf("  Expected: %s", hex.EncodeToString(plaintext))
		t.Errorf("  Got:      %s", hex.EncodeToString(decrypted))
	} else {
		t.Logf("Decryption successful")
	}
}

// TestDESStandardVectors тестирование с официальными FIPS векторами
func TestDESStandardVectors(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		plaintext  string
		ciphertext string
	}{
		{
			name:       "Standard test vector",
			key:        "133457799BBCDFF1",
			plaintext:  "0123456789ABCDEF",
			ciphertext: "85E813540F0AB405",
		},
		{
			name:       "All zeros",
			key:        "0101010101010101",
			plaintext:  "0000000000000000",
			ciphertext: "8CA64DE9C1B123A7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tt.key)
			plaintext, _ := hex.DecodeString(tt.plaintext)
			expectedCipher, _ := hex.DecodeString(tt.ciphertext)

			t.Logf("Key:       %s", tt.key)
			t.Logf("Plaintext: %s", tt.plaintext)
			t.Logf("Expected:  %s", tt.ciphertext)

			cipher := NewDESCipher()
			if err := cipher.SetKey(key); err != nil {
				t.Fatalf("SetKey failed: %v", err)
			}

			ciphertext, err := cipher.EncryptBlock(plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			t.Logf("Got:       %s", hex.EncodeToString(ciphertext))

			if !bytes.Equal(ciphertext, expectedCipher) {
				t.Errorf("Encryption mismatch")
				t.Errorf("  Expected: %s", hex.EncodeToString(expectedCipher))
				t.Errorf("  Got:      %s", hex.EncodeToString(ciphertext))
			} else {
				t.Logf("Encryption matches")
			}

			decrypted, err := cipher.DecryptBlock(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decryption mismatch")
				t.Errorf("  Expected: %s", hex.EncodeToString(plaintext))
				t.Errorf("  Got:      %s", hex.EncodeToString(decrypted))
			} else {
				t.Logf("Decryption successful")
			}
		})
	}
}

// TestDESBasic базовый тест шифрования/дешифрования
func TestDESBasic(t *testing.T) {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	t.Logf("Key:       %s", hex.EncodeToString(key))
	t.Logf("Plaintext: %s", hex.EncodeToString(plaintext))

	cipher := NewDESCipher()
	if err := cipher.SetKey(key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	ciphertext, err := cipher.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	t.Logf("Encrypted: %s", hex.EncodeToString(ciphertext))
	t.Logf("           (should be: 85e813540f0ab405)")

	decrypted, err := cipher.DecryptBlock(ciphertext)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	t.Logf("Decrypted: %s", hex.EncodeToString(decrypted))

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decryption failed")
		t.Errorf("  Expected: %x", plaintext)
		t.Errorf("  Got:      %x", decrypted)
	} else {
		t.Logf("Round-trip successful")
	}

	expectedCiphertext := []byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05}
	if bytes.Equal(ciphertext, expectedCiphertext) {
		t.Logf("Ciphertext matches DES standard")
	} else {
		t.Logf("Ciphertext does NOT match standard")
		t.Logf("  Expected: %s", hex.EncodeToString(expectedCiphertext))
		t.Logf("  Got:      %s", hex.EncodeToString(ciphertext))
	}
}

// TestDESMultipleKeys тест с разными ключами
func TestDESMultipleKeys(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		plaintext string
	}{
		{
			name:      "Key 1",
			key:       "0123456789ABCDEF",
			plaintext: "0011223344556677",
		},
		{
			name:      "Key 2",
			key:       "FEDCBA9876543210",
			plaintext: "8899AABBCCDDEEFF",
		},
		{
			name:      "Key 3",
			key:       "1122334455667788",
			plaintext: "FFEEDDCCBBAA9988",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tt.key)
			plaintext, _ := hex.DecodeString(tt.plaintext)

			t.Logf("Key:       %s", tt.key)
			t.Logf("Plaintext: %s", tt.plaintext)

			cipher := NewDESCipher()
			if err := cipher.SetKey(key); err != nil {
				t.Fatalf("SetKey failed: %v", err)
			}

			ciphertext, err := cipher.EncryptBlock(plaintext)
			if err != nil {
				t.Fatalf("EncryptBlock failed: %v", err)
			}

			t.Logf("Encrypted: %s", hex.EncodeToString(ciphertext))

			decrypted, err := cipher.DecryptBlock(ciphertext)
			if err != nil {
				t.Fatalf("DecryptBlock failed: %v", err)
			}

			t.Logf("Decrypted: %s", hex.EncodeToString(decrypted))

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Round-trip failed")
				t.Errorf("  Original:  %s", hex.EncodeToString(plaintext))
				t.Errorf("  Decrypted: %s", hex.EncodeToString(decrypted))
			} else {
				t.Logf("Round-trip successful")
			}
		})
	}
}

// TestDESBlockSize проверка размера блока
func TestDESBlockSize(t *testing.T) {
	cipher := NewDESCipher()
	if cipher.BlockSize() != 8 {
		t.Errorf("Expected block size 8, got %d", cipher.BlockSize())
	}
}

// TestDESInvalidKeySize проверка обработки неверного размера ключа
func TestDESInvalidKeySize(t *testing.T) {
	cipher := NewDESCipher()

	shortKey := []byte{0x01, 0x02, 0x03}
	if err := cipher.SetKey(shortKey); err == nil {
		t.Error("Expected error for short key, got nil")
	}

	longKey := make([]byte, 16)
	if err := cipher.SetKey(longKey); err == nil {
		t.Error("Expected error for long key, got nil")
	}
}

// TestDESInvalidBlockSize проверка обработки неверного размера блока
func TestDESInvalidBlockSize(t *testing.T) {
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	cipher := NewDESCipher()
	if err := cipher.SetKey(key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	shortBlock := []byte{0x01, 0x02, 0x03}
	if _, err := cipher.EncryptBlock(shortBlock); err == nil {
		t.Error("Expected error for short block, got nil")
	}

	longBlock := make([]byte, 16)
	if _, err := cipher.EncryptBlock(longBlock); err == nil {
		t.Error("Expected error for long block, got nil")
	}
}

