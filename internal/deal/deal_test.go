package deal

import (
	"bytes"
	"testing"
	"fmt"
)

func TestDEALBasic(t *testing.T) {
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
		t.Fatalf("NewDEALCipher failed: %v", err)
	}

	err = cipher.SetKey(key)
	if err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	ciphertext, err := cipher.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	decrypted, err := cipher.DecryptBlock(ciphertext)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decryption failed: got %x, want %x", decrypted, plaintext)
	}
}

// Дополнительный тест для всех размеров ключей
func TestDEALAllKeySizes(t *testing.T) {
	keySizes := []int{16, 24, 32}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("KeySize%d", keySize*8), func(t *testing.T) {
			key := make([]byte, keySize)
			for i := range key {
				key[i] = byte(i)
			}

			plaintext := make([]byte, 16)
			for i := range plaintext {
				plaintext[i] = byte(i * 3)
			}

			cipher, err := NewDEALCipher(keySize)
			if err != nil {
				t.Fatalf("NewDEALCipher failed: %v", err)
			}

			err = cipher.SetKey(key)
			if err != nil {
				t.Fatalf("SetKey failed: %v", err)
			}

			ciphertext, err := cipher.EncryptBlock(plaintext)
			if err != nil {
				t.Fatalf("EncryptBlock failed: %v", err)
			}

			decrypted, err := cipher.DecryptBlock(ciphertext)
			if err != nil {
				t.Fatalf("DecryptBlock failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decryption failed: got %x, want %x", decrypted, plaintext)
			}
		})
	}
}
