package context

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/Qwental/crypota/internal/des"
	"github.com/Qwental/crypota/internal/modes"
	"github.com/Qwental/crypota/internal/padding"
)

func TestCipherContextBasic(t *testing.T) {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	plaintext := []byte("Hello, World! This is a test message.")

	cipher := des.NewDESCipher()

	ctx, err := NewCipherContext(
		cipher,
		key,
		modes.ECB,
		padding.PKCS7,
		nil,
	)
	if err != nil {
		t.Fatalf("NewCipherContext failed: %v", err)
	}

	// Шифруем
	ciphertext, err := ctx.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Дешифруем
	decrypted, err := ctx.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Проверяем
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decryption failed\nExpected: %s\nGot:      %s", plaintext, decrypted)
	}
}

func TestCipherContextCBC(t *testing.T) {
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	iv := make([]byte, 8)
	rand.Read(iv)
	plaintext := []byte("Test message for CBC mode encryption and decryption")

	cipher := des.NewDESCipher()

	ctx, err := NewCipherContext(
		cipher,
		key,
		modes.CBC,
		padding.PKCS7,
		iv,
	)
	if err != nil {
		t.Fatalf("NewCipherContext failed: %v", err)
	}

	// Шифруем
	ciphertext, err := ctx.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Дешифруем
	decrypted, err := ctx.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Проверяем
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decryption failed")
	}
}
