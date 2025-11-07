package feistel

import (
	"bytes"
	"testing"
)

type mockRoundFunction struct{}

func (m *mockRoundFunction) Apply(block []byte, key []byte) ([]byte, error) {
	result := make([]byte, len(block))
	for i := range block {
		result[i] = block[i] ^ key[i%len(key)]
	}
	return result, nil
}

type mockKeyScheduler struct{}

func (m *mockKeyScheduler) GenerateRoundKeys(key []byte) ([][]byte, error) {
	keys := make([][]byte, 4)
	for i := range keys {
		keys[i] = make([]byte, 4)
		for j := range keys[i] {
			keys[i][j] = key[j%len(key)] ^ byte(i)
		}
	}
	return keys, nil
}

func TestFeistelBasic(t *testing.T) {
	keyScheduler := &mockKeyScheduler{}
	roundFunction := &mockRoundFunction{}

	cipher := NewFeistelCipher(keyScheduler, roundFunction, 4, 8)
	key := []byte{0x01, 0x02, 0x03, 0x04}

	err := cipher.SetKey(key)
	if err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	plaintext := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	ciphertext, err := cipher.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	decrypted, err := cipher.DecryptBlock(ciphertext)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decryption failed\nExpected: %v\nGot:      %v", plaintext, decrypted)
	}
}
