package padding

import (
	"bytes"
	"testing"
)

func TestPKCS7Padding(t *testing.T) {
	data := []byte("Hello")
	blockSize := 8

	padded, err := Pad(data, blockSize, PKCS7)
	if err != nil {
		t.Fatalf("Pad failed: %v", err)
	}

	if len(padded)%blockSize != 0 {
		t.Errorf("Padded length %d is not multiple of block size %d", len(padded), blockSize)
	}

	unpadded, err := Unpad(padded, PKCS7)
	if err != nil {
		t.Fatalf("Unpad failed: %v", err)
	}

	if !bytes.Equal(unpadded, data) {
		t.Errorf("Unpadded data doesn't match original")
	}
}
