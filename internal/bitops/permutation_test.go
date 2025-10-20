package bitops

import (
	"bytes"
	"testing"
)

func TestPermuteBasic(t *testing.T) {
	data := []byte{0xFF, 0x00}
	pBlock := []int{9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8}

	config := PermuteConfig{
		Indexing:  LSBFirst,
		Numbering: OneBased,
	}

	result, err := Permute(data, pBlock, config)
	if err != nil {
		t.Fatalf("Permute failed: %v", err)
	}

	expected := []byte{0x00, 0xFF}
	if !bytes.Equal(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}
