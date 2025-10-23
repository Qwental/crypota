package math

import (
	"math/big"
	"testing"
)

func TestJacobiSymbol(t *testing.T) {
	tests := []struct {
		a        int64
		n        int64
		expected int
	}{
		{1, 3, 1},
		{2, 3, -1},
		{3, 5, -1},
		{4, 5, 1},
		{5, 9, 1},
		{6, 15, 0},
		{7, 15, -1},
		{8, 15, 1},
		{9, 15, 0},
		{2, 5, -1},
		{1, 5, 1},
		{2, 9, 1},
		{3, 9, 0},
		{7, 9, 1},
		{1001, 9907, -1},
		{19, 45, 1},
		{8, 21, -1},
		{5, 21, 1},
		{2, 15, 1},
		{3, 15, 0},
		{5, 15, 0},
		{11, 35, 1},
	}

	for _, tt := range tests {
		a := big.NewInt(tt.a)
		n := big.NewInt(tt.n)
		result := JacobiSymbol(a, n)
		if result != tt.expected {
			t.Errorf("JacobiSymbol(%d, %d) = %d, expected %d", tt.a, tt.n, result, tt.expected)
		}
	}
}

func TestJacobiSymbolZeroNumerator(t *testing.T) {
	result := JacobiSymbol(big.NewInt(0), big.NewInt(15))
	if result != 0 {
		t.Errorf("JacobiSymbol(0, 15) = %d, expected 0", result)
	}
}

func TestJacobiSymbolNegative(t *testing.T) {
	tests := []struct {
		a        int64
		n        int64
		expected int
	}{
		{-1, 5, 1},
		{-2, 9, 1},
		{-3, 7, 1},
		{-2, 7, -1},
	}

	for _, tt := range tests {
		a := big.NewInt(tt.a)
		n := big.NewInt(tt.n)
		result := JacobiSymbol(a, n)
		if result != tt.expected {
			t.Errorf("JacobiSymbol(%d, %d) = %d, expected %d", tt.a, tt.n, result, tt.expected)
		}
	}
}

func TestJacobiSymbolLargeNumbers(t *testing.T) {
	tests := []struct {
		a        string
		n        string
		expected int
	}{
		{"987654321", "123456789", 0},
		{"123456789", "987654321", 0},
		{"1001", "9907", -1},
		{"2", "31", 1},
		{"3", "31", -1},
		{"2", "1000000000000000003", -1},
		{"3", "1000000000000000003", -1},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		n := new(big.Int)
		n.SetString(tt.n, 10)
		result := JacobiSymbol(a, n)
		if result != tt.expected {
			t.Errorf("JacobiSymbol(%s, %s) = %d, expected %d", tt.a, tt.n, result, tt.expected)
		}
	}
}

func TestJacobiSymbolProperties(t *testing.T) {
	n := big.NewInt(15)

	for i := int64(1); i < 15; i++ {
		a := big.NewInt(i)
		result := JacobiSymbol(a, n)
		if result < -1 || result > 1 {
			t.Errorf("JacobiSymbol(%d, 15) = %d, must be -1, 0, or 1", i, result)
		}
	}
}

func TestJacobiSymbolEvenModulusPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for even n")
		}
	}()
	JacobiSymbol(big.NewInt(1), big.NewInt(2))
}

func TestJacobiSymbolSmallModulusPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for n = 1")
		}
	}()
	JacobiSymbol(big.NewInt(1), big.NewInt(1))
}

func TestJacobiSymbolPanicNegative(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for negative n")
		}
	}()
	JacobiSymbol(big.NewInt(2), big.NewInt(-5))
}
