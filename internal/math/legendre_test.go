package math

import (
	"math/big"
	"testing"
)

func TestLegendreSymbolQuadraticResidue(t *testing.T) {
	tests := []struct {
		a string
		p string
	}{
		{"5", "11"},
		{"2", "7"},
		{"1", "5"},
		{"4", "5"},
		{"4", "7"},
		{"1", "11"},
		{"3", "11"},
		{"4", "11"},
		{"5", "11"},
		{"9", "11"},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		p := new(big.Int)
		p.SetString(tt.p, 10)
		result := LegendreSymbol(a, p)
		if result != 1 {
			t.Errorf("LegendreSymbol(%s, %s) = %d, expected 1", tt.a, tt.p, result)
		}
	}
}

func TestLegendreSymbolQuadraticNonResidue(t *testing.T) {
	tests := []struct {
		a string
		p string
	}{
		{"3", "7"},
		{"2", "5"},
		{"3", "5"},
		{"5", "7"},
		{"6", "7"},
		{"2", "11"},
		{"6", "11"},
		{"7", "11"},
		{"8", "11"},
		{"10", "11"},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		p := new(big.Int)
		p.SetString(tt.p, 10)
		result := LegendreSymbol(a, p)
		if result != -1 {
			t.Errorf("LegendreSymbol(%s, %s) = %d, expected -1", tt.a, tt.p, result)
		}
	}
}

func TestLegendreSymbolZeroCase(t *testing.T) {
	tests := []struct {
		a string
		p string
	}{
		{"15", "5"},
		{"0", "13"},
		{"0", "7"},
		{"21", "7"},
		{"33", "11"},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		p := new(big.Int)
		p.SetString(tt.p, 10)
		result := LegendreSymbol(a, p)
		if result != 0 {
			t.Errorf("LegendreSymbol(%s, %s) = %d, expected 0", tt.a, tt.p, result)
		}
	}
}

func TestLegendreSymbolSpecialCases(t *testing.T) {
	tests := []struct {
		a        string
		p        string
		expected int
	}{
		{"-1", "11", -1},
		{"2", "7", 1},
		{"-1", "17", 1},
		{"56", "65537", -1},
		{"-1", "5", 1},
		{"-1", "13", 1},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		p := new(big.Int)
		p.SetString(tt.p, 10)
		result := LegendreSymbol(a, p)
		if result != tt.expected {
			t.Errorf("LegendreSymbol(%s, %s) = %d, expected %d", tt.a, tt.p, result, tt.expected)
		}
	}
}

func TestLegendreSymbolLargeNumbers(t *testing.T) {
	tests := []struct {
		a        string
		p        string
		expected int
	}{
		{"1234567890", "1000000007", -1},
		{"987654321", "1000000007", 1},
		{"4698450", "1000000007", -1},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		p := new(big.Int)
		p.SetString(tt.p, 10)
		result := LegendreSymbol(a, p)
		if result != tt.expected {
			t.Errorf("LegendreSymbol(%s, %s) = %d, expected %d", tt.a, tt.p, result, tt.expected)
		}
	}
}

func TestLegendreSymbolInvalidInputEven(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for even p")
		}
	}()
	LegendreSymbol(big.NewInt(5), big.NewInt(10))
}

func TestLegendreSymbolInvalidInputTwo(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for p = 2")
		}
	}()
	LegendreSymbol(big.NewInt(3), big.NewInt(2))
}

func TestLegendreSymbolInvalidInputSmall(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for p < 3")
		}
	}()
	LegendreSymbol(big.NewInt(1), big.NewInt(1))
}

func TestLegendreSymbolNegative(t *testing.T) {
	tests := []struct {
		a        int64
		p        int64
		expected int
	}{
		{-1, 5, 1},
		{-2, 5, -1},
		{-3, 7, 1},
	}

	for _, tt := range tests {
		a := big.NewInt(tt.a)
		p := big.NewInt(tt.p)
		result := LegendreSymbol(a, p)
		if result != tt.expected {
			t.Errorf("LegendreSymbol(%d, %d) = %d, expected %d", tt.a, tt.p, result, tt.expected)
		}
	}
}
