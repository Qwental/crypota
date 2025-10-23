package math

import (
	"math/big"
	"testing"
)

func TestModExp(t *testing.T) {
	tests := []struct {
		base     int64
		exp      int64
		mod      int64
		expected int64
	}{
		{2, 3, 5, 3},
		{3, 4, 7, 4},
		{5, 3, 13, 8},
		{7, 2, 10, 9},
		{2, 10, 1000, 24},
		{3, 5, 11, 1},
		{4, 13, 497, 445},
		{10, 3, 7, 6},
		{2, 0, 5, 1},
		{1, 100, 7, 1},
		{7, 3, 11, 2},
	}

	for _, tt := range tests {
		base := big.NewInt(tt.base)
		exp := big.NewInt(tt.exp)
		mod := big.NewInt(tt.mod)
		result := ModExp(base, exp, mod)
		expected := big.NewInt(tt.expected)
		if result.Cmp(expected) != 0 {
			t.Errorf("ModExp(%d, %d, %d) = %s, expected %s", tt.base, tt.exp, tt.mod, result.String(), expected.String())
		}
	}
}

func TestModExpPositiveNumbers(t *testing.T) {
	a := big.NewInt(3)
	n := big.NewInt(4)
	m := big.NewInt(5)
	result := ModExp(a, n, m)
	expected := big.NewInt(1)
	if result.Cmp(expected) != 0 {
		t.Errorf("ModExp(3, 4, 5) = %s, expected 1", result.String())
	}
}

func TestModExpNegativeBase(t *testing.T) {
	a := big.NewInt(-2)
	n := big.NewInt(3)
	m := big.NewInt(10)
	result := ModExp(a, n, m)
	expected := big.NewInt(2)
	if result.Cmp(expected) != 0 {
		t.Errorf("ModExp(-2, 3, 10) = %s, expected 2", result.String())
	}
}

func TestModExpZeroExponent(t *testing.T) {
	a := big.NewInt(5)
	n := big.NewInt(0)
	m := big.NewInt(100)
	result := ModExp(a, n, m)
	expected := big.NewInt(1)
	if result.Cmp(expected) != 0 {
		t.Errorf("ModExp(5, 0, 100) = %s, expected 1", result.String())
	}
}

func TestModExpModOne(t *testing.T) {
	a := new(big.Int)
	a.SetString("123456789", 10)
	n := big.NewInt(1000)
	m := big.NewInt(1)
	result := ModExp(a, n, m)
	expected := big.NewInt(0)
	if result.Cmp(expected) != 0 {
		t.Errorf("ModExp(123456789, 1000, 1) = %s, expected 0", result.String())
	}
}

func TestModExpLargeNumbers(t *testing.T) {
	a := new(big.Int)
	a.SetString("123456789", 10)
	n := new(big.Int)
	n.SetString("1000000", 10)
	m := new(big.Int)
	m.SetString("1000000007", 10)
	expected := new(big.Int)
	expected.SetString("471040903", 10)

	result := ModExp(a, n, m)
	if result.Cmp(expected) != 0 {
		t.Errorf("ModExp(123456789, 1000000, 1000000007) = %s, expected %s", result.String(), expected.String())
	}
}

func TestModExpPanicZeroMod(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for zero modulus")
		}
	}()
	ModExp(big.NewInt(10), big.NewInt(2), big.NewInt(0))
}

func TestModExpOneBase(t *testing.T) {
	result := ModExp(big.NewInt(1), big.NewInt(100), big.NewInt(7))
	expected := big.NewInt(1)
	if result.Cmp(expected) != 0 {
		t.Errorf("ModExp(1, 100, 7) = %s, expected 1", result.String())
	}
}

func TestModExpResultRange(t *testing.T) {
	base := big.NewInt(7)
	exp := big.NewInt(100)
	mod := big.NewInt(13)

	result := ModExp(base, exp, mod)

	if result.Cmp(mod) >= 0 {
		t.Errorf("ModExp result must be less than modulus")
	}
	if result.Cmp(big.NewInt(0)) < 0 {
		t.Errorf("ModExp result must be non-negative")
	}
}

func TestModExpFermatLittleTheorem(t *testing.T) {
	p := big.NewInt(7)
	for a := int64(1); a < 7; a++ {
		base := big.NewInt(a)
		exp := new(big.Int).Sub(p, big.NewInt(1))
		result := ModExp(base, exp, p)
		if result.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("ModExp(%d, %d, 7) = %s, expected 1 (Fermat)", a, exp.Int64(), result.String())
		}
	}
}

func TestModExpSquare(t *testing.T) {
	base := big.NewInt(5)
	exp := big.NewInt(2)
	mod := big.NewInt(13)
	result := ModExp(base, exp, mod)
	expected := big.NewInt(12)
	if result.Cmp(expected) != 0 {
		t.Errorf("ModExp(5, 2, 13) = %s, expected 12", result.String())
	}
}

func TestModExpSmallCases(t *testing.T) {
	tests := []struct {
		base     int64
		exp      int64
		mod      int64
		expected int64
	}{
		{5, 5, 221, 31},
		{2, 8, 13, 9},
		{3, 10, 17, 8},
	}

	for _, tt := range tests {
		base := big.NewInt(tt.base)
		exp := big.NewInt(tt.exp)
		mod := big.NewInt(tt.mod)
		result := ModExp(base, exp, mod)
		expected := big.NewInt(tt.expected)
		if result.Cmp(expected) != 0 {
			t.Errorf("ModExp(%d, %d, %d) = %s, expected %s", tt.base, tt.exp, tt.mod, result.String(), expected.String())
		}
	}
}
