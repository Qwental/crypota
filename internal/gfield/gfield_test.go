package gfield

import (
	"testing"
)

func TestAdd(t *testing.T) {
	tests := []struct {
		name     string
		a, b     byte
		expected byte
	}{
		{"standard test", 0x53, 0xCA, 0x99},
		{"same values cancel", 0xFF, 0xFF, 0x00},
		{"add with zero", 0x00, 0x57, 0x57},
		{"MATLAB example 1", 0x09, 0x01, 0x08},
		{"MATLAB example 2", 0x08, 0x02, 0x0A},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Add(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("Add(0x%02X, 0x%02X) = 0x%02X; want 0x%02X",
					tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestMultiplyByMod(t *testing.T) {
	tests := []struct {
		name     string
		a, b     byte
		mod      byte
		expected byte
	}{
		{"AES polynomial", 0x57, 0x83, 0x1B, 0xC1},
		{"multiply by one", 0x57, 0x01, 0x1B, 0x57},
		{"multiply by zero", 0x00, 0xFF, 0x1B, 0x00},
		{"MATLAB mod 0xF5 test 1", 0x09, 0x01, 0xF5, 0x09},
		{"MATLAB mod 0xF5 test 2", 0x02, 0x02, 0xF5, 0x04},
		{"MATLAB mod 0xF5 test 3", 0x03, 0x02, 0xF5, 0x06},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MultiplyByMod(tt.a, tt.b, tt.mod)
			if result != tt.expected {
				t.Errorf("MultiplyByMod(0x%02X, 0x%02X, 0x%02X) = 0x%02X; want 0x%02X",
					tt.a, tt.b, tt.mod, result, tt.expected)
			}
		})
	}
}

func TestInverse(t *testing.T) {
	tests := []struct {
		name string
		poly byte
		mod  byte
	}{
		{"AES mod test 1", 0x53, 0x1B},
		{"AES mod test 2", 0x01, 0x1B},
		{"AES mod test 3", 0xCA, 0x1B},
		{"MATLAB mod 0xF5 test 1", 0x09, 0xF5},
		{"MATLAB mod 0xF5 test 2", 0x08, 0xF5},
		{"MATLAB mod 0xF5 test 3", 0x02, 0xF5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := Inverse(tt.poly, tt.mod)
			product := MultiplyByMod(tt.poly, inv, tt.mod)
			if product != 0x01 {
				t.Errorf("Inverse(0x%02X, 0x%02X) = 0x%02X; poly * inv = 0x%02X, want 0x01",
					tt.poly, tt.mod, inv, product)
			}
		})
	}
}

func TestIsIrreducible(t *testing.T) {
	tests := []struct {
		name     string
		poly     int
		degree   int
		expected bool
	}{
		{"AES polynomial", 0x11B, 8, true},
		{"another irreducible 8", 0x11D, 8, true},
		{"MATLAB polynomial", 0x1F5, 8, true},
		{"reducible 8", 0x100, 8, false},
		{"irreducible 4", 0x13, 4, true},
		{"reducible 4", 0x10, 4, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsIrreducible(tt.poly, tt.degree)
			if result != tt.expected {
				t.Errorf("IsIrreducible(0x%X, %d) = %v; want %v",
					tt.poly, tt.degree, result, tt.expected)
			}
		})
	}
}

func TestGetAllIrreducible8(t *testing.T) {
	result := GetAllIrreducible8()

	if len(result) != 30 {
		t.Fatalf("GetAllIrreducible8() returned %d polynomials; want 30", len(result))
	}

	for i, poly := range result {
		fullPoly := 0x100 | int(poly)
		if !IsIrreducible(fullPoly, 8) {
			t.Errorf("Polynomial #%d (0x%02X / 0x%03X) is not irreducible", i, poly, fullPoly)
		}
	}

	expectedPolynomials := []byte{
		0x1B, 0x1D, 0x2B, 0x2D, 0x39, 0x3F, 0x4D, 0x5F, 0x63, 0x65,
		0x69, 0x71, 0x77, 0x7B, 0x87, 0x8B, 0x8D, 0x9F, 0xA3, 0xA9,
		0xB1, 0xBD, 0xC3, 0xCF, 0xD7, 0xDD, 0xE7, 0xF3, 0xF5, 0xF9,
	}

	if len(result) != len(expectedPolynomials) {
		t.Errorf("Result length %d doesn't match expected length %d",
			len(result), len(expectedPolynomials))
	}

	for i, expected := range expectedPolynomials {
		found := false
		for _, actual := range result {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected polynomial #%d: 0x%02X not found in result", i+1, expected)
		}
	}

	matlabMod := byte(0xF5)
	found := false
	for _, poly := range result {
		if poly == matlabMod {
			found = true
			break
		}
	}
	if !found {
		t.Error("MATLAB polynomial 0xF5 not found in irreducible list")
	}

	t.Logf("All 30 irreducible polynomials verified successfully")
}

func TestFactorize(t *testing.T) {
	tests := []struct {
		name string
		poly int
	}{
		{"test polynomial 1", 0b111011001},
		{"test polynomial 2", 0b110110},
		{"test polynomial 3", 0b100100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factors := Factorize(tt.poly)

			if len(factors) == 0 {
				t.Error("Factorize returned empty result")
				return
			}

			product := 1
			for _, f := range factors {
				product = multiplyPolynomials(product, f)
			}

			if product != tt.poly {
				t.Errorf("Product of factors = 0x%X; want 0x%X", product, tt.poly)
				t.Logf("Factors: %v", factors)
			}

			for _, f := range factors {
				degree := getDegreeHelper(f)
				if degree > 0 && !IsIrreducible(f, degree) {
					t.Errorf("Factor 0x%X (degree %d) is not irreducible", f, degree)
				}
			}
		})
	}
}

func getDegreeHelper(poly int) int {
	if poly == 0 {
		return -1
	}
	degree := 0
	temp := poly
	for temp > 1 {
		temp >>= 1
		degree++
	}
	return degree
}

func multiplyPolynomials(a, b int) int {
	result := 0
	for b != 0 {
		if b&1 != 0 {
			result ^= a
		}
		a <<= 1
		b >>= 1
	}
	return result
}

func TestModuloPolynomials(t *testing.T) {
	tests := []struct {
		name     string
		a, b     int
		expected int
	}{
		{"simple mod 1", 0b1101, 0b11, 0b1},
		{"simple mod 2", 0b10110, 0b101, 0b10},
		{"no remainder", 0b1100, 0b11, 0b0},
		{"larger polynomial", 0b11111, 0b111, 0b11},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ModuloPolynomials(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("ModuloPolynomials(0b%b, 0b%b) = 0b%b; want 0b%b",
					tt.a, tt.b, result, tt.expected)
			}
		})
	}
}


func TestDividePolynomials(t *testing.T) {
	tests := []struct {
		name     string
		a, b     int
		expected int
	}{
		{"simple division", 0b1100, 0b11, 0b100},
		{"division 2", 0b10110, 0b101, 0b100},
		{"exact division", 0b1111, 0b11, 0b101},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DividePolynomials(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("DividePolynomials(0b%b, 0b%b) = 0b%b; want 0b%b",
					tt.a, tt.b, result, tt.expected)
			}

			quotient := result
			remainder := ModuloPolynomials(tt.a, tt.b)
			reconstructed := multiplyPolynomials(quotient, tt.b) ^ remainder

			if reconstructed != tt.a {
				t.Errorf("Verification failed: quotient * divisor + remainder != dividend")
				t.Logf("Expected: 0b%b, Got: 0b%b", tt.a, reconstructed)
			}
		})
	}
}

func TestAddCommutative(t *testing.T) {
	testCases := []struct {
		a, b byte
	}{
		{0x12, 0x34},
		{0xAB, 0xCD},
		{0xFF, 0x01},
	}

	for _, tc := range testCases {
		result1 := Add(tc.a, tc.b)
		result2 := Add(tc.b, tc.a)
		if result1 != result2 {
			t.Errorf("Add is not commutative: Add(0x%02X, 0x%02X) = 0x%02X, but Add(0x%02X, 0x%02X) = 0x%02X",
				tc.a, tc.b, result1, tc.b, tc.a, result2)
		}
	}
}

func TestMultiplyCommutative(t *testing.T) {
	mod := byte(0x1B)
	testCases := []struct {
		a, b byte
	}{
		{0x12, 0x34},
		{0x53, 0xCA},
		{0x02, 0x03},
	}

	for _, tc := range testCases {
		result1 := MultiplyByMod(tc.a, tc.b, mod)
		result2 := MultiplyByMod(tc.b, tc.a, mod)
		if result1 != result2 {
			t.Errorf("Multiply is not commutative: Multiply(0x%02X, 0x%02X, 0x%02X) = 0x%02X, but Multiply(0x%02X, 0x%02X, 0x%02X) = 0x%02X",
				tc.a, tc.b, mod, result1, tc.b, tc.a, mod, result2)
		}
	}
}
