package math

import (
	"math/big"
	"testing"
)

func TestGCD(t *testing.T) {
	tests := []struct {
		a        int64
		b        int64
		expected int64
	}{
		{48, 18, 6},
		{17, 5, 1},
		{60, 48, 12},
		{1071, 462, 21},
		{10, 10, 10},
		{100, 50, 50},
		{0, 5, 5},
		{5, 0, 5},
		{270, 192, 6},
		{35, 14, 7},
		{99, 78, 3},
		{1, 1, 1},
		{7, 7, 7},
		{252, 105, 21},
		{1000, 500, 500},
	}

	for _, tt := range tests {
		a := big.NewInt(tt.a)
		b := big.NewInt(tt.b)
		result := GCD(a, b)
		expected := big.NewInt(tt.expected)
		if result.Cmp(expected) != 0 {
			t.Errorf("GCD(%d, %d) = %s, expected %s", tt.a, tt.b, result.String(), expected.String())
		}
	}
}

func TestGCDWithOne(t *testing.T) {
	result := GCD(big.NewInt(1), big.NewInt(10))
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("GCD(1, 10) = %s, expected 1", result.String())
	}

	result = GCD(big.NewInt(17), big.NewInt(1))
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("GCD(17, 1) = %s, expected 1", result.String())
	}
}

func TestGCDNegative(t *testing.T) {
	tests := []struct {
		a        int64
		b        int64
		expected int64
	}{
		{-48, 18, 6},
		{48, -18, 6},
		{-48, -18, 6},
		{-17, 13, 1},
		{-15, 20, 5},
		{-12, 8, 4},
		{9, -6, 3},
	}

	for _, tt := range tests {
		a := big.NewInt(tt.a)
		b := big.NewInt(tt.b)
		result := GCD(a, b)
		expected := big.NewInt(tt.expected)
		if result.Cmp(expected) != 0 {
			t.Errorf("GCD(%d, %d) = %s, expected %s", tt.a, tt.b, result.String(), expected.String())
		}
	}
}

func TestGCDLargeNumbers(t *testing.T) {
	tests := []struct {
		a        string
		b        string
		expected string
	}{
		{"123456789012345", "987654321098765", "5"},
		{"1000000000", "500000000", "500000000"},
		{"999999999999", "888888888888", "111111111111"},
		{"123456789012345678901234567890", "987654321098765432109876543210", "9000000000900000000090"},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		b := new(big.Int)
		b.SetString(tt.b, 10)
		expected := new(big.Int)
		expected.SetString(tt.expected, 10)
		result := GCD(a, b)
		if result.Cmp(expected) != 0 {
			t.Errorf("GCD(%s, %s) = %s, expected %s", tt.a, tt.b, result.String(), expected.String())
		}
	}
}

func TestGCDWithLargePrimes(t *testing.T) {
	prime1 := new(big.Int)
	prime1.SetString("32416190071", 10)
	prime2 := new(big.Int)
	prime2.SetString("2305843009213693951", 10)

	result := GCD(prime1, prime2)
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("GCD of large primes should be 1, got %s", result.String())
	}
}

func TestGCDWithSameNumbers(t *testing.T) {
	num := new(big.Int)
	num.SetString("123456789", 10)
	result := GCD(num, num)
	if result.Cmp(num) != 0 {
		t.Errorf("GCD of same numbers should equal the number")
	}
}

func TestGCDWithFibonacciNumbers(t *testing.T) {
	fib20 := big.NewInt(6765)
	fib15 := big.NewInt(610)
	result := GCD(fib20, fib15)
	if result.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("GCD(6765, 610) = %s, expected 5", result.String())
	}
}

func TestGCDPanicBothZero(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for GCD(0, 0)")
		}
	}()
	GCD(big.NewInt(0), big.NewInt(0))
}

func TestGCDPanicNilFirst(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for nil first argument")
		}
	}()
	GCD(nil, big.NewInt(1))
}

func TestGCDPanicNilSecond(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for nil second argument")
		}
	}()
	GCD(big.NewInt(1), nil)
}

func TestExtendedGCD(t *testing.T) {
	tests := []struct {
		a   int64
		b   int64
		gcd int64
	}{
		{48, 18, 6},
		{17, 5, 1},
		{1071, 462, 21},
		{270, 192, 6},
		{35, 14, 7},
		{99, 78, 3},
		{240, 46, 2},
	}

	for _, tt := range tests {
		a := big.NewInt(tt.a)
		b := big.NewInt(tt.b)
		gcd, x, y := ExtendedGCD(a, b)

		expectedGCD := big.NewInt(tt.gcd)
		if gcd.Cmp(expectedGCD) != 0 {
			t.Errorf("ExtendedGCD(%d, %d) gcd = %s, expected %s", tt.a, tt.b, gcd.String(), expectedGCD.String())
		}

		result := new(big.Int).Mul(a, x)
		result.Add(result, new(big.Int).Mul(b, y))
		if result.Cmp(gcd) != 0 {
			t.Errorf("ExtendedGCD(%d, %d): a*x + b*y = %s, expected %s", tt.a, tt.b, result.String(), gcd.String())
		}
	}
}

func TestExtendedGCDBasicCase(t *testing.T) {
	a := big.NewInt(48)
	b := big.NewInt(18)
	gcd, x, y := ExtendedGCD(a, b)

	if gcd.Cmp(big.NewInt(6)) != 0 {
		t.Errorf("gcd should be 6, got %s", gcd.String())
	}

	if x.Cmp(big.NewInt(-1)) != 0 || y.Cmp(big.NewInt(3)) != 0 {
		t.Errorf("x,y should be -1,3, got %s,%s", x.String(), y.String())
	}

	result := new(big.Int).Mul(a, x)
	result.Add(result, new(big.Int).Mul(b, y))
	if result.Cmp(gcd) != 0 {
		t.Errorf("48*x + 18*y should equal gcd")
	}
}

func TestExtendedGCDPrimeNumbers(t *testing.T) {
	a := big.NewInt(17)
	b := big.NewInt(5)
	gcd, x, y := ExtendedGCD(a, b)

	if gcd.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("gcd of primes should be 1")
	}

	if x.Cmp(big.NewInt(-2)) != 0 || y.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("x,y should be -2,7, got %s,%s", x.String(), y.String())
	}

	result := new(big.Int).Mul(a, x)
	result.Add(result, new(big.Int).Mul(b, y))
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("17*x + 5*y should equal 1")
	}
}

func TestExtendedGCDZero(t *testing.T) {
	gcd, x, y := ExtendedGCD(big.NewInt(0), big.NewInt(15))

	if gcd.Cmp(big.NewInt(15)) != 0 {
		t.Errorf("ExtendedGCD(0, 15) gcd = %s, expected 15", gcd.String())
	}
	if x.Cmp(big.NewInt(0)) != 0 || y.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("ExtendedGCD(0, 15) x,y = %s,%s, expected 0,1", x.String(), y.String())
	}
}

func TestExtendedGCDEqualNumbers(t *testing.T) {
	gcd, x, y := ExtendedGCD(big.NewInt(25), big.NewInt(25))

	if gcd.Cmp(big.NewInt(25)) != 0 {
		t.Errorf("gcd should be 25")
	}
	if x.Cmp(big.NewInt(1)) != 0 || y.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("x,y should be 1,0, got %s,%s", x.String(), y.String())
	}
}

func TestExtendedGCDLargeNumbers(t *testing.T) {
	a := new(big.Int)
	a.SetString("12345678901234567890", 10)
	b := new(big.Int)
	b.SetString("9876543210", 10)

	gcd, x, y := ExtendedGCD(a, b)

	result := new(big.Int).Mul(a, x)
	result.Add(result, new(big.Int).Mul(b, y))

	if result.Cmp(gcd) != 0 {
		t.Errorf("ExtendedGCD large numbers: a*x + b*y != gcd")
	}
}

func TestExtendedGCDCoprimes(t *testing.T) {
	gcd, x, y := ExtendedGCD(big.NewInt(17), big.NewInt(13))

	if gcd.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("ExtendedGCD(17, 13) gcd = %s, expected 1", gcd.String())
	}

	result := new(big.Int).Mul(big.NewInt(17), x)
	result.Add(result, new(big.Int).Mul(big.NewInt(13), y))

	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("ExtendedGCD(17, 13): 17*x + 13*y = %s, expected 1", result.String())
	}
}
