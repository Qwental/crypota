package math

import "math/big"

// gcd(a, b) = gcd(b mod a, a)
func GCD(a, b *big.Int) *big.Int {
	if a == nil || b == nil {
		panic("nil argument")
	}

	a = new(big.Int).Abs(a)
	b = new(big.Int).Abs(b)

	if a.Cmp(big.NewInt(0)) == 0 && b.Cmp(big.NewInt(0)) == 0 {
		panic("both arguments are zero")
	}

	if a.Cmp(big.NewInt(0)) == 0 {
		return new(big.Int).Set(b)
	}

	return GCD(new(big.Int).Mod(b, a), a)
}

// gcd(a, b) = a*x + b*y
func ExtendedGCD(a, b *big.Int) (gcd, x, y *big.Int) {
	if a.Cmp(big.NewInt(0)) == 0 {
		return new(big.Int).Set(b), big.NewInt(0), big.NewInt(1)
	}

	gcd1, x1, y1 := ExtendedGCD(new(big.Int).Mod(b, a), a)

	gcd = gcd1
	x = new(big.Int).Sub(y1, new(big.Int).Mul(new(big.Int).Div(b, a), x1))
	y = x1

	return
}
