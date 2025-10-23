package math

import "math/big"

//возводит в степень по модулю c ≡ a^n (mod m)
func ModExp(base, exp, mod *big.Int) *big.Int {
	if mod.Cmp(big.NewInt(0)) == 0 {
		panic("modulus cannot be zero")
	}

	result := big.NewInt(1)
	base = new(big.Int).Mod(base, mod)
	exp = new(big.Int).Set(exp)

	for exp.Cmp(big.NewInt(0)) > 0 {
		if exp.Bit(0) == 1 {
			result = new(big.Int).Mod(new(big.Int).Mul(result, base), mod)
		}
		base = new(big.Int).Mod(new(big.Int).Mul(base, base), mod)
		exp = new(big.Int).Rsh(exp, 1)
	}

	return result
}
