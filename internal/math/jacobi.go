package math

import "math/big"

// вычисляет символ Якоби (a/n)
func JacobiSymbol(a, n *big.Int) int {
	if n.Cmp(big.NewInt(3)) < 0 || n.Bit(0) == 0 {
		panic("n must be an odd integer >= 3")
	}

	a = new(big.Int).Mod(a, n)

	if a.Cmp(big.NewInt(0)) == 0 {
		return 0
	}

	result := 1

	for a.Cmp(big.NewInt(0)) != 0 {
		for a.Bit(0) == 0 {
			a.Rsh(a, 1)
			nMod8 := new(big.Int).Mod(n, big.NewInt(8))
			if nMod8.Cmp(big.NewInt(3)) == 0 || nMod8.Cmp(big.NewInt(5)) == 0 {
				result = -result
			}
		}

		a, n = n, a

		if new(big.Int).Mod(a, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 &&
			new(big.Int).Mod(n, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 {
			result = -result
		}

		a = new(big.Int).Mod(a, n)
	}

	if n.Cmp(big.NewInt(1)) == 0 {
		return result
	}
	return 0
}
