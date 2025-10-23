package math

import "math/big"

// LegendreSymbol вычисляет символ Лежандра (a/p)
// (a/p) ≡ a^((p-1)/2) (mod p)
func LegendreSymbol(a, p *big.Int) int {
	if p.Cmp(big.NewInt(3)) < 0 || p.Bit(0) == 0 {
		panic("p must be an odd prime >= 3")
	}

	a = new(big.Int).Mod(a, p)

	if a.Cmp(big.NewInt(0)) == 0 {
		return 0
	}

	result := 1

	for a.Cmp(big.NewInt(0)) != 0 {
		for a.Bit(0) == 0 {
			a.Rsh(a, 1)
			pMod8 := new(big.Int).Mod(p, big.NewInt(8))
			if pMod8.Cmp(big.NewInt(3)) == 0 || pMod8.Cmp(big.NewInt(5)) == 0 {
				result = -result
			}
		}

		a, p = p, a

		if new(big.Int).Mod(a, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 &&
			new(big.Int).Mod(p, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 {
			result = -result
		}

		a = new(big.Int).Mod(a, p)
	}

	if p.Cmp(big.NewInt(1)) == 0 {
		return result
	}
	return 0
}
