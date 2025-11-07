package primality

import ("github.com/Qwental/crypota/internal/math"
	"math/big")

type FermatTest struct {
    BasePrimalityTest
}

func NewFermatTest() *FermatTest {
    test := &FermatTest{}
	test.errorChance = 0.5
    test.iterationTester = func(n, a *big.Int) bool {
        nMinus1 := new(big.Int).Sub(n, big.NewInt(1))
        return math.ModExp(a, nMinus1, n).Cmp(big.NewInt(1)) == 0
    }
    return test
}
