package primality

import ("github.com/Qwental/crypota/internal/math"
	"math/big")


type SolovayStrassenTest struct {
    BasePrimalityTest
}

func NewSolovayStrassenTest() *SolovayStrassenTest {
    test := &SolovayStrassenTest{}
	test.errorChance = 0.5
    test.iterationTester = func(n, a *big.Int) bool {

        if math.GCD(a, n).Cmp(big.NewInt(1)) > 0 {
            return false
        }

        nMinus1Div2 := new(big.Int).Rsh(new(big.Int).Sub(n, big.NewInt(1)), 1)
        left := math.ModExp(a, nMinus1Div2, n)
        
        jacobi := big.NewInt(int64(math.JacobiSymbol(a, n)))

        right := new(big.Int).Mod(jacobi, n)
        
        return left.Cmp(right) == 0
    }
    return test
}
