package primality

import ("github.com/Qwental/crypota/internal/math"
	"math/big")

type MillerRabinTest struct {
    BasePrimalityTest
}

func NewMillerRabinTest() *MillerRabinTest {
    test := &MillerRabinTest{}
	test.errorChance = 0.25
    test.iterationTester = func(n, a *big.Int) bool {

        nMinus1 := new(big.Int).Sub(n, big.NewInt(1))
        d, s := decompose(nMinus1)


        x := math.ModExp(a, s, n)
        if x.Cmp(big.NewInt(1)) == 0 {
            return true
        }

        for i := int64(0); i < d; i++ {
            if x.Cmp(nMinus1) == 0 {
                return true
            }
            x = math.ModExp(x, big.NewInt(2), n)
        }
        
        return false
    }
    return test
}


