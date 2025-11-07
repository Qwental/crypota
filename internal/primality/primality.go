package primality

import (
	"crypto/rand"
	"math"
	"math/big"
)

type PrimalityTester interface {
	IsPrime(n *big.Int, probability float64) bool
}

type BasePrimalityTest struct {
	iterationTester func(n, a *big.Int) bool
	errorChance     float64
}

func (b *BasePrimalityTest) IsPrime(n *big.Int, probability float64) bool {

	if n.Cmp(big.NewInt(2)) < 0 {
		return false
	}
	if n.Cmp(big.NewInt(3)) == 0 { // Добавим 3 для явности
		return true
	}
	if n.Bit(0) == 0 {
		return n.Cmp(big.NewInt(2)) == 0
	}

	// Для n < 4 нет смысла в вероятностных тестах
	if n.Cmp(big.NewInt(4)) < 0 {
		return true // 2 и 3 уже обработаны
	}

	k := calculateIterations(probability, b.errorChance)

	for i := 0; i < k; i++ {
		a, err := generateRandomA(n)
		if err != nil {
			
			panic(err)
		}

		if !b.iterationTester(n, a) {
			return false
		}
	}

	return true
}

func calculateIterations(probability, errorChance float64) int {
	if probability < 0.5 || probability >= 1.0 {
		probability = 0.99 // Значение по умолчанию
	}

	// k >= ln(1-p) / ln(errorChance)
	k := math.Log(1.0-probability) / math.Log(errorChance)

	return int(math.Ceil(k))
}

func generateRandomA(n *big.Int) (*big.Int, error) {

	max := new(big.Int).Sub(n, big.NewInt(3))

	a, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}

	return a.Add(a, big.NewInt(2)), nil
}

func decompose(nMinus1 *big.Int) (int64, *big.Int) {
	s := new(big.Int).Set(nMinus1)
	d := int64(0)

	for s.Bit(0) == 0 {
		s.Rsh(s, 1)
		d++
	}

	return d, s
}
