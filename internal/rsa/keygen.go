package rsa

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/Qwental/crypota/internal/math"
	"github.com/Qwental/crypota/internal/primality"
)

type KeyGenerator struct {
	primeTester primality.PrimalityTester
	bitLength   int
	probability float64
}

func newKeyGenerator(testType PrimalityTestType, bitLength int, probability float64) (*KeyGenerator, error) {
	var tester primality.PrimalityTester
	switch testType {
	case MillerRabin:
		tester = primality.NewMillerRabinTest()
	case SolovayStrassen:
		tester = primality.NewSolovayStrassenTest()
	case Fermat:
		tester = primality.NewFermatTest()
	default:
		return nil, fmt.Errorf("unknown primality test type: %d", testType)
	}

	return &KeyGenerator{
		primeTester: tester,
		bitLength:   bitLength,
		probability: probability,
	}, nil
}

func (kg *KeyGenerator) GenerateKeys() (*PublicKey, *PrivateKey, error) {
	for {
		p, err := kg.generatePrime()
		if err != nil {
			return nil, nil, err
		}

		q, err := kg.generatePrime()
		if err != nil {
			return nil, nil, err
		}

		// Убедимся, что p != q
		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
		qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
		phiN := new(big.Int).Mul(pMinus1, qMinus1)

		e := big.NewInt(65537)

		// Проверяем, что gcd(e, phiN) == 1
		if math.GCD(e, phiN).Cmp(big.NewInt(1)) != 0 {
			continue
		}
		
		d := new(big.Int).ModInverse(e, phiN)
		if d == nil {
			continue
		}

		if isSecureAgainstAttacks(p, q, d, n) {
			pubKey := &PublicKey{E: e, N: n}
			privKey := &PrivateKey{D: d, P: p, Q: q}
			return pubKey, privKey, nil
		}
	}
}

func (kg *KeyGenerator) generatePrime() (*big.Int, error) {
	for {
		p, err := rand.Prime(rand.Reader, kg.bitLength)
		if err != nil {
			return nil, err
		}

		if kg.primeTester.IsPrime(p, kg.probability) {
			return p, nil
		}
	}
}

// isSecureAgainstAttacks проверяет защиту от атак Ферма и Винера.
func isSecureAgainstAttacks(p, q, d, n *big.Int) bool {
	// Защита от атаки Ферма p и q не должны быть слишком близки
	diff := new(big.Int).Sub(p, q)
	diff.Abs(diff)

	nRoot4 := new(big.Int)
	nRoot2 := new(big.Int).Sqrt(n)
	nRoot4.Sqrt(nRoot2)

	limitFermat := new(big.Int).Mul(nRoot4, big.NewInt(2))

	if diff.Cmp(limitFermat) <= 0 {
		return false // p и q слишком близки
	}

	// Защита от атаки Винера: d должно быть достаточно большим.
	limitWiener := new(big.Int).Div(nRoot4, big.NewInt(3))

	if d.Cmp(limitWiener) <= 0 {
		return false
	}

	return true
}
