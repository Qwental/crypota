package rsabad

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
		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
		qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
		phiN := new(big.Int).Mul(pMinus1, qMinus1)
		e := big.NewInt(3)

		if math.GCD(e, phiN).Cmp(big.NewInt(1)) != 0 {
			continue
		}
		d := new(big.Int).ModInverse(e, phiN)
		if d == nil {
			continue
		}

		pubKey := &PublicKey{E: e, N: n}
		privKey := &PrivateKey{D: d, P: p, Q: q}
		return pubKey, privKey, nil
	}
}

func (kg *KeyGenerator) GenerateWeakKeys() (*PublicKey, *PrivateKey, error) {
	for {
		p, err := kg.generatePrime()
		if err != nil {
			return nil, nil, err
		}
		q, err := kg.generatePrime()
		if err != nil {
			return nil, nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		phiN := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

		nRoot4 := new(big.Int).Sqrt(new(big.Int).Sqrt(n))
		limit := new(big.Int).Div(nRoot4, big.NewInt(3))

		if limit.Cmp(big.NewInt(3)) <= 0 {
			continue 
		}

		var d, e *big.Int

		for i := 0; i < 500; i++ { 
			dCandidate, err := rand.Int(rand.Reader, new(big.Int).Sub(limit, big.NewInt(3)))
			if err != nil {
				return nil, nil, err
			}
			dCandidate.Add(dCandidate, big.NewInt(3))

			if math.GCD(dCandidate, phiN).Cmp(big.NewInt(1)) == 0 {
				d = dCandidate
				break
			}
		}

		if d == nil {
			continue
		} 

		e = new(big.Int).ModInverse(d, phiN)
		if e == nil {
			continue
		} 

		pubKey := &PublicKey{E: e, N: n}
		privKey := &PrivateKey{D: d, P: p, Q: q}
		return pubKey, privKey, nil
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
