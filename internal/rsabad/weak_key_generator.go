package rsabad

import (
	"crypto/rand"
	"math/big"

	"github.com/Qwental/crypota/internal/math"
	"github.com/Qwental/crypota/internal/primality"
)

func GenerateWeakKeyPair(bitLength int) (*PublicKey, *PrivateKey, error) {
	primeTester := primality.NewMillerRabinTest()

	for {
		p, err := rand.Prime(rand.Reader, bitLength/2)
		if err != nil {
			return nil, nil, err
		}
		q, err := rand.Prime(rand.Reader, bitLength/2)
		if err != nil {
			return nil, nil, err
		}

		if p.Cmp(q) == 0 {
			continue
		}
		if !primeTester.IsPrime(p, 0.99) || !primeTester.IsPrime(q, 0.99) {
			continue
		}

		// 2. Вычисляем n и phiN
		n := new(big.Int).Mul(p, q)
		phiN := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

		nRoot4 := new(big.Int).Sqrt(new(big.Int).Sqrt(n))
		limit := new(big.Int).Div(nRoot4, big.NewInt(3))

		if limit.Cmp(big.NewInt(3)) <= 0 {
			continue
		}

		var d, e *big.Int

		for i := 0; i < 100; i++ {
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
