package rsabad

import (
	"fmt"
	"math/big"

	"github.com/Qwental/crypota/internal/math"
)

type PrimalityTestType int

const (
	MillerRabin PrimalityTestType = iota
	SolovayStrassen
	Fermat
)

type PublicKey struct {
	E *big.Int
	N *big.Int
}

type PrivateKey struct {
	D *big.Int
	P *big.Int
	Q *big.Int
}

type RSAService struct {
	keyGenerator *KeyGenerator
	publicKey    *PublicKey
	privateKey   *PrivateKey
}

func NewRSAService(testType PrimalityTestType, bitLength int, probability float64) (*RSAService, error) {
	keygen, err := newKeyGenerator(testType, bitLength, probability)
	if err != nil {
		return nil, err
	}
	return &RSAService{
		keyGenerator: keygen,
	}, nil
}

func (s *RSAService) GenerateNewKeys() error {
	pub, priv, err := s.keyGenerator.GenerateKeys()
	if err != nil {
		return err
	}
	s.publicKey = pub
	s.privateKey = priv
	return nil
}

func (s *RSAService) Encrypt(message *big.Int) (*big.Int, error) {
	if s.publicKey == nil {
		return nil, fmt.Errorf("public key not generated")
	}
	if message.Cmp(s.publicKey.N) >= 0 {
		return nil, fmt.Errorf("message is too large for the key modulus")
	}
	return math.ModExp(message, s.publicKey.E, s.publicKey.N), nil
}

func (s *RSAService) Decrypt(ciphertext *big.Int) (*big.Int, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key not generated")
	}
	return math.ModExp(ciphertext, s.privateKey.D, s.publicKey.N), nil
}

func (s *RSAService) GetPublicKey() (*PublicKey, error) {
	if s.publicKey == nil {
		return nil, fmt.Errorf("public key not generated")
	}
	return s.publicKey, nil
}
func (s *RSAService) GetPrivateKey() (*PrivateKey, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key not generated")
	}
	return s.privateKey, nil
}

func (kg *KeyGenerator) GenerateVulnerableKeys_Wiener() (*PublicKey, *PrivateKey, error) {
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

		nRoot4 := new(big.Int).Sqrt(new(big.Int).Sqrt(n))
		limit := new(big.Int).Div(nRoot4, big.NewInt(3))

		d := new(big.Int).Set(limit)
		if d.Bit(0) == 0 {
			d.Sub(d, big.NewInt(1))
		}

		if d.Cmp(big.NewInt(2)) <= 0 || math.GCD(d, phiN).Cmp(big.NewInt(1)) != 0 {
			continue
		}

		e := new(big.Int).ModInverse(d, phiN)
		if e == nil {
			continue
		}

		pubKey := &PublicKey{E: e, N: n}
		privKey := &PrivateKey{D: d, P: p, Q: q}
		return pubKey, privKey, nil
	}
}
