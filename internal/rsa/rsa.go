package rsa

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
	// C = m^E mod N
	return math.ModExp(message, s.publicKey.E, s.publicKey.N), nil
}

func (s *RSAService) Decrypt(ciphertext *big.Int) (*big.Int, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key not generated")
	}
	
	// m = C^d mod N
	return math.ModExp(ciphertext, s.privateKey.D, s.publicKey.N), nil
}

func (s *RSAService) GetPublicKey() (*PublicKey, error) {
	if s.publicKey == nil {
		return nil, fmt.Errorf("public key not generated")
	}
	return s.publicKey, nil
}
