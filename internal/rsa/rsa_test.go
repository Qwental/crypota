package rsa

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestKeyGenerationAndEncryptionForAllTypes(t *testing.T) {
	testTypes := []struct {
		testType PrimalityTestType
		name     string
	}{
		{Fermat, "Fermat"},
		{SolovayStrassen, "SolovayStrassen"},
		{MillerRabin, "MillerRabin"},
	}

	for _, tt := range testTypes {
		t.Run(tt.name, func(t *testing.T) {
			rsaService, err := NewRSAService(tt.testType, 512, 0.99)
			if err != nil {
				t.Fatalf("Failed to create RSA service: %v", err)
			}
			if err := rsaService.GenerateNewKeys(); err != nil {
				t.Fatalf("Failed to generate keys: %v", err)
			}
			if rsaService.publicKey == nil || rsaService.privateKey == nil {
				t.Fatal("Keys were not generated")
			}

			message := big.NewInt(123456789)

			ciphertext, err := rsaService.Encrypt(message)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := rsaService.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if message.Cmp(decrypted) != 0 {
				t.Errorf("Decrypted message does not match. Original: %s, Decrypted: %s", message.String(), decrypted.String())
			}
		})
	}
}

func TestEncryptionDecryption_Parametrized(t *testing.T) {
	testTypes := []struct {
		testType PrimalityTestType
		name     string
	}{
		{Fermat, "Fermat"},
		{SolovayStrassen, "SolovayStrassen"},
		{MillerRabin, "MillerRabin"},
	}

	for _, tt := range testTypes {
		t.Run(tt.name, func(t *testing.T) {
			rsaService, _ := NewRSAService(tt.testType, 512, 0.99)
			rsaService.GenerateNewKeys()

			for i := 0; i < 10; i++ {
				maxMsg := new(big.Int).Sub(rsaService.publicKey.N, big.NewInt(1))
				message, _ := rand.Int(rand.Reader, maxMsg)

				ciphertext, _ := rsaService.Encrypt(message)
				decrypted, _ := rsaService.Decrypt(ciphertext)

				if message.Cmp(decrypted) != 0 {
					t.Fatalf("Random message test failed. Original: %s, Decrypted: %s", message.String(), decrypted.String())
				}
			}

			// 2. Тест с граничными значениями (0 и N-1)
			zero := big.NewInt(0)
			encryptedZero, err := rsaService.Encrypt(zero)
			if err != nil {
				t.Fatalf("Encrypt(0) failed: %v", err)
			}
			decryptedZero, err := rsaService.Decrypt(encryptedZero)
			if err != nil {
				t.Fatalf("Decrypt(Encrypt(0)) failed: %v", err)
			}

			if zero.Cmp(decryptedZero) != 0 {
				t.Error("Encryption/Decryption failed for message = 0")
			}

			maxMessage := new(big.Int).Sub(rsaService.publicKey.N, big.NewInt(1))
			encryptedMax, err := rsaService.Encrypt(maxMessage)
			if err != nil {
				t.Fatalf("Encrypt(N-1) failed: %v", err)
			}
			decryptedMax, err := rsaService.Decrypt(encryptedMax)
			if err != nil {
				t.Fatalf("Decrypt(Encrypt(N-1)) failed: %v", err)
			}

			if maxMessage.Cmp(decryptedMax) != 0 {
				t.Error("Encryption/Decryption failed for message = N-1")
			}
		})
	}
}

func TestEncrypt_MessageTooBig(t *testing.T) {
	rsaService, _ := NewRSAService(MillerRabin, 256, 0.99)
	rsaService.GenerateNewKeys()

	tooBigMessage := new(big.Int).Add(rsaService.publicKey.N, big.NewInt(10))

	_, err := rsaService.Encrypt(tooBigMessage)
	if err == nil {
		t.Errorf("Encrypt should return an error for a message larger than N, but it didn't")
	}
}
