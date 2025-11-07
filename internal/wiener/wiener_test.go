package wiener

import (
	"math/big"
	"testing"

	"github.com/Qwental/crypota/internal/rsa"
	"github.com/Qwental/crypota/internal/rsabad"
)

func TestWienerAttack_Successful(t *testing.T) {
	pubKey, privKey, err := rsabad.GenerateWeakKeyPair(512)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать гарантированно уязвимый ключ: %v", err)
	}

	attacker := NewWienerAttacker()
	result, err := attacker.Attack(pubKey.E, pubKey.N)

	if err != nil {
		t.Fatalf("Атака Винера на уязвимый ключ не удалась: %v", err)
	}

	if result.D.Cmp(privKey.D) != 0 {
		t.Errorf("Найденный d не совпадает с оригинальным!\nНайдено: %s\nОригинал: %s", result.D.String(), privKey.D.String())
	}
}

func TestWienerAttack_FailsOnSecureKey(t *testing.T) {
	secureRSAService, err := rsa.NewRSAService(rsa.MillerRabin, 1024, 0.99)
	if err != nil {
		t.Fatalf("Не удалось создать защищенный RSA сервис: %v", err)
	}
	if err := secureRSAService.GenerateNewKeys(); err != nil {
		t.Fatalf("Не удалось сгенерировать защищенный ключ: %v", err)
	}
	pubKey, _ := secureRSAService.GetPublicKey()

	attacker := NewWienerAttacker()
	_, err = attacker.Attack(pubKey.E, pubKey.N)

	if err == nil {
		t.Fatal("КРИТИЧЕСКАЯ УЯЗВИМОСТЬ! Атака Винера прошла на защищенном ключе!")
	}
}

func TestWienerAttack_WithExample(t *testing.T) {
	n := big.NewInt(90581)
	e := big.NewInt(17993)
	expectedD := big.NewInt(5)

	attacker := NewWienerAttacker()
	result, err := attacker.Attack(e, n)

	if err != nil {
		t.Fatalf("Атака на примере не удалась: %v", err)
	}
	if result.D.Cmp(expectedD) != 0 {
		t.Errorf("Найденный d не совпадает с ожидаемым!\nОжидалось: %s\nНайдено: %s", expectedD.String(), result.D.String())
	}
}
