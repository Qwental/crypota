package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Qwental/crypota/internal/context"
	"github.com/Qwental/crypota/internal/deal"
	"github.com/Qwental/crypota/internal/des"
	"github.com/Qwental/crypota/internal/modes"
	"github.com/Qwental/crypota/internal/padding"
)

func main() {
	cleanupOldFiles()
	demonstrateDES()
	demonstrateDEAL()
}

func cleanupOldFiles() {
	patterns := []string{
		"testdata/encrypted_*.enc",
		"testdata/decrypted_*",
	}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, file := range matches {
			os.Remove(file)
		}
	}
}

func demonstrateDES() {
	fmt.Println("DES шифрование")

	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}

	testModes := []struct {
		mode modes.CipherMode
		name string
	}{
		{modes.ECB, "ECB"},
		{modes.CBC, "CBC"},
		{modes.CTR, "CTR"},
	}

	for _, tm := range testModes {
		fmt.Printf("\nРежим %s:\n", tm.name)

		plaintext := make([]byte, 1024)
		rand.Read(plaintext)

		cipher := des.NewDESCipher()

		var iv []byte
		if tm.mode != modes.ECB {
			iv = make([]byte, cipher.BlockSize())
			rand.Read(iv)
		}

		ctx, err := context.NewCipherContext(
			cipher,
			key,
			tm.mode,
			padding.PKCS7,
			iv,
		)
		if err != nil {
			log.Fatalf("не удалось создать контекст: %v", err)
		}

		ciphertext, err := ctx.Encrypt(plaintext)
		if err != nil {
			log.Fatalf("ошибка шифрования: %v", err)
		}
		fmt.Printf("  зашифровали %d байт -> %d байт\n", len(plaintext), len(ciphertext))

		decrypted, err := ctx.Decrypt(ciphertext)
		if err != nil {
			log.Fatalf("ошибка дешифрования: %v", err)
		}

		if verifyData(plaintext, decrypted) {
			fmt.Println("  расшифровка прошла успешно")
		} else {
			fmt.Println("  расшифровка провалилась")
		}
	}

	fmt.Println("\nШифруем файлы через DES:")
	testFiles := getTestFiles()
	for _, file := range testFiles {
		testFileEncryption(des.NewDESCipher(), key, "DES", file)
	}
}
func demonstrateDEAL() {
	fmt.Println("DEAL шифрование")

	key := make([]byte, 16)
	rand.Read(key)

	plaintext := make([]byte, 2048)
	rand.Read(plaintext)

	cipher, err := deal.NewDEALCipher(16)
	if err != nil {
		log.Fatalf("Не удалось создать DEAL шифр: %v", err)
	}

	iv := make([]byte, cipher.BlockSize())
	rand.Read(iv)

	ctx, err := context.NewCipherContext(
		cipher,
		key,
		modes.CBC,
		padding.PKCS7,
		iv,
	)
	if err != nil {
		log.Fatalf("не удалось создать контекст: %v", err)
	}

	ciphertext, err := ctx.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("ошибка шифрования: %v", err)
	}
	fmt.Printf("зашифровали %d байт -> %d байт\n", len(plaintext), len(ciphertext))

	decrypted, err := ctx.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("ошибка дешифрования: %v", err)
	}

	if verifyData(plaintext, decrypted) {
		fmt.Println("DEAL расшифровка успешна")
	} else {
		fmt.Println("DEAL расшифровка провалилась")
	}

	fmt.Println("\nШифруем файлы через DEAL:")
	testFiles := getTestFiles()
	for _, file := range testFiles {

		testFileEncryption(cipher, key, "DEAL", file)
	}
}

func getTestFiles() []string {
	files := []string{
		"testdata/test.txt",
		"testdata/pic.png",
		"testdata/sample-6s.mp3",
		"testdata/sample-clouds-400x300.jpg",
		"testdata/rfc3447.txt",
	}

	var existing []string
	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			existing = append(existing, file)
		}
	}
	return existing
}

func testFileEncryption(cipher interface{}, key []byte, name, inputFile string) {
	basename := filepath.Base(inputFile)
	ext := filepath.Ext(basename)
	nameOnly := basename[:len(basename)-len(ext)]

	encFile := fmt.Sprintf("testdata/encrypted_%s_%s.enc", name, nameOnly)
	decFile := fmt.Sprintf("testdata/decrypted_%s_%s%s", name, nameOnly, ext)

	os.MkdirAll("testdata", 0755)

	var ctx *context.CipherContext
	var err error

	switch c := cipher.(type) {
	case *des.DESCipher:
		iv := make([]byte, 8)
		rand.Read(iv)
		ctx, err = context.NewCipherContext(c, key, modes.CBC, padding.PKCS7, iv)
	case *deal.DEALCipher:
		iv := make([]byte, 16)
		rand.Read(iv)
		ctx, err = context.NewCipherContext(c, key, modes.CBC, padding.PKCS7, iv)
	}

	if err != nil {
		log.Printf("не удалось создать контекст для %s: %v", inputFile, err)
		return
	}

	if err := ctx.EncryptFile(inputFile, encFile); err != nil {
		log.Printf("не удалось зашифровать %s: %v", inputFile, err)
		return
	}

	if err := ctx.DecryptFile(encFile, decFile); err != nil {
		log.Printf("не удалось расшифровать %s: %v", inputFile, err)
		return
	}

	original, err := os.ReadFile(inputFile)
	if err != nil {
		log.Printf("не удалось прочитать оригинал %s: %v", inputFile, err)
		return
	}

	decrypted, err := os.ReadFile(decFile)
	if err != nil {
		log.Printf("не удалось прочитать расшифрованный %s: %v", decFile, err)
		return
	}

	if verifyData(original, decrypted) {
		fmt.Printf("  %s: ok\n", basename)
		fmt.Printf("    enc: %s\n", encFile)
		fmt.Printf("    dec: %s\n", decFile)
	} else {
		fmt.Printf("  %s: fail\n", basename)
	}
}

func verifyData(original, decrypted []byte) bool {
	if len(original) != len(decrypted) {
		return false
	}
	for i := range original {
		if original[i] != decrypted[i] {
			return false
		}
	}
	return true
}
