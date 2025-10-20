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
	fmt.Println("Используется режим CTR (Counter Mode)")
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
	fmt.Println("=== DES-CTR шифрование ===")

	key := make([]byte, 8)
	rand.Read(key)

	cipher := des.NewDESCipher()
	iv := make([]byte, cipher.BlockSize())
	rand.Read(iv)

	ctx, err := context.NewCipherContext(
		cipher,
		key,
		modes.CTR,
		padding.PKCS7,
		iv,
	)
	if err != nil {
		log.Fatalf("не удалось создать контекст: %v", err)
	}

	testSizes := []int{100, 1024, 4096}
	for _, size := range testSizes {
		plaintext := make([]byte, size)
		rand.Read(plaintext)

		ciphertext, err := ctx.Encrypt(plaintext)
		if err != nil {
			log.Fatalf("ошибка шифрования: %v", err)
		}

		decrypted, err := ctx.Decrypt(ciphertext)
		if err != nil {
			log.Fatalf("ошибка дешифрования: %v", err)
		}

		if verifyData(plaintext, decrypted) {
			fmt.Printf("  [OK] %d байт\n", size)
		} else {
			fmt.Printf("  [FAIL] %d байт\n", size)
		}
	}

	fmt.Println("\nШифрование файлов через DES-CTR:")
	testFiles := getTestFiles()
	for _, file := range testFiles {
		testFileEncryption(des.NewDESCipher(), key, "DES-CTR", file, modes.CTR)
	}
}

func demonstrateDEAL() {
	fmt.Println("\n=== DEAL-CTR шифрование ===")

	keySizes := []struct {
		size int
		name string
	}{
		{16, "DEAL-128-CTR"},
		{24, "DEAL-192-CTR"},
		{32, "DEAL-256-CTR"},
	}

	for _, ks := range keySizes {
		fmt.Printf("\n--- %s ---\n", ks.name)

		key := make([]byte, ks.size)
		rand.Read(key)

		cipher, err := deal.NewDEALCipher(ks.size)
		if err != nil {
			log.Fatalf("Не удалось создать DEAL шифр: %v", err)
		}

		iv := make([]byte, cipher.BlockSize())
		rand.Read(iv)

		ctx, err := context.NewCipherContext(
			cipher,
			key,
			modes.CTR,
			padding.PKCS7,
			iv,
		)
		if err != nil {
			log.Fatalf("не удалось создать контекст: %v", err)
		}

		testSizes := []int{100, 1024, 4096, 16384}
		for _, size := range testSizes {
			plaintext := make([]byte, size)
			rand.Read(plaintext)

			ciphertext, err := ctx.Encrypt(plaintext)
			if err != nil {
				log.Fatalf("ошибка шифрования: %v", err)
			}

			decrypted, err := ctx.Decrypt(ciphertext)
			if err != nil {
				log.Fatalf("ошибка дешифрования: %v", err)
			}

			if verifyData(plaintext, decrypted) {
				fmt.Printf("  [OK] %d байт\n", size)
			} else {
				fmt.Printf("  [FAIL] %d байт\n", size)
			}
		}

		fmt.Printf("\nШифрование файлов через %s:\n", ks.name)
		testFiles := getTestFiles()
		for _, file := range testFiles {
			testFileEncryption(cipher, key, ks.name, file, modes.CTR)
		}
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

func testFileEncryption(cipher interface{}, key []byte, name, inputFile string, mode modes.CipherMode) {
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
		ctx, err = context.NewCipherContext(c, key, mode, padding.PKCS7, iv)
	case *deal.DEALCipher:
		iv := make([]byte, 16)
		rand.Read(iv)
		ctx, err = context.NewCipherContext(c, key, mode, padding.PKCS7, iv)
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
		fmt.Printf("  [OK] %s\n", basename)
	} else {
		fmt.Printf("  [FAIL] %s\n", basename)
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
