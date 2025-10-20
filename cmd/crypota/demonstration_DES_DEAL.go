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

func shouldSkipCombination(mode modes.CipherMode, pad padding.PaddingMode) bool {
	blockModes := []modes.CipherMode{modes.ECB, modes.CBC, modes.PCBC}
	for _, bm := range blockModes {
		if mode == bm && pad == padding.Zeros {
			return true
		}
	}
	return false
}

func demonstrateDES() {
	fmt.Println("DES")

	allModes := []struct {
		mode modes.CipherMode
		name string
	}{
		{modes.ECB, "ECB"},
		{modes.CBC, "CBC"},
		{modes.PCBC, "PCBC"},
		{modes.CFB, "CFB"},
		{modes.OFB, "OFB"},
		{modes.CTR, "CTR"},
	}

	allPaddings := []struct {
		pad  padding.PaddingMode
		name string
	}{
		{padding.PKCS7, "PKCS7"},
		{padding.ANSIX923, "ANSI X.923"},
		{padding.ISO10126, "ISO 10126"},
		{padding.Zeros, "Zeros"},
	}

	key := make([]byte, 8)
	rand.Read(key)

	cipher := des.NewDESCipher()

	for _, modeInfo := range allModes {
		for _, padInfo := range allPaddings {
			if shouldSkipCombination(modeInfo.mode, padInfo.pad) {
				fmt.Printf("\nРежим: %s | Набивка: %s\n", modeInfo.name, padInfo.name)
				fmt.Printf("  [SKIP] известная несовместимость\n")
				continue
			}

			fmt.Printf("\nРежим: %s | Набивка: %s\n", modeInfo.name, padInfo.name)

			var iv []byte
			if modeInfo.mode != modes.ECB {
				iv = make([]byte, cipher.BlockSize())
				rand.Read(iv)
			}

			ctx, err := context.NewCipherContext(
				cipher,
				key,
				modeInfo.mode,
				padInfo.pad,
				iv,
			)
			if err != nil {
				log.Printf("  [SKIP] не удалось создать контекст: %v\n", err)
				continue
			}

			plaintext := make([]byte, 100)
			rand.Read(plaintext)

			ciphertext, err := ctx.Encrypt(plaintext)
			if err != nil {
				log.Printf("  [FAIL] ошибка шифрования: %v\n", err)
				continue
			}

			decrypted, err := ctx.Decrypt(ciphertext)
			if err != nil {
				log.Printf("  [FAIL] ошибка дешифрования: %v\n", err)
				continue
			}

			if verifyData(plaintext, decrypted) {
				fmt.Printf("  [OK] 100 байт\n")
			} else {
				fmt.Printf("  [FAIL] данные не совпадают\n")
			}
		}
	}

	fmt.Println("\n--- Шифрование файлов через DES ---")
	testFiles := getTestFiles()
	if len(testFiles) > 0 {
		file := testFiles[0]
		for _, modeInfo := range allModes {
			testFileEncryption(des.NewDESCipher(), key, fmt.Sprintf("DES-%s", modeInfo.name), file, modeInfo.mode)
		}
	}
}

func demonstrateDEAL() {
	fmt.Println("\nDEAL шифрование")

	keySizes := []struct {
		size int
		name string
	}{
		{16, "DEAL-128"},
		{24, "DEAL-192"},
		{32, "DEAL-256"},
	}

	allModes := []struct {
		mode modes.CipherMode
		name string
	}{
		{modes.ECB, "ECB"},
		{modes.CBC, "CBC"},
		{modes.PCBC, "PCBC"},
		{modes.CFB, "CFB"},
		{modes.OFB, "OFB"},
		{modes.CTR, "CTR"},
	}

	allPaddings := []struct {
		pad  padding.PaddingMode
		name string
	}{
		{padding.PKCS7, "PKCS7"},
		{padding.ANSIX923, "ANSI X.923"},
		{padding.ISO10126, "ISO 10126"},
		{padding.Zeros, "Zeros"},
	}

	for _, ks := range keySizes {
		fmt.Printf("\n--- %s ---\n", ks.name)

		key := make([]byte, ks.size)
		rand.Read(key)

		cipher, err := deal.NewDEALCipher(ks.size)
		if err != nil {
			log.Fatalf("Не удалось создать DEAL шифр: %v", err)
		}

		for _, modeInfo := range allModes {
			for _, padInfo := range allPaddings {
				if shouldSkipCombination(modeInfo.mode, padInfo.pad) {
					fmt.Printf("\nРежим: %s | Набивка: %s\n", modeInfo.name, padInfo.name)
					fmt.Printf("  [SKIP] известная несовместимость\n")
					continue
				}

				fmt.Printf("\nРежим: %s | Набивка: %s\n", modeInfo.name, padInfo.name)

				var iv []byte
				if modeInfo.mode != modes.ECB {
					iv = make([]byte, cipher.BlockSize())
					rand.Read(iv)
				}

				ctx, err := context.NewCipherContext(
					cipher,
					key,
					modeInfo.mode,
					padInfo.pad,
					iv,
				)
				if err != nil {
					log.Printf("  [SKIP] не удалось создать контекст: %v\n", err)
					continue
				}

				plaintext := make([]byte, 100)
				rand.Read(plaintext)

				ciphertext, err := ctx.Encrypt(plaintext)
				if err != nil {
					log.Printf("  [FAIL] ошибка шифрования: %v\n", err)
					continue
				}

				decrypted, err := ctx.Decrypt(ciphertext)
				if err != nil {
					log.Printf("  [FAIL] ошибка дешифрования: %v\n", err)
					continue
				}

				if verifyData(plaintext, decrypted) {
					fmt.Printf("  [OK] 100 байт\n")
				} else {
					fmt.Printf("  [FAIL] данные не совпадают\n")
				}
			}
		}

		fmt.Printf("\n--- Шифрование файлов через %s ---\n", ks.name)
		testFiles := getTestFiles()
		if len(testFiles) > 0 {
			file := testFiles[0]
			for _, modeInfo := range allModes {
				testFileEncryption(cipher, key, fmt.Sprintf("%s-%s", ks.name, modeInfo.name), file, modeInfo.mode)
			}
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
		var iv []byte
		if mode != modes.ECB {
			iv = make([]byte, 8)
			rand.Read(iv)
		}
		ctx, err = context.NewCipherContext(c, key, mode, padding.PKCS7, iv)
	case *deal.DEALCipher:
		var iv []byte
		if mode != modes.ECB {
			iv = make([]byte, 16)
			rand.Read(iv)
		}
		ctx, err = context.NewCipherContext(c, key, mode, padding.PKCS7, iv)
	}

	if err != nil {
		log.Printf("  [SKIP] %s: %v\n", basename, err)
		return
	}

	if err := ctx.EncryptFile(inputFile, encFile); err != nil {
		log.Printf("  [FAIL] %s: шифрование - %v\n", basename, err)
		return
	}

	if err := ctx.DecryptFile(encFile, decFile); err != nil {
		log.Printf("  [FAIL] %s: дешифрование - %v\n", basename, err)
		return
	}

	original, err := os.ReadFile(inputFile)
	if err != nil {
		log.Printf("  [FAIL] %s: чтение оригинала - %v\n", basename, err)
		return
	}

	decrypted, err := os.ReadFile(decFile)
	if err != nil {
		log.Printf("  [FAIL] %s: чтение дешифрованного - %v\n", basename, err)
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
