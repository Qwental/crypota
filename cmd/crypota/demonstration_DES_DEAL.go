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
	"github.com/Qwental/crypota/internal/interfaces"
	"github.com/Qwental/crypota/internal/modes"
	"github.com/Qwental/crypota/internal/padding"
)

func main() {
	cleanupOldFiles()
	testAllModesOnTextFile()
	testAllFilesWithOneMode()
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

func testAllModesOnTextFile() {
	textFile := findTextFile()
	if textFile == "" {
		log.Println("Текстовый файл не найден в testdata/")
		return
	}

	fmt.Printf("Используется файл: %s\n\n", textFile)

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

	fmt.Println("DES с разными режимами:")
	desKey := make([]byte, 8)
	rand.Read(desKey)
	desCipher := des.NewDESCipher()

	for _, modeInfo := range allModes {
		testFileWithMode(desCipher, desKey, "DES", textFile, modeInfo.mode, modeInfo.name, 8)
	}

	fmt.Println("\nDEAL-128 с разными режимами:")
	deal128Key := make([]byte, 16)
	rand.Read(deal128Key)
	deal128, _ := deal.NewDEALCipher(16)

	for _, modeInfo := range allModes {
		testFileWithMode(deal128, deal128Key, "DEAL-128", textFile, modeInfo.mode, modeInfo.name, 16)
	}

	fmt.Println("\nDEAL-192 с разными режимами:")
	deal192Key := make([]byte, 24)
	rand.Read(deal192Key)
	deal192, _ := deal.NewDEALCipher(24)

	for _, modeInfo := range allModes {
		testFileWithMode(deal192, deal192Key, "DEAL-192", textFile, modeInfo.mode, modeInfo.name, 16)
	}

	fmt.Println("\nDEAL-256 с разными режимами:")
	deal256Key := make([]byte, 32)
	rand.Read(deal256Key)
	deal256, _ := deal.NewDEALCipher(32)

	for _, modeInfo := range allModes {
		testFileWithMode(deal256, deal256Key, "DEAL-256", textFile, modeInfo.mode, modeInfo.name, 16)
	}
}

func testAllFilesWithOneMode() {
	testFiles := getTestFiles()
	if len(testFiles) == 0 {
		log.Println("Тестовые файлы не найдены в testdata/")
		return
	}

	fmt.Println("DES в режиме CBC:")
	desKey := make([]byte, 8)
	rand.Read(desKey)
	desCipher := des.NewDESCipher()

	for _, file := range testFiles {
		testFileWithMode(desCipher, desKey, "DES", file, modes.CBC, "CBC", 8)
	}

	fmt.Println("\nDEAL-128 в режиме CBC:")
	deal128Key := make([]byte, 16)
	rand.Read(deal128Key)
	deal128, _ := deal.NewDEALCipher(16)

	for _, file := range testFiles {
		testFileWithMode(deal128, deal128Key, "DEAL-128", file, modes.CBC, "CBC", 16)
	}

	fmt.Println("\nDEAL-192 в режиме CBC:")
	deal192Key := make([]byte, 24)
	rand.Read(deal192Key)
	deal192, _ := deal.NewDEALCipher(24)

	for _, file := range testFiles {
		testFileWithMode(deal192, deal192Key, "DEAL-192", file, modes.CBC, "CBC", 16)
	}

	fmt.Println("\nDEAL-256 в режиме CBC:")
	deal256Key := make([]byte, 32)
	rand.Read(deal256Key)
	deal256, _ := deal.NewDEALCipher(32)

	for _, file := range testFiles {
		testFileWithMode(deal256, deal256Key, "DEAL-256", file, modes.CBC, "CBC", 16)
	}
}

func testFileWithMode(cipher interfaces.BlockCipher, key []byte, cipherName, inputFile string, mode modes.CipherMode, modeName string, blockSize int) {
	basename := filepath.Base(inputFile)
	ext := filepath.Ext(basename)
	nameOnly := basename[:len(basename)-len(ext)]

	encFile := fmt.Sprintf("testdata/encrypted_%s_%s_%s.enc", cipherName, modeName, nameOnly)
	decFile := fmt.Sprintf("testdata/decrypted_%s_%s_%s%s", cipherName, modeName, nameOnly, ext)

	os.MkdirAll("testdata", 0755)

	var iv []byte
	if mode != modes.ECB {
		iv = make([]byte, blockSize)
		rand.Read(iv)
	}

	ctx, err := context.NewCipherContext(cipher, key, mode, padding.PKCS7, iv)
	if err != nil {
		fmt.Printf("  [FAIL] %s: %v\n", basename, err)
		return
	}

	if err := ctx.EncryptFile(inputFile, encFile); err != nil {
		fmt.Printf("  [FAIL] %s: шифрование - %v\n", basename, err)
		return
	}

	if err := ctx.DecryptFile(encFile, decFile); err != nil {
		fmt.Printf("  [FAIL] %s: дешифрование - %v\n", basename, err)
		return
	}

	original, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("  [FAIL] %s: чтение оригинала - %v\n", basename, err)
		return
	}

	decrypted, err := os.ReadFile(decFile)
	if err != nil {
		fmt.Printf("  [FAIL] %s: чтение дешифрованного - %v\n", basename, err)
		return
	}

	if verifyData(original, decrypted) {
		fmt.Printf("  [OK] %s (%d байт)\n", basename, len(original))
	} else {
		fmt.Printf("  [FAIL] %s (данные не совпадают)\n", basename)
	}
}

func findTextFile() string {
	candidates := []string{
		"testdata/test.txt",
		"testdata/rfc3447.txt",
	}

	for _, file := range candidates {
		if _, err := os.Stat(file); err == nil {
			return file
		}
	}
	return ""
}

func getTestFiles() []string {
	files := []string{
		"testdata/test.txt",
		"testdata/pic.png",
		"testdata/sample-clouds-400x300.jpg",
		"testdata/sample-6s.mp3",
		"testdata/sample-5s.mp4",
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
