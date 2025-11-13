package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/Qwental/crypota/internal/context"
	"github.com/Qwental/crypota/internal/modes"
	"github.com/Qwental/crypota/internal/padding"
	"github.com/Qwental/crypota/internal/rijndael"
)

func main() {
	demonstrateRijndaelFiles()
}

func demonstrateRijndaelFiles() {
	fmt.Println("--- Демонстрация Rijndael с файлами ---")
	cleanupRijndaelFiles()

	blockSizes := []int{16, 24, 32}
	keySizes := []int{16, 24, 32}
	paddingModes := []struct {
		Mode padding.PaddingMode
		Name string
	}{
		{padding.Zeros, "Zeros"},
		{padding.ANSIX923, "ANSIX923"},
		{padding.PKCS7, "PKCS7"},
		{padding.ISO10126, "ISO10126"},
	}
	cipherModes := []struct {
		Mode modes.CipherMode
		Name string
	}{
		{modes.ECB, "ECB"},
		{modes.CBC, "CBC"},
		{modes.PCBC, "PCBC"},
		{modes.CFB, "CFB"},
		{modes.OFB, "OFB"},
		{modes.CTR, "CTR"},
	}
	testFiles := getTestFiles()
	if len(testFiles) == 0 {
		log.Println("Тестовые файлы не найдены в testdata/")
		return
	}

	for _, blockSize := range blockSizes {
		for _, keySize := range keySizes {
			for _, pm := range paddingModes {
				for _, cm := range cipherModes {
					configName := fmt.Sprintf("Rijndael_Block%d_Key%d_%s_%s", blockSize, keySize, cm.Name, pm.Name)
					fmt.Printf("\n--- Тестирование конфигурации: %s ---\n", configName)

					key := make([]byte, keySize)
					if _, err := rand.Read(key); err != nil {
						log.Printf("[%s] [FAIL] Ошибка генерации ключа: %v\n", configName, err)
						continue
					}

					for _, file := range testFiles {
						testFileEncryptionRijndael(file, configName, blockSize, key, cm.Mode, pm.Mode)
					}
				}
			}
		}
	}
}

func testFileEncryptionRijndael(inputFile, configName string, blockSize int, key []byte, cm modes.CipherMode, pm padding.PaddingMode) {
	fmt.Printf("  Обработка файла: %s\n", inputFile)
	basename := filepath.Base(inputFile)
	ext := filepath.Ext(basename)
	nameOnly := basename[:len(basename)-len(ext)]

	encFile := fmt.Sprintf("testdata/encrypted_%s_%s.enc", configName, nameOnly)
	decFile := fmt.Sprintf("testdata/decrypted_%s_%s%s", configName, nameOnly, ext)

	// Шифрование
	iv, err := encryptFileRijndael(inputFile, encFile, blockSize, key, cm, pm)
	if err != nil {
		fmt.Printf("    [FAIL] Ошибка шифрования: %v\n", err)
		return
	}
	fmt.Printf("    [OK] Файл зашифрован в %s\n", encFile)

	// Дешифрование
	if err := decryptFileRijndael(encFile, decFile, blockSize, key, iv, cm, pm); err != nil {
		fmt.Printf("    [FAIL] Ошибка дешифрования: %v\n", err)
		return
	}
	fmt.Printf("    [OK] Файл дешифрован в %s\n", decFile)

	// Проверка
	originalData, _ := os.ReadFile(inputFile)
	decryptedData, _ := os.ReadFile(decFile)
	if bytes.Equal(originalData, decryptedData) {
		fmt.Println("    [OK] Контрольные суммы совпадают.")
	} else {
		fmt.Printf("    [FAIL] Контрольные суммы не совпадают! Original: %d bytes, Decrypted: %d bytes\n", len(originalData), len(decryptedData))
	}
}

func encryptFileRijndael(inputFile, outputFile string, blockSize int, key []byte, cm modes.CipherMode, pm padding.PaddingMode) ([]byte, error) {
	cipher, err := rijndael.NewRijndaelCipher(blockSize, len(key), 0x1B)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания шифра: %w", err)
	}

	var iv []byte
	if cm != modes.ECB {
		iv = make([]byte, blockSize)
		if _, err := rand.Read(iv); err != nil {
			return nil, fmt.Errorf("ошибка генерации IV: %w", err)
		}
	}

	ctx, err := context.NewCipherContext(cipher, key, cm, pm, iv)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания контекста: %w", err)
	}

	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла: %w", err)
	}

	ciphertext, err := ctx.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("ошибка шифрования: %w", err)
	}

	dst, err := os.Create(outputFile)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания файла: %w", err)
	}
	defer dst.Close()

	if iv != nil {
		if _, err := dst.Write(iv); err != nil {
			return nil, fmt.Errorf("ошибка записи IV: %w", err)
		}
	}

	if _, err := dst.Write(ciphertext); err != nil {
		return nil, fmt.Errorf("ошибка записи шифротекста: %w", err)
	}

	return iv, nil
}

func decryptFileRijndael(inputFile, outputFile string, blockSize int, key, ivIn []byte, cm modes.CipherMode, pm padding.PaddingMode) error {
	src, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("ошибка открытия файла: %w", err)
	}
	defer src.Close()

	var iv []byte
	if cm != modes.ECB {
		iv = make([]byte, blockSize)
		if _, err := io.ReadFull(src, iv); err != nil {
			return fmt.Errorf("ошибка чтения IV: %w", err)
		}
	} else {
		iv = ivIn
	}

	cipher, err := rijndael.NewRijndaelCipher(blockSize, len(key), 0x1B)
	if err != nil {
		return fmt.Errorf("ошибка создания шифра: %w", err)
	}

	ctx, err := context.NewCipherContext(cipher, key, cm, pm, iv)
	if err != nil {
		return fmt.Errorf("ошибка создания контекста: %w", err)
	}

	ciphertext, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("ошибка чтения шифротекста: %w", err)
	}

	plaintext, err := ctx.Decrypt(ciphertext)
	if err != nil {
		return fmt.Errorf("ошибка дешифрования: %w", err)
	}

	if err := os.WriteFile(outputFile, plaintext, 0644); err != nil {
		return fmt.Errorf("ошибка записи дешифрованного файла: %w", err)
	}

	return nil
}

func getTestFiles() []string {
	files := []string{
		"testdata/test.txt",
		"testdata/rfc3447.txt",
		"testdata/pic.png",
		"testdata/sample-clouds-400x300.jpg",
	}
	var existing []string
	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			existing = append(existing, file)
		}
	}
	return existing
}

func cleanupRijndaelFiles() {
	patterns := []string{
		"testdata/encrypted_Rijndael_*.enc",
		"testdata/decrypted_Rijndael_*",
	}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, file := range matches {
			os.Remove(file)
		}
	}
}
