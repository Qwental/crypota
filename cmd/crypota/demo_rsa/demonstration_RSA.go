package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/Qwental/crypota/internal/rsa"
)

func main() {
	demonstrateRSAFiles()
}

func demonstrateRSAFiles() {
	fmt.Println("--- Демонстрация RSA с файлами ---")
	rsaService, err := rsa.NewRSAService(rsa.MillerRabin, 2048, 0.999)
	if err != nil {
		log.Fatalf("Ошибка создания RSA сервиса: %v", err)
	}
	fmt.Println("Генерация 2048-битных ключей для файлов...")
	if err := rsaService.GenerateNewKeys(); err != nil {
		log.Fatalf("Ошибка генерации ключей: %v", err)
	}
	fmt.Println("[OK] Ключи успешно сгенерированы.")
	cleanupRSAFiles()
	testFiles := getTestFiles()
	if len(testFiles) == 0 {
		log.Println("Тестовые файлы не найдены в testdata/")
		return
	}
	for _, file := range testFiles {
		testFileEncryptionRSA(rsaService, file)
	}
}

func testFileEncryptionRSA(rsaService *rsa.RSAService, inputFile string) {
	fmt.Printf("\nОбработка файла: %s\n", inputFile)
	basename := filepath.Base(inputFile)
	ext := filepath.Ext(basename)
	nameOnly := basename[:len(basename)-len(ext)]
	encFile := fmt.Sprintf("testdata/encrypted_RSA_%s.enc", nameOnly)
	decFile := fmt.Sprintf("testdata/decrypted_RSA_%s%s", nameOnly, ext)

	if err := encryptFileRSA(rsaService, inputFile, encFile); err != nil {
		fmt.Printf("  [FAIL] Ошибка шифрования файла: %v\n", err)
		return
	}
	fmt.Printf("  [OK] Файл зашифрован в %s\n", encFile)

	if err := decryptFileRSA(rsaService, encFile, decFile); err != nil {
		fmt.Printf("  [FAIL] Ошибка дешифрования файла: %v\n", err)
		return
	}
	fmt.Printf("  [OK] Файл дешифрован в %s\n", decFile)

	originalData, _ := os.ReadFile(inputFile)
	decryptedData, _ := os.ReadFile(decFile)
	if bytes.Equal(originalData, decryptedData) {
		fmt.Println("  [OK] Контрольные суммы совпадают.")
	} else {
		fmt.Printf("  [FAIL] Контрольные суммы не совпадают! Original: %d bytes, Decrypted: %d bytes\n", len(originalData), len(decryptedData))
	}
}

func encryptFileRSA(s *rsa.RSAService, inputFile, outputFile string) error {
	pubKey, err := s.GetPublicKey()
	if err != nil {
		return err
	}
	keySize := (pubKey.N.BitLen() + 7) / 8
	blockSize := keySize - 1

	src, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer dst.Close()

	buf := make([]byte, blockSize)
	for {
		n, err := src.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		m := new(big.Int).SetBytes(buf[:n])
		c, err := s.Encrypt(m)
		if err != nil {
			return err
		}

		encryptedBytes := c.Bytes()
		// Записываем и длину исходного блока, и длину зашифрованного
		binary.Write(dst, binary.BigEndian, uint32(n))
		binary.Write(dst, binary.BigEndian, uint32(len(encryptedBytes)))
		dst.Write(encryptedBytes)
	}
	return nil
}

func decryptFileRSA(s *rsa.RSAService, inputFile, outputFile string) error {
	src, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer dst.Close()

	for {
		var originalBlockSize, encryptedBlockSize uint32

		if err := binary.Read(src, binary.BigEndian, &originalBlockSize); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if err := binary.Read(src, binary.BigEndian, &encryptedBlockSize); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		buf := make([]byte, encryptedBlockSize)
		if _, err := io.ReadFull(src, buf); err != nil {
			return err
		}

		c := new(big.Int).SetBytes(buf)
		m, err := s.Decrypt(c)
		if err != nil {
			return err
		}

		decryptedBytes := m.Bytes()

		// Вот ключевое исправление!
		// Дополняем нулями слева до нужной длины.
		paddedBytes := make([]byte, originalBlockSize)
		copy(paddedBytes[int(originalBlockSize)-len(decryptedBytes):], decryptedBytes)

		if _, err := dst.Write(paddedBytes); err != nil {
			return err
		}
	}
	return nil
}

func getTestFiles() []string {
	files := []string{
		"testdata/test.txt",
		"testdata/rfc3447.txt",
		"testdata/pic.png",
		"testdata/test.png",
		"testdata/sample-5s.mp4",
		"testdata/sample-6s.mp3",
		"testdata/sample-animated-400x300.gif",
		"testdata/sample-bumblebee-400x300.png",
		"testdata/sample-clouds-400x300.jpg",
		"testdata/sample-spring-park-400x300.svg",
	}
	var existing []string
	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			existing = append(existing, file)
		}
	}
	return existing
}

func cleanupRSAFiles() {
	patterns := []string{
		"testdata/encrypted_RSA_*.enc",
		"testdata/decrypted_RSA_*",
	}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, file := range matches {
			os.Remove(file)
		}
	}
}
