package context

import (
	"fmt"
	"os"

	"github.com/Qwental/crypota/internal/interfaces"
	"github.com/Qwental/crypota/internal/modes"
	"github.com/Qwental/crypota/internal/padding"
)


type CipherResult struct {
	Data []byte
	Err  error
}

// контекст выполнения симметричного алгоритма
type CipherContext struct {
	cipher      interfaces.BlockCipher
	mode        modes.Mode
	paddingMode padding.PaddingMode
}

func NewCipherContext(
	cipher interfaces.BlockCipher,
	key []byte,
	cipherMode modes.CipherMode,
	paddingMode padding.PaddingMode,
	iv []byte,
	params ...interface{},
) (*CipherContext, error) {

	if err := cipher.SetKey(key); err != nil {
		return nil, fmt.Errorf("failed to set key: %w", err)
	}

	var mode modes.Mode
	switch cipherMode {
	case modes.ECB:
		mode = &modes.ECBMode{}
	case modes.CBC:
		if iv == nil {
			return nil, fmt.Errorf("CBC mode requires IV")
		}
		mode = modes.NewCBCMode(iv)
	case modes.PCBC:
		if iv == nil {
			return nil, fmt.Errorf("PCBC mode requires IV")
		}
		mode = modes.NewPCBCMode(iv)
	case modes.CFB:
		if iv == nil {
			return nil, fmt.Errorf("CFB mode requires IV")
		}
		mode = modes.NewCFBMode(iv)
	case modes.OFB:
		if iv == nil {
			return nil, fmt.Errorf("OFB mode requires IV")
		}
		mode = modes.NewOFBMode(iv)
	case modes.CTR:
		if iv == nil {
			return nil, fmt.Errorf("CTR mode requires IV")
		}
		mode = modes.NewCTRMode(iv)
	case modes.RandomDelta:
		if iv == nil {
			return nil, fmt.Errorf("RandomDelta mode requires IV")
		}
		mode = modes.NewRandomDeltaMode(iv)
	default:
		return nil, fmt.Errorf("unsupported cipher mode: %d", cipherMode)
	}

	return &CipherContext{
		cipher:      cipher,
		mode:        mode,
		paddingMode: paddingMode,
	}, nil
}

//  шифрует данные
func (ctx *CipherContext) Encrypt(plaintext []byte) ([]byte, error) {
	// Добавляем padding
	padded, err := padding.Pad(plaintext, ctx.cipher.BlockSize(), ctx.paddingMode)
	if err != nil {
		return nil, fmt.Errorf("padding failed: %w", err)
	}

	// Шифруем
	ciphertext, err := ctx.mode.Encrypt(ctx.cipher, padded)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	return ciphertext, nil
}

//  дешифрует данные
func (ctx *CipherContext) Decrypt(ciphertext []byte) ([]byte, error) {
	padded, err := ctx.mode.Decrypt(ctx.cipher, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	plaintext, err := padding.Unpad(padded, ctx.paddingMode)
	if err != nil {
		return nil, fmt.Errorf("unpadding failed: %w", err)
	}

	return plaintext, nil
}

// шифрует данные асинхронно
func (ctx *CipherContext) EncryptAsync(plaintext []byte) <-chan CipherResult {
	resultChan := make(chan CipherResult, 1)
	go func() {
		defer close(resultChan)
		data, err := ctx.Encrypt(plaintext)
		resultChan <- CipherResult{Data: data, Err: err}
	}()
	return resultChan
}

// дешифрует данные асинхронно
func (ctx *CipherContext) DecryptAsync(ciphertext []byte) <-chan CipherResult {
	resultChan := make(chan CipherResult, 1)
	go func() {
		defer close(resultChan)
		data, err := ctx.Decrypt(ciphertext)
		resultChan <- CipherResult{Data: data, Err: err}
	}()
	return resultChan
}

// шифрует файл 
func (ctx *CipherContext) EncryptFile(inputPath, outputPath string) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	ciphertext, err := ctx.Encrypt(plaintext)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, ciphertext, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

//  дешифрует файл
func (ctx *CipherContext) DecryptFile(inputPath, outputPath string) error {

	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	plaintext, err := ctx.Decrypt(ciphertext)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, plaintext, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

//  шифрует файл асинхронно
func (ctx *CipherContext) EncryptFileAsync(inputPath, outputPath string) <-chan error {
	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		errChan <- ctx.EncryptFile(inputPath, outputPath)
	}()
	return errChan
}

// дешифрует файл асинхронно
func (ctx *CipherContext) DecryptFileAsync(inputPath, outputPath string) <-chan error {
	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		errChan <- ctx.DecryptFile(inputPath, outputPath)
	}()
	return errChan
}
