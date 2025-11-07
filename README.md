## Пайплайн с запуском тестов
[![Tests](https://github.com/Qwental/crypota/workflows/Tests/badge.svg)](https://github.com/Qwental/crypota/actions)

## Бугренков Владимир М8О-311Б-23

## ЛР1
### task 1.1
- `internal/bitops/permutation.go` - функция перестановки битов с поддержкой различных правил индексирования

### task 1.2
- `internal/interfaces/cipher.go` - интерфейс BlockCipher для симметричного шифрования
- `internal/context/context.go` - контекст выполнения криптографических операций
- `internal/padding/padding.go` - режимы набивки (Zeros, ANSI X.923, PKCS7, ISO 10126)
- `internal/modes/modes.go` - режимы шифрования (ECB, CBC, PCBC, CFB, OFB, CTR, Random Delta)

### task 1.3
- `internal/feistel/feistel.go` - реализация сети Фейстеля

### task 1.4
- `internal/des/des.go` - основная реализация DES
- `internal/des/keygen.go` - генерация раундовых ключей
- `internal/des/round.go` - раундовая функция
- `internal/des/tables.go` - таблицы перестановок и S-блоки
- `internal/des/des_test.go` - тесты DES

### task 1.5 и 1.7
- `cmd/crypota/demonstration_DES_DEAL.go` - демонстрация шифрования файлов DES + в тестах есть демонстрация работы

### task 1.6
- `internal/deal/deal.go` - реализация DEAL (128/192/256 бит)
- `internal/deal/adapter.go` - адаптер DES для использования в DEAL
- `internal/deal/deal_test.go` - тесты DEAL

## ЛР2
### task 2.1
- `internal/math/*.go` - функции для вычисления символа Лежандра, Якоби, GCD, fastpow по модулю 
### task 2.2
- `internal/primality/*.go` - тесты простоты
### task 2.3
- `internal/rsa/*.go` - rsa
### task 2.4
- `internal/wiener/*.go` - атака Винера с использованием rsabad




