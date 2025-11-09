package gfield

import "errors"

var ErrNotIrreducible = errors.New("polynomial is not irreducible")

func Add(a, b byte) byte {
	return a ^ b
}

func MultiplyByMod(a, b, mod byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			result ^= a
		}
		a = multiplyByXByMod(a, mod)
		b >>= 1
	}
	return result
}

func multiplyByXByMod(a, mod byte) byte {
	if a&0x80 == 0x80 {
		return (a << 1) ^ mod
	}
	return a << 1
}

func Inverse(poly, mod byte) byte {
	return binaryPower(poly, 254, mod)
}

func binaryPower(poly byte, power int, mod byte) byte {
	res := byte(1)
	for power != 0 {
		if power&1 == 1 {
			res = MultiplyByMod(res, poly, mod)
		}
		poly = MultiplyByMod(poly, poly, mod)
		power >>= 1
	}
	return res
}

func MultiplyByModSafe(a, b, mod byte) (byte, error) {
	fullPoly := 0x100 | int(mod)
	if !IsIrreducible(fullPoly, 8) {
		return 0, ErrNotIrreducible
	}
	return MultiplyByMod(a, b, mod), nil
}

func InverseSafe(poly, mod byte) (byte, error) {
	fullPoly := 0x100 | int(mod)
	if !IsIrreducible(fullPoly, 8) {
		return 0, ErrNotIrreducible
	}
	return Inverse(poly, mod), nil
}
