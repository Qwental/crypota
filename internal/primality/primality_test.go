package primality

import (
	"fmt"
	"math/big"
	"testing"
)

var knownPrimes = []int64{
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
	73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
	157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
	239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
	331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
	421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
	509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
	613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
	709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
	821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
	919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
}

//  числа Кармайкла (для проверки слабости теста Ферма)
var carmichaelNumbers = []int64{
	561, 1105, 1729, 2465, 2821, 6601, 8911, 10585, 15841, 29341,
}

var compositeNumbers = []int64{
	4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 22, 24, 25, 26, 27, 28,
	100, 200, 300, 400, 500, 1000, 10000,
}

func TestFermat_KnownPrimes(t *testing.T) {
	fermat := NewFermatTest()

	for _, p := range knownPrimes {
		t.Run(fmt.Sprintf("Prime_%d", p), func(t *testing.T) {
			n := big.NewInt(p)
			if !fermat.IsPrime(n, 0.99) {
				t.Errorf("Fermat test failed for known prime %d", p)
			}
		})
	}
}

func TestFermat_CompositeNumbers(t *testing.T) {
	fermat := NewFermatTest()

	for _, c := range compositeNumbers {
		t.Run(fmt.Sprintf("Composite_%d", c), func(t *testing.T) {
			n := big.NewInt(c)
			if fermat.IsPrime(n, 0.99) {
				t.Errorf("Fermat test incorrectly identified composite %d as prime", c)
			}
		})
	}
}

func TestFermat_CarmichaelNumbers(t *testing.T) {
	fermat := NewFermatTest()


	for _, c := range carmichaelNumbers {
		t.Run(fmt.Sprintf("Carmichael_%d", c), func(t *testing.T) {
			n := big.NewInt(c)
			result := fermat.IsPrime(n, 0.99)
			t.Logf("Carmichael number %d: Fermat test result = %v (expected false positive)", c, result)
		})
	}
}

func TestSolovayStrassen_KnownPrimes(t *testing.T) {
	solovay := NewSolovayStrassenTest()

	for _, p := range knownPrimes {
		t.Run(fmt.Sprintf("Prime_%d", p), func(t *testing.T) {
			n := big.NewInt(p)
			if !solovay.IsPrime(n, 0.99) {
				t.Errorf("Solovay-Strassen test failed for known prime %d", p)
			}
		})
	}
}

func TestSolovayStrassen_CompositeNumbers(t *testing.T) {
	solovay := NewSolovayStrassenTest()

	for _, c := range compositeNumbers {
		t.Run(fmt.Sprintf("Composite_%d", c), func(t *testing.T) {
			n := big.NewInt(c)
			if solovay.IsPrime(n, 0.99) {
				t.Errorf("Solovay-Strassen test incorrectly identified composite %d as prime", c)
			}
		})
	}
}

func TestSolovayStrassen_CarmichaelNumbers(t *testing.T) {
	solovay := NewSolovayStrassenTest()

	for _, c := range carmichaelNumbers {
		t.Run(fmt.Sprintf("Carmichael_%d", c), func(t *testing.T) {
			n := big.NewInt(c)
			if solovay.IsPrime(n, 0.99) {
				t.Errorf("Solovay-Strassen test incorrectly identified Carmichael number %d as prime", c)
			}
		})
	}
}

func TestMillerRabin_KnownPrimes(t *testing.T) {
	miller := NewMillerRabinTest()

	for _, p := range knownPrimes {
		t.Run(fmt.Sprintf("Prime_%d", p), func(t *testing.T) {
			n := big.NewInt(p)
			if !miller.IsPrime(n, 0.99) {
				t.Errorf("Miller-Rabin test failed for known prime %d", p)
			}
		})
	}
}

func TestMillerRabin_CompositeNumbers(t *testing.T) {
	miller := NewMillerRabinTest()

	for _, c := range compositeNumbers {
		t.Run(fmt.Sprintf("Composite_%d", c), func(t *testing.T) {
			n := big.NewInt(c)
			if miller.IsPrime(n, 0.99) {
				t.Errorf("Miller-Rabin test incorrectly identified composite %d as prime", c)
			}
		})
	}
}

func TestMillerRabin_CarmichaelNumbers(t *testing.T) {
	miller := NewMillerRabinTest()

	for _, c := range carmichaelNumbers {
		t.Run(fmt.Sprintf("Carmichael_%d", c), func(t *testing.T) {
			n := big.NewInt(c)
			if miller.IsPrime(n, 0.99) {
				t.Errorf("Miller-Rabin test incorrectly identified Carmichael number %d as prime", c)
			}
		})
	}
}

func TestPrimalityTests_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		n      *big.Int
		expect bool
	}{
		{"Zero", big.NewInt(0), false},
		{"One", big.NewInt(1), false},
		{"Two", big.NewInt(2), true},
		{"Three", big.NewInt(3), true},
		{"Four", big.NewInt(4), false},
		{"Negative", big.NewInt(-5), false},
	}

	fermat := NewFermatTest()
	solovay := NewSolovayStrassenTest()
	miller := NewMillerRabinTest()

	for _, tt := range tests {
		t.Run("Fermat_"+tt.name, func(t *testing.T) {
			result := fermat.IsPrime(tt.n, 0.99)
			if result != tt.expect {
				t.Errorf("Fermat: %s = %v, expected %v", tt.name, result, tt.expect)
			}
		})

		t.Run("Solovay_"+tt.name, func(t *testing.T) {
			result := solovay.IsPrime(tt.n, 0.99)
			if result != tt.expect {
				t.Errorf("Solovay: %s = %v, expected %v", tt.name, result, tt.expect)
			}
		})

		t.Run("Miller_"+tt.name, func(t *testing.T) {
			result := miller.IsPrime(tt.n, 0.99)
			if result != tt.expect {
				t.Errorf("Miller: %s = %v, expected %v", tt.name, result, tt.expect)
			}
		})
	}
}
