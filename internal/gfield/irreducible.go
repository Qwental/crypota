package gfield

import "sync"

var IrreducibleEightDegree = sync.OnceValue(func() []byte {
	lst := calculateAllIrreducible(8)
	result := make([]byte, len(lst))
	for i := 0; i < len(lst); i++ {
		result[i] = byte(lst[i] & 0xFF)
	}
	return result
})

func IsIrreducible(poly, degree int) bool {
	if degree < 1 {
		return false
	}

	maxCheckValue := 1 << ((degree / 2) + 1)

	for i := 2; i < maxCheckValue; i++ {
		mod := ModuloPolynomials(poly, i)
		if mod == 0 {
			return false
		}
	}
	return true
}

func calculateAllIrreducible(degree int) []int {
	if degree < 1 {
		panic("degree cannot be less than one")
	}

	result := []int{}
	val := 1 << degree
	maxValue := 1 << (degree + 1)

	for val < maxValue {
		if IsIrreducible(val, degree) {
			result = append(result, val)
		}
		val++
	}

	return result
}

func GetAllIrreducible8() []byte {
	return IrreducibleEightDegree()
}
