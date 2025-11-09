package gfield

func getDegree(poly int) int {
	if poly == 0 {
		return -1
	}
	degree := 0
	temp := poly
	for temp > 1 {
		temp >>= 1
		degree++
	}
	return degree
}

func ModuloPolynomials(a, b int) int {
	if a == 0 {
		return 0
	}

	dividendDegree := getDegree(a)
	divisorDegree := getDegree(b)

	for dividendDegree >= divisorDegree {
		shift := dividendDegree - divisorDegree
		alignedDivisor := b << shift
		a ^= alignedDivisor
		dividendDegree = getDegree(a)
	}

	return a
}

func DividePolynomials(a, b int) int {
	if b == 0 {
		panic("division by zero polynomial")
	}
	if a == 0 {
		return 0
	}

	dividendDegree := getDegree(a)
	divisorDegree := getDegree(b)
	res := 0

	for dividendDegree >= divisorDegree {
		shift := dividendDegree - divisorDegree
		res |= 1 << shift
		alignedDivisor := b << shift
		a ^= alignedDivisor
		dividendDegree = getDegree(a)
	}

	return res
}

func Factorize(poly int) []int {
	result := []int{}
	degree := getDegree(poly)
	if degree <= 0 {
		return result
	}

	minDegree := min(degree, 7)

	var irreduciblePolynomials []int
	for i := 1; i <= minDegree; i++ {
		irreduciblePolynomials = append(irreduciblePolynomials, calculateAllIrreducible(i)...)
	}

	for _, irr := range irreduciblePolynomials {
		for ModuloPolynomials(poly, irr) == 0 {
			poly = DividePolynomials(poly, irr)
			result = append(result, irr)
		}
	}

	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
