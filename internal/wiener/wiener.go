package wiener

import (
	"fmt"
	"math/big"
)

type Convergent struct {
	K *big.Int
	D *big.Int
}

type AttackResult struct {
	D           *big.Int
	PhiN        *big.Int
	Convergents []Convergent
}

type WienerAttacker struct{}

func NewWienerAttacker() *WienerAttacker {
	return &WienerAttacker{}
}

func (wa *WienerAttacker) Attack(e, n *big.Int) (*AttackResult, error) {
	coeffs := expandToContinuedFraction(e, n)
	var allConvergents []Convergent

	pPrev := big.NewInt(1)
	qPrev := big.NewInt(0)

	pCurr := coeffs[0]
	qCurr := big.NewInt(1)

	for i := 0; i < len(coeffs); i++ {
		if i > 0 {

			pNext := new(big.Int).Add(new(big.Int).Mul(coeffs[i], pCurr), pPrev)
			qNext := new(big.Int).Add(new(big.Int).Mul(coeffs[i], qCurr), qPrev)
			pPrev.Set(pCurr)
			qPrev.Set(qCurr)
			pCurr = pNext
			qCurr = qNext
		}

		k := pCurr
		d := qCurr

		allConvergents = append(allConvergents, Convergent{K: k, D: d})

		if k.Sign() == 0 || d.Sign() == 0 {
			continue
		}

		if d.Bit(0) == 0 { 
			continue
		}

		edMinus1 := new(big.Int).Sub(new(big.Int).Mul(e, d), big.NewInt(1))
		if new(big.Int).Rem(edMinus1, k).Cmp(big.NewInt(0)) != 0 {
			continue
		}

		phiN := new(big.Int).Div(edMinus1, k)
		p, q := solveQuadraticEquation(n, phiN)

		if p != nil && q != nil {
			if new(big.Int).Mul(p, q).Cmp(n) == 0 {
				return &AttackResult{
					D:           d,
					PhiN:        phiN,
					Convergents: allConvergents,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("атака Винера не удалась, ключ не найден")
}

func expandToContinuedFraction(a, b *big.Int) []*big.Int {
	var coeffs []*big.Int
	num := new(big.Int).Set(a)
	den := new(big.Int).Set(b)
	rem := new(big.Int)

	for den.Sign() > 0 {
		div, mod := new(big.Int).DivMod(num, den, rem)
		coeffs = append(coeffs, div)
		num.Set(den)
		den.Set(mod)
	}
	return coeffs
}

func solveQuadraticEquation(c, phiN *big.Int) (*big.Int, *big.Int) {
	b := new(big.Int).Sub(c, phiN)
	b.Add(b, big.NewInt(1))

	d := new(big.Int).Sub(new(big.Int).Mul(b, b), new(big.Int).Mul(big.NewInt(4), c))

	if d.Sign() < 0 {
		return nil, nil
	}

	sqrtD := new(big.Int).Sqrt(d)
	if new(big.Int).Mul(sqrtD, sqrtD).Cmp(d) != 0 {
		return nil, nil
	}

	p := new(big.Int).Add(b, sqrtD)
	p.Div(p, big.NewInt(2))

	q := new(big.Int).Sub(b, sqrtD)
	q.Div(q, big.NewInt(2))

	return p, q
}
