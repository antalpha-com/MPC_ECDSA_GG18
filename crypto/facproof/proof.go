// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package facproof

import (
	// "crypto/elliptic"
	"errors"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/elliptic"
	big "github.com/bnb-chain/tss-lib/v2/gmp"
	"github.com/fxamacker/cbor/v2"
)

const (
	ProofFacBytesParts = 11
)

type (
	ProofFac struct {
		P, Q, A, B, T, Sigma, Z1, Z2, W1, W2, V *big.Int
	}
)

var (
	// rangeParameter l limits the bits of p or q to be in [1024-l, 1024+l]
	rangeParameter = new(big.Int).Lsh(big.NewInt(1), 15)
	one            = big.NewInt(1)
)

// NewProof implements prooffac
func NewProof(Session []byte, ec elliptic.Curve, N0, NCap, s, t, N0p, N0q *big.Int) (*ProofFac, error) {
	if ec == nil || N0 == nil || NCap == nil || s == nil || t == nil || N0p == nil || N0q == nil {
		return nil, errors.New("ProveFac constructor received nil value(s)")
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	qNCap := new(big.Int).Mul(q, NCap)
	qN0NCap := new(big.Int).Mul(qNCap, N0)
	q3NCap := new(big.Int).Mul(q3, NCap)
	q3N0NCap := new(big.Int).Mul(q3NCap, N0)
	sqrtN0 := new(big.Int).Sqrt(N0)
	q3SqrtN0 := new(big.Int).Mul(q3, sqrtN0)

	// q3SqrtN0 := new(big.Int).Sqrt(q3N0NCap)
	// Fig 28.1 sample
	alpha := common.GetRandomPositiveInt(q3SqrtN0)
	beta := common.GetRandomPositiveInt(q3SqrtN0)
	mu := common.GetRandomPositiveInt(qNCap)
	nu := common.GetRandomPositiveInt(qNCap)
	sigma := common.GetRandomPositiveInt(qN0NCap)
	r := common.GetRandomPositiveRelativelyPrimeInt(q3N0NCap)
	x := common.GetRandomPositiveInt(q3NCap)
	y := common.GetRandomPositiveInt(q3NCap)

	// Fig 28.1 compute
	modNCap := common.ModInt(NCap)
	P := modNCap.Exp(s, N0p)
	P = modNCap.Mul(P, modNCap.Exp(t, mu))

	Q := modNCap.Exp(s, N0q)
	Q = modNCap.Mul(Q, modNCap.Exp(t, nu))

	A := modNCap.Exp(s, alpha)
	A = modNCap.Mul(A, modNCap.Exp(t, x))

	B := modNCap.Exp(s, beta)
	B = modNCap.Mul(B, modNCap.Exp(t, y))

	T := modNCap.Exp(Q, alpha)
	T = modNCap.Mul(T, modNCap.Exp(t, r))

	// Fig 28.2 e
	var e *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(Session, N0, NCap, s, t, P, Q, A, B, T, sigma)
		e = common.RejectionSample(q, eHash)
	}

	// Fig 28.3
	z1 := new(big.Int).Mul(e, N0p)
	z1 = new(big.Int).Add(z1, alpha)

	z2 := new(big.Int).Mul(e, N0q)
	z2 = new(big.Int).Add(z2, beta)

	w1 := new(big.Int).Mul(e, mu)
	w1 = new(big.Int).Add(w1, x)

	w2 := new(big.Int).Mul(e, nu)
	w2 = new(big.Int).Add(w2, y)

	v := new(big.Int).Mul(nu, N0p)
	v = new(big.Int).Sub(sigma, v)
	v = new(big.Int).Mul(e, v)
	v = new(big.Int).Add(v, r)

	return &ProofFac{P: P, Q: Q, A: A, B: B, T: T, Sigma: sigma, Z1: z1, Z2: z2, W1: w1, W2: w2, V: v}, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofFac, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofFacBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofFac", ProofFacBytesParts)
	}
	return &ProofFac{
		P:     new(big.Int).SetBytes(bzs[0]),
		Q:     new(big.Int).SetBytes(bzs[1]),
		A:     new(big.Int).SetBytes(bzs[2]),
		B:     new(big.Int).SetBytes(bzs[3]),
		T:     new(big.Int).SetBytes(bzs[4]),
		Sigma: new(big.Int).SetBytes(bzs[5]),
		Z1:    new(big.Int).SetBytes(bzs[6]),
		Z2:    new(big.Int).SetBytes(bzs[7]),
		W1:    new(big.Int).SetBytes(bzs[8]),
		W2:    new(big.Int).SetBytes(bzs[9]),
		V:     new(big.Int).SetBytes(bzs[10]),
	}, nil
}

func (pf *ProofFac) Verify(Session []byte, ec elliptic.Curve, N0, NCap, s, t *big.Int) bool {
	fmt.Println("begin Verify facproof")
	if pf == nil || !pf.ValidateBasic() || ec == nil || N0 == nil || NCap == nil || s == nil || t == nil {
		return false
	}
	if N0.Sign() != 1 {
		return false
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	// fmt.Println("N0:", N0.String())
	sqrtN0gmp := new(big.Int).Sqrt(N0)
	// fmt.Println("sqrtN0gmp:", sqrtN0gmp.String())

	q3SqrtN0 := new(big.Int).Mul(q3, sqrtN0gmp)

	// Fig 28. Range Check
	if !common.IsInInterval(pf.Z1, q3SqrtN0) {
		return false
	}

	if !common.IsInInterval(pf.Z2, q3SqrtN0) {
		return false
	}

	var e *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(Session, N0, NCap, s, t, pf.P, pf.Q, pf.A, pf.B, pf.T, pf.Sigma)
		e = common.RejectionSample(q, eHash)
	}

	// Fig 28. Equality Check
	modNCap := common.ModInt(NCap)
	{
		LHS := modNCap.Mul(modNCap.Exp(s, pf.Z1), modNCap.Exp(t, pf.W1))
		RHS := modNCap.Mul(pf.A, modNCap.Exp(pf.P, e))

		if LHS.Cmp(RHS) != 0 {
			return false
		}
	}

	{
		LHS := modNCap.Mul(modNCap.Exp(s, pf.Z2), modNCap.Exp(t, pf.W2))
		RHS := modNCap.Mul(pf.B, modNCap.Exp(pf.Q, e))

		if LHS.Cmp(RHS) != 0 {
			return false
		}
	}

	{
		R := modNCap.Mul(modNCap.Exp(s, N0), modNCap.Exp(t, pf.Sigma))
		LHS := modNCap.Mul(modNCap.Exp(pf.Q, pf.Z1), modNCap.Exp(t, pf.V))
		RHS := modNCap.Mul(pf.T, modNCap.Exp(R, e))

		if LHS.Cmp(RHS) != 0 {
			return false
		}
	}
	fmt.Println(" facproof verify  success")
	return true
}

func (pf *ProofFac) ValidateBasic() bool {
	return pf.P != nil &&
		pf.Q != nil &&
		pf.A != nil &&
		pf.B != nil &&
		pf.T != nil &&
		pf.Sigma != nil &&
		pf.Z1 != nil &&
		pf.Z2 != nil &&
		pf.W1 != nil &&
		pf.W2 != nil &&
		pf.V != nil
}

func (pf *ProofFac) Bytes() [ProofFacBytesParts][]byte {
	return [...][]byte{
		pf.P.Bytes(),
		pf.Q.Bytes(),
		pf.A.Bytes(),
		pf.B.Bytes(),
		pf.T.Bytes(),
		pf.Sigma.Bytes(),
		pf.Z1.Bytes(),
		pf.Z2.Bytes(),
		pf.W1.Bytes(),
		pf.W2.Bytes(),
		pf.V.Bytes(),
	}
}

type (
	ProofFacCode struct {
		P, Q, A, B, T, Sigma, Z1, Z2, W1, W2, V *big.IntGmpCode
	}
)
type Proofbuf struct {
	Malbuf []byte
}

func ProofToCode(p *ProofFac) *ProofFacCode {
	z := new(ProofFacCode)
	z.A = p.A.MarshalGmp()
	z.B = p.B.MarshalGmp()
	z.T = p.T.MarshalGmp()
	z.P = p.P.MarshalGmp()
	z.Q = p.Q.MarshalGmp()
	z.V = p.V.MarshalGmp()
	z.Sigma = p.Sigma.MarshalGmp()
	z.W1 = p.W1.MarshalGmp()
	z.W2 = p.W2.MarshalGmp()
	z.Z1 = p.Z1.MarshalGmp()
	z.Z2 = p.Z2.MarshalGmp()
	return z
}
func CodeToProof(p *ProofFacCode) *ProofFac {
	z := new(ProofFac)
	z.A = new(big.Int).UnmarshalGmp(p.A)
	z.B = new(big.Int).UnmarshalGmp(p.B)
	z.T = new(big.Int).UnmarshalGmp(p.T)
	z.P = new(big.Int).UnmarshalGmp(p.P)
	z.Q = new(big.Int).UnmarshalGmp(p.Q)
	z.V = new(big.Int).UnmarshalGmp(p.V)
	z.Sigma = new(big.Int).UnmarshalGmp(p.Sigma)
	z.W1 = new(big.Int).UnmarshalGmp(p.W1)
	z.W2 = new(big.Int).UnmarshalGmp(p.W2)
	z.Z1 = new(big.Int).UnmarshalGmp(p.Z1)
	z.Z2 = new(big.Int).UnmarshalGmp(p.Z2)
	return z
}
func EmptyCode() *ProofFacCode {
	return &ProofFacCode{}
}
func NewProofMal(Session []byte, ec elliptic.Curve, N0, NCap, s, t, N0p, N0q *big.Int) (*Proofbuf, error) {
	proof, err := NewProof(Session, ec, N0, NCap, s, t, N0p, N0q)
	if err != nil {
		return nil, err
	}
	proofcode := ProofToCode(proof)
	buf, _ := cbor.Marshal(proofcode)
	proofbuf := new(Proofbuf)
	proofbuf.Malbuf = buf
	return proofbuf, nil
}
func (p *Proofbuf) VerifyMal(Session []byte, ec elliptic.Curve, N0, NCap, s, t *big.Int) bool {
	// proofcode := &ProofCode{}
	proofcode := EmptyCode()
	cbor.Unmarshal(p.Malbuf, proofcode)
	proof := CodeToProof(proofcode)
	return proof.Verify(Session, ec, N0, NCap, s, t)
}

func BytesToCode2(bzs [][]byte) *ProofFacCode {
	if len(bzs) != ProofFacBytesParts {
		fmt.Errorf("expected %d byte parts to construct ProofModCode", ProofFacBytesParts)
		return nil
	}
	proofcode := &ProofFacCode{}
	temp := new(big.Int)
	temp.SetBytes(bzs[0])
	proofcode.P = temp.MarshalGmp()
	cbor.Unmarshal(bzs[0], proofcode.P)
	temp.SetBytes(bzs[1])
	proofcode.Q = temp.MarshalGmp()
	cbor.Unmarshal(bzs[1], proofcode.Q)
	temp.SetBytes(bzs[2])
	proofcode.A = temp.MarshalGmp()
	cbor.Unmarshal(bzs[2], proofcode.A)
	temp.SetBytes(bzs[3])
	proofcode.B = temp.MarshalGmp()
	cbor.Unmarshal(bzs[3], proofcode.B)
	temp.SetBytes(bzs[4])
	proofcode.T = temp.MarshalGmp()
	cbor.Unmarshal(bzs[4], proofcode.T)
	temp.SetBytes(bzs[5])
	proofcode.Sigma = temp.MarshalGmp()
	cbor.Unmarshal(bzs[5], proofcode.Sigma)
	temp.SetBytes(bzs[6])
	proofcode.Z1 = temp.MarshalGmp()
	cbor.Unmarshal(bzs[6], proofcode.Z1)
	temp.SetBytes(bzs[7])
	proofcode.Z2 = temp.MarshalGmp()
	cbor.Unmarshal(bzs[7], proofcode.Z2)
	temp.SetBytes(bzs[8])
	proofcode.W1 = temp.MarshalGmp()
	cbor.Unmarshal(bzs[8], proofcode.W1)
	temp.SetBytes(bzs[9])
	proofcode.W2 = temp.MarshalGmp()
	cbor.Unmarshal(bzs[9], proofcode.W2)
	temp.SetBytes(bzs[10])
	proofcode.V = temp.MarshalGmp()
	cbor.Unmarshal(bzs[10], proofcode.V)
	return proofcode
}
func (proofcode *ProofFacCode) CodeToBytes2() [][]byte {
	bzs := make([][]byte, ProofFacBytesParts)
	bzs[0], _ = cbor.Marshal(proofcode.P)
	bzs[1], _ = cbor.Marshal(proofcode.Q)
	bzs[2], _ = cbor.Marshal(proofcode.A)
	bzs[3], _ = cbor.Marshal(proofcode.B)
	bzs[4], _ = cbor.Marshal(proofcode.T)
	bzs[5], _ = cbor.Marshal(proofcode.Sigma)
	bzs[6], _ = cbor.Marshal(proofcode.Z1)
	bzs[7], _ = cbor.Marshal(proofcode.Z2)
	bzs[8], _ = cbor.Marshal(proofcode.W1)
	bzs[9], _ = cbor.Marshal(proofcode.W2)
	bzs[10], _ = cbor.Marshal(proofcode.V)
	return bzs
}
func NewProofFromBytes2(bzs [][]byte) (*ProofFac, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofFacBytesParts) {
		// fmt.Println("expected %d byte parts to construct ProofMod", ProofModBytesParts)
		return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofFacBytesParts)
	}
	// 将byte转化为code
	proofCode := BytesToCode2(bzs)
	// 将code转化为proof
	proof := CodeToProof(proofCode)
	return proof, nil
}
func (pf *ProofFac) Bytes2() [][]byte {
	// proof to code
	proofcode := ProofToCode(pf)
	// code to [][]byte
	// 创建一个新的[][]byte,长度为ProofModBytesParts
	bzs := make([][]byte, ProofFacBytesParts)
	// bzs := [][]byte{}
	// 将proofcode转化为[][]byte
	bzs = proofcode.CodeToBytes2()
	// bzs[0], _ = cbor.Marshal(proofcode.W)
	// for i := range proofcode.X {
	// 	if proofcode.X[i] != nil {
	// 		bzs[1+i], _ = cbor.Marshal(proofcode.X[i])
	// 	}
	// }
	// bzs[Iterations+1], _ = cbor.Marshal(proofcode.A)
	// bzs[Iterations+2], _ = cbor.Marshal(proofcode.B)
	// for i := range proofcode.Z {
	// 	if proofcode.Z[i] != nil {
	// 		bzs[Iterations+3+i], _ = cbor.Marshal(proofcode.Z[i])
	// 	}
	// }
	return bzs
}
