// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"errors"
	"fmt"
	// "crypto/elliptic"
	"github.com/bnb-chain/tss-lib/v2/crypto/elliptic"
	"github.com/fxamacker/cbor/v2"

	// "math/big"
	big "github.com/bnb-chain/tss-lib/v2/gmp"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	ProofBobBytesParts   = 10
	ProofBobWCBytesParts = 12
)

type (
	ProofBob struct {
		Z, ZPrm, T, V, W, S, S1, S2, T1, T2 *big.Int
	}

	ProofBobWC struct {
		*ProofBob
		U *crypto.ECPoint
	}
)

// ProveBobWC implements Bob's proof both with or without check "ProveMtawc_Bob" and "ProveMta_Bob" used in the MtA protocol from GG18Spec (9) Figs. 10 & 11.
// an absent `X` generates the proof without the X consistency check X = g^x
func ProveBobWC(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int, X *crypto.ECPoint) (*ProofBobWC, error) {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c1 == nil || c2 == nil || x == nil || y == nil || r == nil {
		return nil, errors.New("ProveBob() received a nil argument")
	}

	NSquared := pk.NSquare()

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	q7 := new(big.Int).Mul(q3, q3)
	q7 = new(big.Int).Mul(q7, q)
	qNTilde := new(big.Int).Mul(q, NTilde)
	q3NTilde := new(big.Int).Mul(q3, NTilde)

	// steps are numbered as shown in Fig. 10, but diverge slightly for Fig. 11
	// 1.
	alpha := common.GetRandomPositiveInt(q3)

	// 2.
	rho := common.GetRandomPositiveInt(qNTilde)
	sigma := common.GetRandomPositiveInt(qNTilde)
	tau := common.GetRandomPositiveInt(q3NTilde)

	// 3.
	rhoPrm := common.GetRandomPositiveInt(q3NTilde)

	// 4.
	beta := common.GetRandomPositiveRelativelyPrimeInt(pk.N)

	gamma := common.GetRandomPositiveInt(q7)

	// 5.
	u := crypto.NewECPointNoCurveCheck(ec, zero, zero) // initialization suppresses an IDE warning
	if X != nil {
		u = crypto.ScalarBaseMult(ec, alpha)
	}

	// 6.
	modNTilde := common.ModInt(NTilde)
	z := modNTilde.Exp(h1, x)
	z = modNTilde.Mul(z, modNTilde.Exp(h2, rho))

	// 7.
	zPrm := modNTilde.Exp(h1, alpha)
	zPrm = modNTilde.Mul(zPrm, modNTilde.Exp(h2, rhoPrm))

	// 8.
	t := modNTilde.Exp(h1, y)
	t = modNTilde.Mul(t, modNTilde.Exp(h2, sigma))

	// 9.
	modNSquared := common.ModInt(NSquared)
	v := modNSquared.Exp(c1, alpha)
	v = modNSquared.Mul(v, modNSquared.Exp(pk.Gamma(), gamma))
	v = modNSquared.Mul(v, modNSquared.Exp(beta, pk.N))

	// 10.
	w := modNTilde.Exp(h1, gamma)
	w = modNTilde.Mul(w, modNTilde.Exp(h2, tau))

	// 11-12. e'
	var e *big.Int
	{ // must use RejectionSample
		var eHash *big.Int
		// X is nil if called by ProveBob (Bob's proof "without check")
		if X == nil {
			eHash = common.SHA512_256i_TAGGED(Session, append(pk.AsInts(), c1, c2, z, zPrm, t, v, w)...)
		} else {
			eHash = common.SHA512_256i_TAGGED(Session, append(pk.AsInts(), X.X(), X.Y(), c1, c2, u.X(), u.Y(), z, zPrm, t, v, w)...)
		}
		e = common.RejectionSample(q, eHash)
	}

	// 13.
	modN := common.ModInt(pk.N)
	s := modN.Exp(r, e)
	s = modN.Mul(s, beta)

	// 14.
	s1 := new(big.Int).Mul(e, x)
	s1 = s1.Add(s1, alpha)

	// 15.
	s2 := new(big.Int).Mul(e, rho)
	s2 = s2.Add(s2, rhoPrm)

	// 16.
	t1 := new(big.Int).Mul(e, y)
	t1 = t1.Add(t1, gamma)

	// 17.
	t2 := new(big.Int).Mul(e, sigma)
	t2 = t2.Add(t2, tau)

	// the regular Bob proof ("without check") is extracted and returned by ProveBob
	pf := &ProofBob{Z: z, ZPrm: zPrm, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}

	// or the WC ("with check") version is used in round 2 of the signing protocol
	return &ProofBobWC{ProofBob: pf, U: u}, nil
}

// ProveBob implements Bob's proof "ProveMta_Bob" used in the MtA protocol from GG18Spec (9) Fig. 11.
func ProveBob(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int) (*ProofBob, error) {
	// the Bob proof ("with check") contains the ProofBob "without check"; this method extracts and returns it
	// X is supplied as nil to exclude it from the proof hash
	pf, err := ProveBobWC(Session, ec, pk, NTilde, h1, h2, c1, c2, x, y, r, nil)
	if err != nil {
		return nil, err
	}
	return pf.ProofBob, nil
}

func ProofBobWCFromBytes(ec elliptic.Curve, bzs [][]byte) (*ProofBobWC, error) {
	proofBob, err := ProofBobFromBytes(bzs)
	if err != nil {
		return nil, err
	}
	point, err := crypto.NewECPoint(ec,
		new(big.Int).SetBytes(bzs[10]),
		new(big.Int).SetBytes(bzs[11]))
	if err != nil {
		return nil, err
	}
	return &ProofBobWC{
		ProofBob: proofBob,
		U:        point,
	}, nil
}

func ProofBobFromBytes(bzs [][]byte) (*ProofBob, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofBobBytesParts) &&
		!common.NonEmptyMultiBytes(bzs, ProofBobWCBytesParts) {
		return nil, fmt.Errorf(
			"expected %d byte parts to construct ProofBob, or %d for ProofBobWC",
			ProofBobBytesParts, ProofBobWCBytesParts)
	}
	return &ProofBob{
		Z:    new(big.Int).SetBytes(bzs[0]),
		ZPrm: new(big.Int).SetBytes(bzs[1]),
		T:    new(big.Int).SetBytes(bzs[2]),
		V:    new(big.Int).SetBytes(bzs[3]),
		W:    new(big.Int).SetBytes(bzs[4]),
		S:    new(big.Int).SetBytes(bzs[5]),
		S1:   new(big.Int).SetBytes(bzs[6]),
		S2:   new(big.Int).SetBytes(bzs[7]),
		T1:   new(big.Int).SetBytes(bzs[8]),
		T2:   new(big.Int).SetBytes(bzs[9]),
	}, nil
}

// ProveBobWC.Verify implements verification of Bob's proof with check "VerifyMtawc_Bob" used in the MtA protocol from GG18Spec (9) Fig. 10.
// an absent `X` verifies a proof generated without the X consistency check X = g^x
func (pf *ProofBobWC) Verify(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2 *big.Int, X *crypto.ECPoint) bool {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c1 == nil || c2 == nil {
		return false
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)   // q^2
	q3 = new(big.Int).Mul(q, q3)   // q^3
	q7 := new(big.Int).Mul(q3, q3) // q^6
	q7 = new(big.Int).Mul(q7, q)   // q^7

	if !common.IsInInterval(pf.Z, NTilde) {
		return false
	}
	if !common.IsInInterval(pf.ZPrm, NTilde) {
		return false
	}
	if !common.IsInInterval(pf.T, NTilde) {
		return false
	}
	if !common.IsInInterval(pf.V, pk.NSquare()) {
		return false
	}
	if !common.IsInInterval(pf.W, NTilde) {
		return false
	}
	if !common.IsInInterval(pf.S, pk.N) {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.Z, NTilde).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.ZPrm, NTilde).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.T, NTilde).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.V, pk.NSquare()).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.W, NTilde).Cmp(one) != 0 {
		return false
	}

	gcd := big.NewInt(0)
	if pf.S.Cmp(zero) == 0 {
		return false
	}
	if gcd.GCD(nil, nil, pf.S, pk.N).Cmp(one) != 0 {
		return false
	}
	if pf.V.Cmp(zero) == 0 {
		return false
	}
	if gcd.GCD(nil, nil, pf.V, pk.N).Cmp(one) != 0 {
		return false
	}
	if pf.S1.Cmp(q) == -1 {
		return false
	}
	if pf.S2.Cmp(q) == -1 {
		return false
	}
	if pf.T1.Cmp(q) == -1 {
		return false
	}
	if pf.T2.Cmp(q) == -1 {
		return false
	}

	// 3.
	if pf.S1.Cmp(q3) > 0 {
		return false
	}
	if pf.T1.Cmp(q7) > 0 {
		return false
	}

	// 1-2. e'
	var e *big.Int
	{ // must use RejectionSample
		var eHash *big.Int
		// X is nil if called on a ProveBob (Bob's proof "without check")
		if X == nil {
			eHash = common.SHA512_256i_TAGGED(Session, append(pk.AsInts(), c1, c2, pf.Z, pf.ZPrm, pf.T, pf.V, pf.W)...)
		} else {
			if !tss.SameCurve(ec, X.Curve()) {
				return false
			}
			eHash = common.SHA512_256i_TAGGED(Session, append(pk.AsInts(), X.X(), X.Y(), c1, c2, pf.U.X(), pf.U.Y(), pf.Z, pf.ZPrm, pf.T, pf.V, pf.W)...)
		}
		e = common.RejectionSample(q, eHash)
	}

	var left, right *big.Int // for the following conditionals

	// 4. runs only in the "with check" mode from Fig. 10
	if X != nil {
		s1ModQ := new(big.Int).Mod(pf.S1, ec.Params().N)
		gS1 := crypto.ScalarBaseMult(ec, s1ModQ)
		xEU, err := X.ScalarMult(e).Add(pf.U)
		// TODO:!gS1.Equals(xEU)
		if err != nil || !gS1.Equals(xEU) {
			// 打印gS1和xEU的值
			// fmt.Printf("gS1:%s\n", gS1)
			// fmt.Printf("xEU:%s\n", xEU)
			fmt.Printf("verify ProofBob failed %v\n", X)
			return false
		}
	}

	{ // 5-6.
		modNTilde := common.ModInt(NTilde)

		{ // 5.
			h1ExpS1 := modNTilde.Exp(h1, pf.S1)
			h2ExpS2 := modNTilde.Exp(h2, pf.S2)
			left = modNTilde.Mul(h1ExpS1, h2ExpS2)
			zExpE := modNTilde.Exp(pf.Z, e)
			right = modNTilde.Mul(zExpE, pf.ZPrm)
			if left.Cmp(right) != 0 {
				return false
			}
		}

		{ // 6.
			h1ExpT1 := modNTilde.Exp(h1, pf.T1)
			h2ExpT2 := modNTilde.Exp(h2, pf.T2)
			left = modNTilde.Mul(h1ExpT1, h2ExpT2)
			tExpE := modNTilde.Exp(pf.T, e)
			right = modNTilde.Mul(tExpE, pf.W)
			if left.Cmp(right) != 0 {
				return false
			}
		}
	}

	{ // 7.
		modNSquared := common.ModInt(pk.NSquare())

		c1ExpS1 := modNSquared.Exp(c1, pf.S1)
		sExpN := modNSquared.Exp(pf.S, pk.N)
		gammaExpT1 := modNSquared.Exp(pk.Gamma(), pf.T1)
		left = modNSquared.Mul(c1ExpS1, sExpN)
		left = modNSquared.Mul(left, gammaExpT1)
		c2ExpE := modNSquared.Exp(c2, e)
		right = modNSquared.Mul(c2ExpE, pf.V)
		if left.Cmp(right) != 0 {
			return false
		}
	}
	fmt.Printf("verify ProofBob success %v\n", X)
	return true
}

// ProveBob.Verify implements verification of Bob's proof without check "VerifyMta_Bob" used in the MtA protocol from GG18Spec (9) Fig. 11.
func (pf *ProofBob) Verify(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2 *big.Int) bool {
	if pf == nil {
		return false
	}
	pfWC := &ProofBobWC{ProofBob: pf, U: nil}
	return pfWC.Verify(Session, ec, pk, NTilde, h1, h2, c1, c2, nil)
}

func (pf *ProofBob) ValidateBasic() bool {
	return pf.Z != nil &&
		pf.ZPrm != nil &&
		pf.T != nil &&
		pf.V != nil &&
		pf.W != nil &&
		pf.S != nil &&
		pf.S1 != nil &&
		pf.S2 != nil &&
		pf.T1 != nil &&
		pf.T2 != nil
}

func (pf *ProofBobWC) ValidateBasic() bool {
	return pf.ProofBob.ValidateBasic() && pf.U != nil
}

func (pf *ProofBob) Bytes() [ProofBobBytesParts][]byte {
	return [...][]byte{
		pf.Z.Bytes(),
		pf.ZPrm.Bytes(),
		pf.T.Bytes(),
		pf.V.Bytes(),
		pf.W.Bytes(),
		pf.S.Bytes(),
		pf.S1.Bytes(),
		pf.S2.Bytes(),
		pf.T1.Bytes(),
		pf.T2.Bytes(),
	}
}

func (pf *ProofBobWC) Bytes() [ProofBobWCBytesParts][]byte {
	var out [ProofBobWCBytesParts][]byte
	bobBzs := pf.ProofBob.Bytes()
	bobBzsSlice := bobBzs[:]
	bobBzsSlice = append(bobBzsSlice, pf.U.X().Bytes())
	bobBzsSlice = append(bobBzsSlice, pf.U.Y().Bytes())
	copy(out[:], bobBzsSlice[:12])
	return out
}
func (pf *ProofBobWC) BytesFromProofBobWC() [ProofBobWCBytesParts][]byte {
	// Proof to code
	proofcode := ProofBobWCToCode(pf)
	bzs := [ProofBobWCBytesParts][]byte{}
	// code to bytes
	bzs = proofcode.BobWCCodeToBytes()
	return bzs

}

type ProofbufBob struct {
	MalbufBob []byte
}
type ProofbufBobWC struct {
	MalbufBobWC []byte
}
type ProofBobCode struct {
	Z, ZPrm, T, V, W, S, S1, S2, T1, T2 *big.IntGmpCode
}

// todo:第2个参数crypto.ECPoint的设置是否有问题？
type ProofBobWCCode struct {
	*ProofBobCode
	ECPointCode
}

type ECPointCode struct {
	curve elliptic.Curve
	X, Y  *big.IntGmpCode
}

func ProofBobToCode(p *ProofBob) *ProofBobCode {
	z := new(ProofBobCode)
	z.S = p.S.MarshalGmp()
	z.S1 = p.S1.MarshalGmp()
	z.S2 = p.S2.MarshalGmp()
	z.T = p.T.MarshalGmp()
	z.T1 = p.T1.MarshalGmp()
	z.T2 = p.T2.MarshalGmp()
	z.V = p.V.MarshalGmp()
	z.W = p.W.MarshalGmp()
	z.Z = p.Z.MarshalGmp()
	z.ZPrm = p.ZPrm.MarshalGmp()
	return z
}
func CodeToProofBob(p *ProofBobCode) *ProofBob {
	z := new(ProofBob)
	z.Z = new(big.Int).UnmarshalGmp(p.Z)
	z.ZPrm = new(big.Int).UnmarshalGmp(p.ZPrm)
	z.T = new(big.Int).UnmarshalGmp(p.T)
	z.V = new(big.Int).UnmarshalGmp(p.V)
	z.W = new(big.Int).UnmarshalGmp(p.W)
	z.S = new(big.Int).UnmarshalGmp(p.S)
	z.S1 = new(big.Int).UnmarshalGmp(p.S1)
	z.S2 = new(big.Int).UnmarshalGmp(p.S2)
	z.T1 = new(big.Int).UnmarshalGmp(p.T1)
	z.T2 = new(big.Int).UnmarshalGmp(p.T2)
	return z
}
func CodeToProofBobWC(ec elliptic.Curve, p *ProofBobWCCode) *ProofBobWC {
	// z := new(ProofBobWC)
	// z.ProofBob = CodeToProofBob(p.ProofBobCode)
	// x := new(big.Int).UnmarshalGmp(p.X)
	// z.U.X().Set(x)
	//  y := new(big.Int).UnmarshalGmp(p.Y)
	// z.U.Y().Set(y)
	// return z
	proofBob := CodeToProofBob(p.ProofBobCode)
	point, err := crypto.NewECPoint(ec,
		new(big.Int).UnmarshalGmp(p.X),
		new(big.Int).UnmarshalGmp(p.Y),
	)
	if err != nil {
		common.Logger.Error("CodeToProofBobWC error", "err", err)
	}
	return &ProofBobWC{
		ProofBob: proofBob,
		U:        point,
	}

}
func ProofBobWCFromBytes22(ec elliptic.Curve, bzs [][]byte) (*ProofBobWC, error) {
	proofBob, err := ProofBobFromBytes(bzs)
	if err != nil {
		return nil, err
	}
	point, err := crypto.NewECPoint(ec,
		new(big.Int).SetBytes(bzs[10]),
		new(big.Int).SetBytes(bzs[11]))
	if err != nil {
		return nil, err
	}
	return &ProofBobWC{
		ProofBob: proofBob,
		U:        point,
	}, nil
}
func ProofBobWCToCode(p *ProofBobWC) *ProofBobWCCode {
	z := new(ProofBobWCCode)
	z.ProofBobCode = ProofBobToCode(p.ProofBob)
	// p.
	// z.=p.U.X(),p.U.Y()
	return z
}

//	func CodeToProofBobWC(p *ProofBobWCCode) *ProofBobWC {
//		z := new(ProofBobWC)
//		z.ProofBob = CodeToProofBob(p.ProofBobCode)
//		z.U = p.ECPointCode
//		return z
//	}
func EmptyCodeBob() *ProofBobCode {
	return &ProofBobCode{}
}
func EmptyCodeBobWC() *ProofBobWCCode {
	return &ProofBobWCCode{}
}

func NewProofBobMal(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int, X *crypto.ECPoint) *ProofbufBob {
	// 调用函数ProveBob生成证明
	proof, _ := ProveBob(Session, ec, pk, NTilde, h1, h2, c1, c2, x, y, r)
	proofcode := ProofBobToCode(proof)
	buf, _ := cbor.Marshal(proofcode)
	proofbuf := new(ProofbufBob)
	proofbuf.MalbufBob = buf
	return proofbuf
}
func NewProofBobWCMal(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int, X *crypto.ECPoint) *ProofbufBobWC {
	// 调用函数ProveBob生成证明
	proof, _ := ProveBobWC(Session, ec, pk, NTilde, h1, h2, c1, c2, x, y, r, X)
	proofcode := ProofBobWCToCode(proof)
	buf, _ := cbor.Marshal(proofcode)
	proofbuf := new(ProofbufBobWC)
	proofbuf.MalbufBobWC = buf
	return proofbuf
}
func (pf *ProofbufBob) VerifyMal(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2 *big.Int) bool {
	proofcode := EmptyCodeBob()
	cbor.Unmarshal(pf.MalbufBob, proofcode)
	proof := CodeToProofBob(proofcode)
	return proof.Verify(Session, ec, pk, NTilde, h1, h2, c1, c2)
}

// ProveBob.Verify implements verification of Bob's proof without check "VerifyMta_Bob" used in the MtA protocol from GG18Spec (9) Fig. 11.
// func (pf *ProofbufBobWC) VerifyMal(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2 *big.Int, X *crypto.ECPoint) bool {
// 	proofcode := EmptyCodeBobWC()
// 	cbor.Unmarshal(pf.MalbufBobWC, proofcode)
// 	proof := CodeToProofBobWC(proofcode)
// 	return proof.Verify(Session, ec, pk, NTilde, h1, h2, c1, c2, X)
// }

func ProveBobWC1(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int, X *crypto.ECPoint) (*ProofBobWC, error) {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c1 == nil || c2 == nil || x == nil || y == nil || r == nil {
		return nil, errors.New("ProveBob() received a nil argument")
	}

	NSquared := pk.NSquare()

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	q7 := new(big.Int).Mul(q3, q3)
	q7 = new(big.Int).Mul(q7, q)
	qNTilde := new(big.Int).Mul(q, NTilde)
	q3NTilde := new(big.Int).Mul(q3, NTilde)

	// steps are numbered as shown in Fig. 10, but diverge slightly for Fig. 11
	// 1.
	alpha := common.GetRandomPositiveInt(q3)

	// 2.
	rho := common.GetRandomPositiveInt(qNTilde)
	sigma := common.GetRandomPositiveInt(qNTilde)
	tau := common.GetRandomPositiveInt(q3NTilde)

	// 3.
	rhoPrm := common.GetRandomPositiveInt(q3NTilde)

	// 4.
	beta := common.GetRandomPositiveRelativelyPrimeInt(pk.N)

	gamma := common.GetRandomPositiveInt(q7)

	// 5.
	u := crypto.NewECPointNoCurveCheck(ec, zero, zero) // initialization suppresses an IDE warning
	if X != nil {
		u = crypto.ScalarBaseMult(ec, alpha)
	}

	// 6.
	modNTilde := common.ModInt(NTilde)
	z := modNTilde.Exp(h1, x)
	z = modNTilde.Mul(z, modNTilde.Exp(h2, rho))

	// 7.
	zPrm := modNTilde.Exp(h1, alpha)
	zPrm = modNTilde.Mul(zPrm, modNTilde.Exp(h2, rhoPrm))

	// 8.
	t := modNTilde.Exp(h1, y)
	t = modNTilde.Mul(t, modNTilde.Exp(h2, sigma))

	// 9.
	modNSquared := common.ModInt(NSquared)
	v := modNSquared.Exp(c1, alpha)
	v = modNSquared.Mul(v, modNSquared.Exp(pk.Gamma(), gamma))
	v = modNSquared.Mul(v, modNSquared.Exp(beta, pk.N))

	// 10.
	w := modNTilde.Exp(h1, gamma)
	w = modNTilde.Mul(w, modNTilde.Exp(h2, tau))

	// 11-12. e'
	var e *big.Int
	{ // must use RejectionSample
		var eHash *big.Int
		// X is nil if called by ProveBob (Bob's proof "without check")
		if X == nil {
			eHash = common.SHA512_256i_TAGGED(Session, append(pk.AsInts(), c1, c2, z, zPrm, t, v, w)...)
		} else {
			eHash = common.SHA512_256i_TAGGED(Session, append(pk.AsInts(), X.X(), X.Y(), c1, c2, u.X(), u.Y(), z, zPrm, t, v, w)...)
		}
		e = common.RejectionSample(q, eHash)
	}

	// 13.
	modN := common.ModInt(pk.N)
	s := modN.Exp(r, e)
	s = modN.Mul(s, beta)

	// 14.
	s1 := new(big.Int).Mul(e, x)
	s1 = s1.Add(s1, alpha)

	// 15.
	s2 := new(big.Int).Mul(e, rho)
	s2 = s2.Add(s2, rhoPrm)

	// 16.
	t1 := new(big.Int).Mul(e, y)
	t1 = t1.Add(t1, gamma)

	// 17.
	t2 := new(big.Int).Mul(e, sigma)
	t2 = t2.Add(t2, tau)

	// the regular Bob proof ("without check") is extracted and returned by ProveBob
	pf := &ProofBob{Z: z, ZPrm: zPrm, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}

	// or the WC ("with check") version is used in round 2 of the signing protocol
	return &ProofBobWC{ProofBob: pf, U: u}, nil
}

// ProveBob implements Bob's proof "ProveMta_Bob" used in the MtA protocol from GG18Spec (9) Fig. 11.
func ProveBob1(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int) (*ProofBob, error) {
	// the Bob proof ("with check") contains the ProofBob "without check"; this method extracts and returns it
	// X is supplied as nil to exclude it from the proof hash
	pf, err := ProveBobWC(Session, ec, pk, NTilde, h1, h2, c1, c2, x, y, r, nil)
	if err != nil {
		return nil, err
	}
	return pf.ProofBob, nil
}

func BytesToBobCode(bzs [][]byte) *ProofBobCode {
	if len(bzs) != ProofBobBytesParts {
		fmt.Errorf("expected %d byte parts to construct ProofBobBytesParts", ProofBobBytesParts)
		return nil
	}
	proofcode := &ProofBobCode{}
	temp := new(big.Int)
	temp.SetBytes(bzs[0])
	proofcode.Z = temp.MarshalGmp()
	cbor.Unmarshal(bzs[0], proofcode.Z)
	temp.SetBytes(bzs[1])
	proofcode.ZPrm = temp.MarshalGmp()
	cbor.Unmarshal(bzs[1], proofcode.ZPrm)
	temp.SetBytes(bzs[2])
	proofcode.T = temp.MarshalGmp()
	cbor.Unmarshal(bzs[2], proofcode.T)
	temp.SetBytes(bzs[3])
	proofcode.V = temp.MarshalGmp()
	cbor.Unmarshal(bzs[3], proofcode.V)
	temp.SetBytes(bzs[4])
	proofcode.W = temp.MarshalGmp()
	cbor.Unmarshal(bzs[4], proofcode.W)
	temp.SetBytes(bzs[5])
	proofcode.S = temp.MarshalGmp()
	cbor.Unmarshal(bzs[5], proofcode.S)
	temp.SetBytes(bzs[6])
	proofcode.S1 = temp.MarshalGmp()
	cbor.Unmarshal(bzs[6], proofcode.S1)
	temp.SetBytes(bzs[7])
	proofcode.S2 = temp.MarshalGmp()
	cbor.Unmarshal(bzs[7], proofcode.S2)
	temp.SetBytes(bzs[8])
	proofcode.T1 = temp.MarshalGmp()
	cbor.Unmarshal(bzs[8], proofcode.T1)
	temp.SetBytes(bzs[9])
	proofcode.T2 = temp.MarshalGmp()
	cbor.Unmarshal(bzs[9], proofcode.T2)
	return proofcode
}
func BytesToBobWCCode(bzs [][]byte) *ProofBobWCCode {
	if len(bzs) != ProofBobWCBytesParts {
		fmt.Errorf("expected %d byte parts to construct ProofBobBytesParts", ProofBobWCBytesParts)
		return nil
	}
	proofcode := &ProofBobWCCode{}
	// TODO:bzs[:10]是否正确？
	proofcode.ProofBobCode = BytesToBobCode(bzs[:10])
	temp := new(big.Int)
	temp.SetBytes(bzs[10])
	proofcode.ECPointCode.X = temp.MarshalGmp()
	cbor.Unmarshal(bzs[10], proofcode.ECPointCode.X)
	temp.SetBytes(bzs[11])
	proofcode.ECPointCode.Y = temp.MarshalGmp()
	cbor.Unmarshal(bzs[11], proofcode.ECPointCode.Y)

	return proofcode
}

func (proofcode *ProofBobCode) BobCodeToBytes() [ProofBobBytesParts][]byte {
	bzs := [ProofBobBytesParts][]byte{}
	bzs[0], _ = cbor.Marshal(proofcode.Z)
	bzs[1], _ = cbor.Marshal(proofcode.ZPrm)
	bzs[2], _ = cbor.Marshal(proofcode.T)
	bzs[3], _ = cbor.Marshal(proofcode.V)
	bzs[4], _ = cbor.Marshal(proofcode.W)
	bzs[5], _ = cbor.Marshal(proofcode.S)
	bzs[6], _ = cbor.Marshal(proofcode.S1)
	bzs[7], _ = cbor.Marshal(proofcode.S2)
	bzs[8], _ = cbor.Marshal(proofcode.T1)
	bzs[9], _ = cbor.Marshal(proofcode.T2)
	return bzs
}
func (proofcode *ProofBobWCCode) BobWCCodeToBytes() [ProofBobWCBytesParts][]byte {
	bzs := [ProofBobWCBytesParts][]byte{}
	// 创建一个长度为ProofBobBytesParts的二维数组
	// bis:=make([]int,ProofBobBytesParts)
	bzs[0], _ = cbor.Marshal(proofcode.Z)
	bzs[1], _ = cbor.Marshal(proofcode.ZPrm)
	bzs[2], _ = cbor.Marshal(proofcode.T)
	bzs[3], _ = cbor.Marshal(proofcode.V)
	bzs[4], _ = cbor.Marshal(proofcode.W)
	bzs[5], _ = cbor.Marshal(proofcode.S)
	bzs[6], _ = cbor.Marshal(proofcode.S1)
	bzs[7], _ = cbor.Marshal(proofcode.S2)
	bzs[8], _ = cbor.Marshal(proofcode.T1)
	bzs[9], _ = cbor.Marshal(proofcode.T2)
	bzs[10], _ = cbor.Marshal(proofcode.ECPointCode.X)
	bzs[11], _ = cbor.Marshal(proofcode.ECPointCode.Y)
	return bzs
}
func NewProofBobFromBytes(bzs [][]byte) (*ProofBob, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofBobBytesParts) {
		// fmt.Println("expected %d byte parts to construct ProofMod", ProofModBytesParts)
		return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofBobBytesParts)
	}
	// 将byte转化为code
	proofCode := BytesToBobCode(bzs)
	// 将code转化为proof
	proof := CodeToProofBob(proofCode)
	return proof, nil
}
func NewProofBobWCFromBytes(ec elliptic.Curve, bzs [][]byte) (*ProofBobWC, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofBobWCBytesParts) {
		// fmt.Println("expected %d byte parts to construct ProofMod", ProofModBytesParts)
		return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofBobWCBytesParts)
	}
	proofCode := BytesToBobWCCode(bzs)
	proof := CodeToProofBobWC(ec, proofCode)
	return proof, nil
}

func (pf *ProofBob) BytesFromProofBob() [ProofBobBytesParts][]byte {
	// proof to code
	proofcode := ProofBobToCode(pf)
	bzs := [ProofBobBytesParts][]byte{}
	// 创建一个长度为ProofBobBytesParts的二维数组
	bzs = proofcode.BobCodeToBytes()
	return bzs
}

// // bobwc
// func BytesToBobWCCode(bzs [][]byte) *ProofBobWCCode {
// 	if len(bzs) != ProofBobWCBytesParts {
// 		fmt.Errorf("expected %d byte parts to construct ProofBobBytesParts", ProofBobWCBytesParts)
// 		return nil
// 	}
// 	proofcode := &ProofBobWCCode{}
// 	temp := new(big.Int)
// 	temp.SetBytes(bzs[0])
// 	proofcode.Z = temp.MarshalGmp()
// 	cbor.Unmarshal(bzs[0], proofcode.Z)
// 	temp.SetBytes(bzs[1])
// 	proofcode.ZPrm = temp.MarshalGmp()
// 	cbor.Unmarshal(bzs[1], proofcode.ZPrm)
// 	temp.SetBytes(bzs[2])
// 	proofcode.T = temp.MarshalGmp()
// 	cbor.Unmarshal(bzs[2], proofcode.T)
// 	temp.SetBytes(bzs[3])
// 	proofcode.V = temp.MarshalGmp()
// 	cbor.Unmarshal(bzs[3], proofcode.V)
// 	temp.SetBytes(bzs[4])
// 	proofcode.W = temp.MarshalGmp()
// 	cbor.Unmarshal(bzs[4], proofcode.W)
// 	temp.SetBytes(bzs[5])
// 	proofcode.S = temp.MarshalGmp()
// 	cbor.Unmarshal(bzs[5], proofcode.S)
// 	temp.SetBytes(bzs[6])
// 	proofcode.S1 = temp.MarshalGmp()
// 	cbor.Unmarshal(bzs[6], proofcode.S1)
// 	temp.SetBytes(bzs[7])
// 	proofcode.S2 = temp.MarshalGmp()
// 	cbor.Unmarshal(bzs[7], proofcode.S2)
// 	temp.SetBytes(bzs[8])
// 	proofcode.T1 = temp.MarshalGmp()
// 	cbor.Unmarshal(bzs[8], proofcode.T1)
// 	temp.SetBytes(bzs[9])
// 	proofcode.T2 = temp.MarshalGmp()
// 	cbor.Unmarshal(bzs[9], proofcode.T2)
// 	temp.SetBytes(bzs[10])
// 	proofcode.X = temp.MarshalGmp()
// 	cbor.Unmarshal(bzs[10], proofcode.X)
// 	temp.SetBytes(bzs[11])
// 	proofcode.Y = temp.MarshalGmp()
// 	return proofcode
// }
//
// func (proofcode *ProofBobWCCode) BobWCCodeToBytes() [][]byte {
// 	bzs := make([][]byte, ProofBobWCBytesParts)
// 	bzs[0], _ = cbor.Marshal(proofcode.Z)
// 	bzs[1], _ = cbor.Marshal(proofcode.ZPrm)
// 	bzs[2], _ = cbor.Marshal(proofcode.T)
// 	bzs[3], _ = cbor.Marshal(proofcode.V)
// 	bzs[4], _ = cbor.Marshal(proofcode.W)
// 	bzs[5], _ = cbor.Marshal(proofcode.S)
// 	bzs[6], _ = cbor.Marshal(proofcode.S1)
// 	bzs[7], _ = cbor.Marshal(proofcode.S2)
// 	bzs[8], _ = cbor.Marshal(proofcode.T1)
// 	bzs[9], _ = cbor.Marshal(proofcode.T2)
// 	// 椭圆曲线
// 	bzs[10], _ = cbor.Marshal(proofcode.X)
// 	bzs[11], _ = cbor.Marshal(proofcode.Y)
// 	return bzs
// }

// func NewProofBobWCFromBytes(bzs [][]byte) (*ProofBobWC, error) {
// 	if !common.NonEmptyMultiBytes(bzs, ProofBobWCBytesParts) {
// 		// fmt.Println("expected %d byte parts to construct ProofMod", ProofModBytesParts)
// 		return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofBobWCBytesParts)
// 	}
// 	// 将byte转化为code
// 	proofCode := BytesToBobWCCode(bzs)
// 	// 将code转化为proof
// 	proof := CodeToProofBobWC(proofCode)
// 	return proof, nil
// }

// func (pf *ProofBobWC) BytesFromProofBobWC() [][]byte {
// 	// proof to code
// 	proofcode := ProofBobWCToCode(pf)
// 	bzs := make([][]byte, ProofBobWCBytesParts)
// 	bzs = proofcode.BobWCCodeToBytes()
// 	return bzs
// }
