// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof

import (
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/fxamacker/cbor/v2"

	//	"math/big"
	big "github.com/bnb-chain/tss-lib/v2/gmp"
)

const (
	Iterations         = 80
	ProofModBytesParts = Iterations*2 + 3
)

var (
	one = big.NewInt(1)
)

type (
	ProofMod struct {
		W *big.Int
		X [Iterations]*big.Int
		A *big.Int
		B *big.Int
		Z [Iterations]*big.Int
	}
)
type (
	ProofModCode struct {
		W *big.IntGmpCode
		X [Iterations]*big.IntGmpCode
		A *big.IntGmpCode
		B *big.IntGmpCode
		Z [Iterations]*big.IntGmpCode
	}
)
type Proofbuf struct {
	Malbuf []byte
}

// isQuadraticResidue checks Euler criterion
func isQuadraticResidue(X, N *big.Int) bool {
	return big.Jacobi(X, N) == 1
}

func NewProof(Session []byte, N, P, Q *big.Int) (*ProofMod, error) {
	Phi := new(big.Int).Mul(new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one))
	// Fig 16.1
	W := common.GetRandomQuadraticNonResidue(N)

	// Fig 16.2
	Y := [Iterations]*big.Int{}
	for i := range Y {
		ei := common.SHA512_256i_TAGGED(Session, append([]*big.Int{W, N}, Y[:i]...)...)
		Y[i] = common.RejectionSample(N, ei)
	}

	// Fig 16.3
	modN, modPhi := common.ModInt(N), common.ModInt(Phi)
	invN := new(big.Int).ModInverse(N, Phi)
	X := [Iterations]*big.Int{}
	// Fix bitLen of A and B
	A := new(big.Int).Lsh(one, Iterations)
	B := new(big.Int).Lsh(one, Iterations)
	Z := [Iterations]*big.Int{}

	// for fourth-root
	expo := new(big.Int).Add(Phi, big.NewInt(4))
	expo = new(big.Int).Rsh(expo, 3)
	expo = modPhi.Mul(expo, expo)

	for i := range Y {
		for j := 0; j < 4; j++ {
			a, b := j&1, j&2>>1
			Yi := new(big.Int).SetBytes(Y[i].Bytes())
			if a > 0 {
				Yi = modN.Mul(big.NewInt(-1), Yi)
			}
			if b > 0 {
				Yi = modN.Mul(W, Yi)
			}
			if isQuadraticResidue(Yi, P) && isQuadraticResidue(Yi, Q) {
				Xi := modN.Exp(Yi, expo)
				Zi := modN.Exp(Y[i], invN)
				X[i], Z[i] = Xi, Zi
				A.SetBit(A, i, uint(a))
				B.SetBit(B, i, uint(b))
				break
			}
		}
	}

	pf := &ProofMod{W: W, X: X, A: A, B: B, Z: Z}
	return pf, nil
}

func (pf *ProofMod) Verify(Session []byte, N *big.Int) bool {
	fmt.Println("modproof verify begin")
	common.Logger.Info("modproof verify begin")
	if pf == nil || !pf.ValidateBasic() {
		return false
	}
	// TODO: add basic properties checker
	if isQuadraticResidue(pf.W, N) {
		return false
	}
	if pf.W.Sign() != 1 || pf.W.Cmp(N) != -1 {
		return false
	}
	for i := range pf.Z {
		if pf.Z[i].Sign() != 1 || pf.Z[i].Cmp(N) != -1 {
			return false
		}
	}
	for i := range pf.X {
		if pf.X[i].Sign() != 1 || pf.X[i].Cmp(N) != -1 {
			return false
		}
	}
	if pf.A.BitLen() != Iterations+1 {
		return false
	}
	if pf.B.BitLen() != Iterations+1 {
		return false
	}

	modN := common.ModInt(N)
	Y := [Iterations]*big.Int{}
	for i := range Y {
		ei := common.SHA512_256i_TAGGED(Session, append([]*big.Int{pf.W, N}, Y[:i]...)...)
		Y[i] = common.RejectionSample(N, ei)
	}

	// Fig 16. Verification
	{
		if N.Bit(0) == 0 || N.ProbablyPrime(30) {
			return false
		}
	}

	chs := make(chan bool, Iterations*2)
	for i := 0; i < Iterations; i++ {
		go func(i int) {
			left := modN.Exp(pf.Z[i], N)
			if left.Cmp(Y[i]) != 0 {
				chs <- false
				return
			}
			chs <- true
		}(i)

		go func(i int) {
			a := pf.A.Bit(i)
			b := pf.B.Bit(i)
			if a != 0 && a != 1 {
				chs <- false
				return
			}
			if b != 0 && b != 1 {
				common.Logger.Info("modproof verify failed")
				chs <- false
				return
			}
			left := modN.Exp(pf.X[i], big.NewInt(4))
			right := Y[i]
			if a > 0 {
				right = modN.Mul(big.NewInt(-1), right)
			}
			if b > 0 {
				right = modN.Mul(pf.W, right)
			}
			if left.Cmp(right) != 0 {
				chs <- false
				common.Logger.Info("modproof verify failed")
				return
			}
			chs <- true
		}(i)
	}

	for i := 0; i < Iterations*2; i++ {
		if !<-chs {
			common.Logger.Info("modproof verify failed")
			return false
		}
	}
	fmt.Printf("modproof verify success\n")
	common.Logger.Info("modproof verify success")
	return true
}

func (pf *ProofMod) ValidateBasic() bool {
	if pf.W == nil {
		return false
	}
	for i := range pf.X {
		if pf.X[i] == nil {
			return false
		}
	}
	if pf.A == nil {
		return false
	}
	if pf.B == nil {
		return false
	}
	for i := range pf.Z {
		if pf.Z[i] == nil {
			return false
		}
	}
	return true
}

func ProofToCode(p *ProofMod) *ProofModCode {
	z := new(ProofModCode)
	z.A = p.A.MarshalGmp()
	z.B = p.B.MarshalGmp()
	for i := range p.X {
		z.X[i] = p.X[i].MarshalGmp()
	}
	z.W = p.W.MarshalGmp()
	for i := range p.Z {
		z.Z[i] = p.Z[i].MarshalGmp()
	}

	return z
}
func CodeToProof(p *ProofModCode) *ProofMod {
	z := new(ProofMod)
	z.A = new(big.Int).UnmarshalGmp(p.A)
	z.B = new(big.Int).UnmarshalGmp(p.B)
	z.W = new(big.Int).UnmarshalGmp(p.W)
	for i := range p.X {
		z.X[i] = new(big.Int).UnmarshalGmp(p.X[i])
	}
	for i := range p.Z {
		z.Z[i] = new(big.Int).UnmarshalGmp(p.Z[i])
	}
	return z
}
func EmptyCode() *ProofModCode {
	return &ProofModCode{}
}
func (pf *ProofMod) Bytes() [ProofModBytesParts][]byte {
	bzs := [ProofModBytesParts][]byte{}
	bzs[0] = pf.W.Bytes()
	for i := range pf.X {
		if pf.X[i] != nil {
			bzs[1+i] = pf.X[i].Bytes()
		}
	}
	bzs[Iterations+1] = pf.A.Bytes()
	bzs[Iterations+2] = pf.B.Bytes()
	for i := range pf.Z {
		if pf.Z[i] != nil {
			bzs[Iterations+3+i] = pf.Z[i].Bytes()
		}
	}
	return bzs
}

// 将proof转换为[][]byte
func (pf *ProofMod) Bytes1() [ProofModBytesParts][]byte {
	// proof to code
	proofcode := ProofToCode(pf)
	// code to [][]byte
	// 创建一个新的ProofBytes
	bzs := [ProofModBytesParts][]byte{}
	// 将proofcode转化为[][]byte
	bzs = proofcode.CodeToBytes()
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

// 将[][]byte转化为proofcode再转化为proof
func NewProofFromBytes1(bzs [ProofModBytesParts][]byte) (*ProofMod, error) {
	// if !common.NonEmptyMultiBytes(bzs, ProofModBytesParts) {
	// 	// fmt.Println("expected %d byte parts to construct ProofMod", ProofModBytesParts)
	// 	return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofModBytesParts)
	// }
	// 将byte转化为code
	proofCode := BytesToCode(bzs)
	// 将code转化为proof
	proof := CodeToProof(proofCode)
	return proof, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofMod, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofModBytesParts) {
		// fmt.Println("expected %d byte parts to construct ProofMod", ProofModBytesParts)
		return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofModBytesParts)
	}
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}

	X := [Iterations]*big.Int{}
	copy(X[:], bis[1:(Iterations+1)])

	Z := [Iterations]*big.Int{}
	copy(Z[:], bis[(Iterations+3):])

	return &ProofMod{
		W: bis[0],
		X: X,
		A: bis[Iterations+1],
		B: bis[Iterations+2],
		Z: Z,
	}, nil
}

func (p *Proofbuf) VerifyMal(Session []byte, N *big.Int) bool {
	// proofcode := &ProofCode{}
	proofcode := EmptyCode()
	cbor.Unmarshal(p.Malbuf, proofcode)
	proof := CodeToProof(proofcode)
	return proof.Verify(Session, N)
}

type ProofBytes struct {
	MalBytes [ProofModBytesParts][]byte
}

func (proofcode *ProofModCode) CodeToBytes() [ProofModBytesParts][]byte {
	// 创建一个ProofBytes
	//	bzs := &ProofBytes{}
	bzs := [ProofModBytesParts][]byte{}
	// TODO:反序列化结果不同
	bzs[0], _ = cbor.Marshal(proofcode.W)
	// // 创建一个新的intgmpcode
	// temp1 := new(big.IntGmpCode)
	// // todo: 使用unmarshal将[]byte转化为big.IntGmpCode成功！
	// cbor.Unmarshal(bzs[0], temp1)
	// temp := new(big.Int)
	// // W和temp的值是否相同？
	// temp.SetBytes(bzs[0])
	// proofcode.W = temp.MarshalGmp()

	for i := range proofcode.X {
		if proofcode.X[i] != nil {
			bzs[1+i], _ = cbor.Marshal(proofcode.X[i])
		}
	}
	bzs[Iterations+1], _ = cbor.Marshal(proofcode.A)
	bzs[Iterations+2], _ = cbor.Marshal(proofcode.B)
	for i := range proofcode.Z {
		if proofcode.Z[i] != nil {
			bzs[Iterations+3+i], _ = cbor.Marshal(proofcode.Z[i])
		}
	}
	return bzs
}
func BytesToCode(bzs [ProofModBytesParts][]byte) *ProofModCode {
	if len(bzs) != ProofModBytesParts {
		fmt.Errorf("expected %d byte parts to construct ProofModCode", ProofModBytesParts)
		return nil
	}
	proofcode := &ProofModCode{}
	// var err error
	// 解序列化失败，结果为nil
	// x[i-1] = new(big.Int).SetBytes(bzs[i])
	// X[i-1] = x[i-1].MarshalGmp()
	temp := new(big.Int)
	temp.SetBytes(bzs[0])
	proofcode.W = temp.MarshalGmp()
	// err = cbor.Unmarshal(bzs[0], proofcode.W)
	// if err != nil {
	// 	return nil, err
	// }
	// temp1 := new(big.IntGmpCode)
	// // todo: 使用unmarshal将[]byte转化为big.IntGmpCode成功！
	cbor.Unmarshal(bzs[0], proofcode.W)
	for i := 0; i < Iterations; i++ {
		if bzs[1+i] != nil {
			// temp := new(big.Int)
			temp.SetBytes(bzs[1+i])
			proofcode.X[i] = temp.MarshalGmp()
			cbor.Unmarshal(bzs[1+i], proofcode.X[i])
		}
	}
	// temp.SetBytes(bzs[Iterations+1])
	// proofcode.A = temp.MarshalGmp()
	temp.SetBytes(bzs[1+Iterations])
	proofcode.A = temp.MarshalGmp()
	cbor.Unmarshal(bzs[Iterations+1], proofcode.A)
	// if err != nil {
	// 	return nil, err
	// }
	temp.SetBytes(bzs[Iterations+2])
	proofcode.B = temp.MarshalGmp()
	cbor.Unmarshal(bzs[Iterations+2], proofcode.B)
	// if err != nil {
	// 	return nil, err
	// }

	for i := 0; i < Iterations; i++ {
		if bzs[Iterations+3+i] != nil {
			temp.SetBytes(bzs[Iterations+3+i])
			proofcode.Z[i] = temp.MarshalGmp()
			cbor.Unmarshal(bzs[Iterations+3+i], proofcode.Z[i])
			// if err != nil {
			// 	return nil, err
			// }
		}
	}
	return proofcode
}

func BytesToCode2(bzs [][]byte) *ProofModCode {
	if len(bzs) != ProofModBytesParts {
		fmt.Errorf("expected %d byte parts to construct ProofModCode", ProofModBytesParts)
		return nil
	}
	proofcode := &ProofModCode{}
	// var err error
	// 解序列化失败，结果为nil
	// x[i-1] = new(big.Int).SetBytes(bzs[i])
	// X[i-1] = x[i-1].MarshalGmp()
	temp := new(big.Int)
	temp.SetBytes(bzs[0])
	proofcode.W = temp.MarshalGmp()
	// err = cbor.Unmarshal(bzs[0], proofcode.W)
	// if err != nil {
	// 	return nil, err
	// }
	// temp1 := new(big.IntGmpCode)
	// // todo: 使用unmarshal将[]byte转化为big.IntGmpCode成功！
	cbor.Unmarshal(bzs[0], proofcode.W)
	for i := 0; i < Iterations; i++ {
		if bzs[1+i] != nil {
			// temp := new(big.Int)
			temp.SetBytes(bzs[1+i])
			proofcode.X[i] = temp.MarshalGmp()
			cbor.Unmarshal(bzs[1+i], proofcode.X[i])
		}
	}
	// temp.SetBytes(bzs[Iterations+1])
	// proofcode.A = temp.MarshalGmp()
	temp.SetBytes(bzs[1+Iterations])
	proofcode.A = temp.MarshalGmp()
	cbor.Unmarshal(bzs[Iterations+1], proofcode.A)
	// if err != nil {
	// 	return nil, err
	// }
	temp.SetBytes(bzs[Iterations+2])
	proofcode.B = temp.MarshalGmp()
	cbor.Unmarshal(bzs[Iterations+2], proofcode.B)
	// if err != nil {
	// 	return nil, err
	// }

	for i := 0; i < Iterations; i++ {
		if bzs[Iterations+3+i] != nil {
			temp.SetBytes(bzs[Iterations+3+i])
			proofcode.Z[i] = temp.MarshalGmp()
			cbor.Unmarshal(bzs[Iterations+3+i], proofcode.Z[i])
			// if err != nil {
			// 	return nil, err
			// }
		}
	}
	return proofcode
}
func (proofcode *ProofModCode) CodeToBytes2() [][]byte {
	// 创建一个ProofBytes
	//	bzs := &ProofBytes{}
	bzs := make([][]byte, ProofModBytesParts)
	// bzs := [ProofModBytesParts][]byte{}
	// TODO:反序列化结果不同
	bzs[0], _ = cbor.Marshal(proofcode.W)
	for i := range proofcode.X {
		if proofcode.X[i] != nil {
			bzs[1+i], _ = cbor.Marshal(proofcode.X[i])
		}
	}
	bzs[Iterations+1], _ = cbor.Marshal(proofcode.A)
	bzs[Iterations+2], _ = cbor.Marshal(proofcode.B)
	for i := range proofcode.Z {
		if proofcode.Z[i] != nil {
			bzs[Iterations+3+i], _ = cbor.Marshal(proofcode.Z[i])
		}
	}
	return bzs
}

func NewProofFromBytes2(bzs [][]byte) (*ProofMod, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofModBytesParts) {
		// fmt.Println("expected %d byte parts to construct ProofMod", ProofModBytesParts)
		return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofModBytesParts)
	}
	// 将byte转化为code
	proofCode := BytesToCode2(bzs)
	// 将code转化为proof
	proof := CodeToProof(proofCode)
	return proof, nil
}
func (pf *ProofMod) Bytes2() [][]byte {
	// proof to code
	proofcode := ProofToCode(pf)
	// code to [][]byte
	// 创建一个新的ProofBytes
	bzs := [][]byte{}
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
