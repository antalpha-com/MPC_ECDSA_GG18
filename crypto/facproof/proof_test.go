// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package facproof_test

import (
	"testing"
	// "time"

	// "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	// "math/big"
	big "github.com/bnb-chain/tss-lib/v2/gmp"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	. "github.com/bnb-chain/tss-lib/v2/crypto/facproof"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

var (
	Session = []byte("session")
)

func TestFac(test *testing.T) {
	ec := tss.EC()

	N0p := common.GetRandomPrimeInt(testSafePrimeBits)
	N0q := common.GetRandomPrimeInt(testSafePrimeBits)
	// // s1 := N0p.String()
	// s1 := N0p.Hex()
	// s2 := N0q.Hex()
	// s11 := "F37E881F2F0C0DC53F1D01EAE41952AB1D41D9FF5617F16C21770339555DB39AB66F82F45895778E2B154037A7A4B511505B9CFBFA1FAFC9235AA5101427F1810227CF6888C0D864E67A1CBDA8B4B8C1C757A046C1702E237BC9AF15369541A1513C38C2C36305BD4D25CF8B4B5542C3DF9B150FF9B093FAF3EEF1169CEABC21"
	//
	// s22 := "CE95C0C51CEE1B23A8D0324D795ED20A0250C228C0F14A90C0038D761223E3095ACFF69F8E3F48E65BD9A5D41ABB76A43E90E3C2B76721BC6DC337EE312CA679194FA722171B2B4E614A72E6858FA7679CFD4064C265DC5A13CC71081957E15337AD65C9EE5F14A030629C194BE769DB570C3D4BBB64C5A96C444EB7DD34A7F9"
	// // fmt.Println("N0p:", s1)
	// // fmt.Println("N0q:", s2)
	// N0p, _ := new(big.Int).SetString(s11, 16)
	// N0q, _ := new(big.Int).SetString(s22, 16)
	// s1 := N0p.Hex()
	// s2 := N0q.Hex()
	// // fmt.Println("N0p:", N0p)
	// // fmt.Println("N0q:", N0q)
	// fmt.Println("s1:", s1)
	// fmt.Println("s2:", s2)

	N0 := new(big.Int).Mul(N0p, N0q)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)
	proof, err := NewProof(Session, ec, N0, NCap, s, t, N0p, N0q)
	assert.NoError(test, err)

	ok := proof.Verify(Session, ec, N0, NCap, s, t)
	assert.True(test, ok, "proof must verify")

	N0p = common.GetRandomPrimeInt(1024)
	N0q = common.GetRandomPrimeInt(1024)
	N0 = new(big.Int).Mul(N0p, N0q)

	proof, err = NewProof(Session, ec, N0, NCap, s, t, N0p, N0q)
	assert.NoError(test, err)

	ok = proof.Verify(Session, ec, N0, NCap, s, t)
	assert.True(test, ok, "proof must verify")
}
func TestFacMal(test *testing.T) {
	ec := tss.EC()
	N0p := common.GetRandomPrimeInt(testSafePrimeBits)
	N0q := common.GetRandomPrimeInt(testSafePrimeBits)
	N0 := new(big.Int).Mul(N0p, N0q)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)
	proof, err := NewProof(Session, ec, N0, NCap, s, t, N0p, N0q)
	assert.NoError(test, err)

	proofcode := ProofToCode(proof)
	out, _ := cbor.Marshal(proofcode)
	proofcode2 := EmptyCode()
	cbor.Unmarshal(out, proofcode2)
	proof3 := CodeToProof(proofcode2)
	assert.True(test, proof3.Verify(Session, ec, N0, NCap, s, t), "proof must verify")
	proobuf, _ := NewProofMal(Session, ec, N0, NCap, s, t, N0p, N0q)
	assert.True(test, proobuf.VerifyMal(Session, ec, N0, NCap, s, t), "proof must verify")
	out4, _ := cbor.Marshal(proobuf)
	proof4 := &Proofbuf{}
	require.NoError(test, cbor.Unmarshal(out4, proof4), "failed to unmarshal 2nd proof")
	assert.True(test, proof4.VerifyMal(Session, ec, N0, NCap, s, t), "proof must verify")

}

// 关于参数ProofModBytesParts的修改，[ProofModBytesParts][]byte修改为[][]byte
func TestCodeBytes2(test *testing.T) {
	ec := tss.EC()
	N0p := common.GetRandomPrimeInt(testSafePrimeBits)
	N0q := common.GetRandomPrimeInt(testSafePrimeBits)
	N0 := new(big.Int).Mul(N0p, N0q)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)
	proof, err := NewProof(Session, ec, N0, NCap, s, t, N0p, N0q)
	assert.NoError(test, err)
	proofBzs := make([][]byte, ProofFacBytesParts)
	proofCode := ProofToCode(proof)
	proofBzs = proofCode.CodeToBytes2()
	proofCode2 := BytesToCode2(proofBzs)
	assert.Equal(test, proofCode, proofCode2)
	assert.NoError(test, err)
}

// 关于参数ProofModBytesParts的修改，[ProofModBytesParts][]byte修改为[][]byte
func TestFacCode2(test *testing.T) {
	ec := tss.EC()
	N0p := common.GetRandomPrimeInt(testSafePrimeBits)
	N0q := common.GetRandomPrimeInt(testSafePrimeBits)
	N0 := new(big.Int).Mul(N0p, N0q)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)
	proof, err := NewProof(Session, ec, N0, NCap, s, t, N0p, N0q)
	assert.NoError(test, err)

	// proofBzs：= [ProofModBytesParts][]byte{}
	proofBzs := proof.Bytes2()
	// proofBzs：= [ProofModBytesParts][]byte{}修改为[][]byte
	proof, err = NewProofFromBytes2(proofBzs)
	assert.NoError(test, err)
	ok := proof.Verify(Session, ec, N0, NCap, s, t)
	assert.True(test, ok, "proof must verify")

}
