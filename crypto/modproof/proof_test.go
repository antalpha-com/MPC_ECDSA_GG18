// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof_test

import (
	"testing"
	"time"

	. "github.com/bnb-chain/tss-lib/v2/crypto/modproof"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/stretchr/testify/assert"
)

var (
	Session = []byte("session")
)

func TestMod(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N

	proof, err := NewProof(Session, N, P, Q)
	assert.NoError(test, err)
	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])
	assert.NoError(test, err)

	ok := proof.Verify(Session, N)
	assert.True(test, ok, "proof must verify")
}
func TestCodeBytes(test *testing.T) {
	proofBzs := [ProofModBytesParts][]byte{}
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N

	proof, err := NewProof(Session, N, P, Q)
	assert.NoError(test, err)
	proofCode := ProofToCode(proof)
	proofBzs = proofCode.CodeToBytes()
	proofCode2 := BytesToCode(proofBzs)
	assert.Equal(test, proofCode, proofCode2)
	assert.NoError(test, err)

}
func TestModCode(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N

	proof, err := NewProof(Session, N, P, Q)
	assert.NoError(test, err)
	proofBzs := proof.Bytes1()
	proof, err = NewProofFromBytes1(proofBzs)
	assert.NoError(test, err)

	ok := proof.Verify(Session, N)
	assert.True(test, ok, "proof must verify")
}

// 关于参数ProofModBytesParts的修改，[ProofModBytesParts][]byte修改为[][]byte
func TestCodeBytes2(test *testing.T) {
	proofBzs := make([][]byte, ProofModBytesParts)
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N

	proof, err := NewProof(Session, N, P, Q)
	assert.NoError(test, err)
	proofCode := ProofToCode(proof)
	proofBzs = proofCode.CodeToBytes2()
	proofCode2 := BytesToCode2(proofBzs)
	assert.Equal(test, proofCode, proofCode2)
	assert.NoError(test, err)
}

// 关于参数ProofModBytesParts的修改，[ProofModBytesParts][]byte修改为[][]byte
func TestModCode2(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N

	proof, err := NewProof(Session, N, P, Q)
	assert.NoError(test, err)
	// proofBzs：= [ProofModBytesParts][]byte{}
	proofBzs := proof.Bytes2()
	// proofBzs：= [ProofModBytesParts][]byte{}修改为[][]byte
	proof, err = NewProofFromBytes2(proofBzs)
	assert.NoError(test, err)

	ok := proof.Verify(Session, N)
	assert.True(test, ok, "proof must verify")
}
