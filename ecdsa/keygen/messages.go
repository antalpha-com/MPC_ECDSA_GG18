// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"github.com/bnb-chain/tss-lib/v2/crypto/facproof"
	"github.com/bnb-chain/tss-lib/v2/crypto/modproof"
	// "math/big"
	big "github.com/bnb-chain/tss-lib/v2/gmp"

	"github.com/bnb-chain/tss-lib/v2/common"
	cmt "github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v2/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*KGRound1Message)(nil),
		(*KGRound2Message1)(nil),
		(*KGRound2Message2)(nil),
		(*KGRound3Message)(nil),
	}
)

// NewKGRound1Message parse the first round of messages into protobuf messages
// and save them to tss.ParsedMessage
func NewKGRound1Message(
	from *tss.PartyID,
	ct cmt.HashCommitment,
	paillierPK *paillier.PublicKey,
	nTildeI, h1I, h2I *big.Int,
	dlnProof1, dlnProof2 *dlnproof.Proof,
) (tss.ParsedMessage, error) {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dlnProof1Bz, err := dlnProof1.Serialize()
	if err != nil {
		return nil, err
	}
	dlnProof2Bz, err := dlnProof2.Serialize()
	if err != nil {
		return nil, err
	}
	content := &KGRound1Message{
		Commitment: ct.Bytes(),
		PaillierN:  paillierPK.N.Bytes(),
		NTilde:     nTildeI.Bytes(),
		H1:         h1I.Bytes(),
		H2:         h2I.Bytes(),
		Dlnproof_1: dlnProof1Bz,
		Dlnproof_2: dlnProof2Bz,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

// ValidateBasic (KGRound1Message method):
// Validates the basic integrity of the KGRound1Message.
// Checks if the necessary fields are non-empty.
func (m *KGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetCommitment()) &&
		common.NonEmptyBytes(m.GetPaillierN()) &&
		common.NonEmptyBytes(m.GetNTilde()) &&
		common.NonEmptyBytes(m.GetH1()) &&
		common.NonEmptyBytes(m.GetH2()) &&
		// expected len of dln proof = sizeof(int64) + len(alpha) + len(t)
		common.NonEmptyMultiBytes(m.GetDlnproof_1(), 2+(dlnproof.Iterations*2)) &&
		common.NonEmptyMultiBytes(m.GetDlnproof_2(), 2+(dlnproof.Iterations*2))
}

// UnmarshalCommitment (KGRound1Message method) unmarshals the commitment from the KGRound1Message.
func (m *KGRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// UnmarshalPaillierPK (KGRound1Message method) unmarshals the Paillier public key from the KGRound1Message.
func (m *KGRound1Message) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
}

// UnmarshalNTilde (KGRound1Message method) unmarshals the NTilde value from the KGRound1Message.
func (m *KGRound1Message) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

// UnmarshalH1 (KGRound1Message method) unmarshals the H1 value from the KGRound1Message.
func (m *KGRound1Message) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

// UnmarshalH2 (KGRound1Message method) unmarshals the H2 value from the KGRound1Message
func (m *KGRound1Message) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

// UnmarshalDLNProof1 (KGRound1Message method)unmarshals the first DLN proof from the KGRound1Message.
func (m *KGRound1Message) UnmarshalDLNProof1() (*dlnproof.Proof, error) {
	return dlnproof.UnmarshalDLNProof(m.GetDlnproof_1())
}

// UnmarshalDLNProof2 (KGRound1Message method) unmarshals the second DLN proof from the KGRound1Message.
func (m *KGRound1Message) UnmarshalDLNProof2() (*dlnproof.Proof, error) {
	return dlnproof.UnmarshalDLNProof(m.GetDlnproof_2())
}

// ----- //
// NewKGRound2Message1 creates a new KGRound2Message1 with the specified parameters

func NewKGRound2Message1(
	to, from *tss.PartyID,
	share *vss.Share,
	proof *facproof.ProofFac,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	proofBzs := proof.Bytes()
	content := &KGRound2Message1{
		Share:    share.Share.Bytes(),
		FacProof: proofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetShare())
	// This is commented for backward compatibility, which msg has no proof
	// && common.NonEmptyMultiBytes(m.GetFacProof(), facproof.ProofFacBytesParts)
}

func (m *KGRound2Message1) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.Share)
}

func (m *KGRound2Message1) UnmarshalFacProof() (*facproof.ProofFac, error) {
	return facproof.NewProofFromBytes(m.GetFacProof())
}

// ----- //

func NewKGRound2Message2(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proof *modproof.ProofMod,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	proofBzs := proof.Bytes()
	content := &KGRound2Message2{
		DeCommitment: dcBzs,
		ModProof:     proofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetDeCommitment())
	// This is commented for backward compatibility, which msg has no proof
	// && common.NonEmptyMultiBytes(m.GetModProof(), modproof.ProofModBytesParts)
}

func (m *KGRound2Message2) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *KGRound2Message2) UnmarshalModProof() (*modproof.ProofMod, error) {
	return modproof.NewProofFromBytes(m.GetModProof())
}

// ----- //

func NewKGRound3Message(
	from *tss.PartyID,
	proof paillier.Proof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pfBzs := make([][]byte, len(proof))
	for i := range pfBzs {
		if proof[i] == nil {
			continue
		}
		pfBzs[i] = proof[i].Bytes()
	}
	content := &KGRound3Message{
		PaillierProof: pfBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetPaillierProof(), paillier.ProofIters)
}

func (m *KGRound3Message) UnmarshalProofInts() paillier.Proof {
	var pf paillier.Proof
	proofBzs := m.GetPaillierProof()
	for i := range pf {
		pf[i] = new(big.Int).SetBytes(proofBzs[i])
	}
	return pf
}
