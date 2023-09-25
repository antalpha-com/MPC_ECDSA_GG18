// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	// "math/big"
	big "github.com/bnb-chain/tss-lib/v2/gmp"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	cmts "github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v2/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

var (
	zero = big.NewInt(0)
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
// newRound1  create a new instance of round1, which implements the tss.Round interface.
// return the created instance of round1, which represents the first round of the TSS protocol.
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

// Start is the entry point for the first round (round1) of the protocol
// it represents the operation that round1 needs to perform
// 1. calculate "partial" key share ui
// 2. compute the vss shares
// 3. make hash commitment
// 4.use the pre-params if they were provided to the LocalParty constructor,
// creat preParams if there is not before.
// generate the dln proofs for keygen
// save params
func (round *round1) Start() *tss.Error {
	// Check if the round has already started
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	// Set the round number to 1 and mark the round as started.
	// Reset the ok flags, which keep track of participants' message acceptance status.
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	// 1. calculate "partial" key share ui
	ui := common.GetRandomPositiveInt(round.Params().EC().Params().N)

	round.temp.ui = ui

	// 2. compute the vss shares
	ids := round.Parties().IDs().Keys()
	vs, shares, err := vss.Create(round.Params().EC(), round.Threshold(), ui, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.save.Ks = ids

	// security: the original u_i may be discarded
	ui = zero // clears the secret data from memory
	_ = ui    // silences a linter warning

	// make commitment -> (C, D)
	pGFlat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	cmt := cmts.NewHashCommitment(pGFlat...)

	// 4. generate Paillier public key E_i, private key and proof
	// 5-7. generate safe primes for ZKPs used later on
	// 9-11. compute ntilde, h1, h2 (uses safe primes)
	// use the pre-params if they were provided to the LocalParty constructor
	var preParams *LocalPreParams
	if round.save.LocalPreParams.Validate() && !round.save.LocalPreParams.ValidateWithProof() {
		return round.WrapError(
			errors.New("`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib"))
	} else if round.save.LocalPreParams.ValidateWithProof() {
		preParams = &round.save.LocalPreParams
	} else {
		preParams, err = GeneratePreParams(round.SafePrimeGenTimeout(), round.Concurrency())
		if err != nil {
			return round.WrapError(errors.New("pre-params generation failed"), Pi)
		}
	}
	round.save.LocalPreParams = *preParams
	round.save.NTildej[i] = preParams.NTildei
	round.save.H1j[i], round.save.H2j[i] = preParams.H1i, preParams.H2i

	// generate the dlnproofs for keygen
	h1i, h2i, alpha, beta, p, q, NTildei :=
		preParams.H1i,
		preParams.H2i,
		preParams.Alpha,
		preParams.Beta,
		preParams.P,
		preParams.Q,
		preParams.NTildei
	dlnProof1 := dlnproof.NewDLNProof(h1i, h2i, alpha, p, q, NTildei)
	dlnProof2 := dlnproof.NewDLNProof(h2i, h1i, beta, p, q, NTildei)

	// for this P: SAVE
	// - shareID
	// and keep in temporary storage:
	// - VSS Vs
	// - our set of Shamir shares
	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	round.save.ShareID = ids[i]
	round.temp.vs = vs
	ssid, err := round.getSSID()
	if err != nil {
		return round.WrapError(errors.New("failed to generate ssid"))
	}
	round.temp.ssid = ssid
	round.temp.shares = shares

	// for this P: SAVE de-commitments, paillier keys for round 2
	round.save.PaillierSK = preParams.PaillierSK
	round.save.PaillierPKs[i] = &preParams.PaillierSK.PublicKey
	round.temp.deCommitPolyG = cmt.D

	// BROADCAST commitments, paillier pk + proof; round 1 message
	{
		msg, err := NewKGRound1Message(
			round.PartyID(), cmt.C, &preParams.PaillierSK.PublicKey, preParams.NTildei, preParams.H1i, preParams.H2i, dlnProof1, dlnProof2)
		if err != nil {
			return round.WrapError(err, Pi)
		}
		// store the message msg in the kgRound1Messages array of the round object
		// The index i corresponds to the current party's index in the array.
		round.temp.kgRound1Messages[i] = msg
		// send the message msg to the out channel, which is used for communication between parties in the protocol.
		round.out <- msg
	}
	// Return nil to indicate that the start of the round was successful without any errors.
	return nil
}

// CanAccept is used to determine if a specific message can be accepted
func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	// In round1, it checks if the message's type is KGRound1Message and if the message was transmitted through reliable broadcast
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update is the update method of round1 and is responsible for processing received messages
func (round *round1) Update() (bool, *tss.Error) {
	// iterate over the kgRound1Messages list and handles each message.
	for j, msg := range round.temp.kgRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		// vss check is in round 2
		round.ok[j] = true
	}
	return true, nil
}

// NextRound is the method for the next round of round1.
// It returns the object of round2 and sets the started flag of the current round to false.
func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
