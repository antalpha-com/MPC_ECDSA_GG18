// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Start represents the fourth round of a protocol.
// Start function in round4 performs the verification of received proofs from other parties using paillier encryption.
// It checks the verification results, identifies any culprits, and signals the end of the round by sending the saved data to the end channel.
func (round *round4) Start() *tss.Error {
	// Check if the round has already started
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	// Set the round number to 4 and mark the round as started.
	round.number = 4
	round.started = true
	// Reset the ok array
	round.resetOK()
	// Retrieve the index of the current party (i) and the list of all parties (Ps) and their corresponding party IDs (PIDs).
	i := round.PartyID().Index
	Ps := round.Parties().IDs()
	PIDs := Ps.Keys()
	// Retrieve the ECDSA public key (ecdsaPub) saved in the previous round.
	ecdsaPub := round.save.ECDSAPub

	// 1-3. (concurrent)
	// r3 messages are assumed to be available and != nil in this function
	r3msgs := round.temp.kgRound3Messages
	chs := make([]chan bool, len(r3msgs))
	for i := range chs {
		chs[i] = make(chan bool)
	}
	// Verify the received proof of other parties
	// If the verification is successful, the corresponding channel (chs[j]) is signaled with true, indicating a successful verification. Otherwise, it is signaled with false.
	for j, msg := range round.temp.kgRound3Messages {
		if j == i {
			continue
		}
		r3msg := msg.Content().(*KGRound3Message)
		go func(prf paillier.Proof, j int, ch chan<- bool) {
			ppk := round.save.PaillierPKs[j]
			ok, err := prf.Verify(ppk.N, PIDs[j], ecdsaPub)
			if err != nil {
				common.Logger.Error(round.WrapError(err, Ps[j]).Error())
				ch <- false
				return
			}
			ch <- ok
		}(r3msg.UnmarshalProofInts(), j, chs[j])
	}

	// consume unbuffered channels (end the goroutines)
	// Consume the channels and update the ok array.
	for j, ch := range chs {
		// If the party itself is being verified (j == i), set its verification status to true by default.
		if j == i {
			round.ok[j] = true
			continue
		}
		// Otherwise, assign the received verification result from the corresponding channel (chs[j]) to the ok array.
		round.ok[j] = <-ch
	}
	// identify any parties that caused verification failures and collect them as culprits in the culprits slice.
	culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
	for j, ok := range round.ok {
		// If there are any culprits, return an error indicating that the paillier verification failed for those parties.
		if !ok {
			culprits = append(culprits, Ps[j])
			common.Logger.Warningf("paillier verify failed for party %s", Ps[j])
			continue
		}
		common.Logger.Debugf("paillier verify passed for party %s", Ps[j])

	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("paillier verify failed"), culprits...)
	}
	// If all verifications are successful, send the saved data (round.save) to the end channel to indicate the end of the round.
	round.end <- *round.save

	return nil
}

// CanAccept determines whether a message can be accepted in this round.
// In the case of round4, it always returns false because no incoming messages are expected in this round.
func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

// Update function updates the round based on incoming messages.
// However, in round4, no incoming messages are expected, so it always returns false and a nil error.
func (round *round4) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

// NextRound determines the next round to be executed in the protocol.
// In the case of round4, the protocol is finished, so it returns nil to indicate that there is no next round.
func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
