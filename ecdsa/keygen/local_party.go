// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"fmt"
	// "math/big"
	big "github.com/bnb-chain/tss-lib/v2/gmp"

	"github.com/bnb-chain/tss-lib/v2/common"
	cmt "github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		temp localTempData
		data LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- LocalPartySaveData
	}

	localMessageStore struct {
		kgRound1Messages,
		kgRound2Message1s,
		kgRound2Message2s,
		kgRound3Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after keygen)
		ui            *big.Int // used for tests
		KGCs          []cmt.HashCommitment
		vs            vss.Vs
		ssid          []byte
		ssidNonce     *big.Int
		shares        vss.Shares
		deCommitPolyG cmt.HashDeCommitment
	}
)

// Exported, used in `tss` client

// NewLocalParty creates and initializes a local party in a threshold secret sharing (TSS) protocol.
// The local party represents a participant in the protocol execution.
func NewLocalParty(
	params *tss.Parameters,
	out chan<- tss.Message,
	end chan<- LocalPartySaveData,
	optionalPreParams ...LocalPreParams,
) tss.Party {
	// obtain the total party count from the params parameter
	// creat a new LocalPartySaveData instance to store the local party's data.
	partyCount := params.PartyCount()
	data := NewLocalPartySaveData(partyCount)
	// check if optionalPreParams is provided
	// when `optionalPreParams` is provided we'll use the pre-computed primes instead of generating them from scratch
	if 0 < len(optionalPreParams) {
		if 1 < len(optionalPreParams) {
			panic(errors.New("keygen.NewLocalParty expected 0 or 1 item in `optionalPreParams`"))
		}
		// perform validation on the pre-params data
		if !optionalPreParams[0].ValidateWithProof() {
			panic(errors.New("`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib"))
		}
		// assign it to the LocalPreParams field of the data variable.
		data.LocalPreParams = optionalPreParams[0]
	}
	// create a new LocalParty instance and initializes its properties.
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}
	// initialize message and temporary data structures specific to the key generation (kg) rounds of the TSS protocol.
	p.temp.kgRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound2Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound2Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound3Messages = make([]tss.ParsedMessage, partyCount)
	// temp data init
	p.temp.KGCs = make([]cmt.HashCommitment, partyCount)
	return p
}

// FirstRound method is responsible for creating and returning a new round object of type tss.Round.
func (p *LocalParty) FirstRound() tss.Round {
	// return an instance of round1 by calling the newRound1 constructor function
	// p.params (the TSS parameters), &p.data (a pointer to the local party's save data), &p.temp (a pointer to the local party's temporary data), p.out (the channel for sending TSS messages), and p.end (the channel for signaling the completion of the TSS protocol).
	return newRound1(p.params, &p.data, &p.temp, p.out, p.end)
}

// Start method starts the execution of the TSS protocol for the local party.
// By calling tss.BaseStart, the Start method delegates the responsibility of starting the TSS protocol to the generic implementation
func (p *LocalParty) Start() *tss.Error {
	// call the tss.BaseStart function, passing the local party p and the task name as arguments
	return tss.BaseStart(p, TaskName)
}

// Update method is used to update the state of the current round in the local party based on the received message. It is implemented based on the BaseUpdate function.
func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

// UpdateFromBytes  is responsible for updating the party's state based on a byte slice representing a wire message received from another party.
func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	// call the ParseWireMessage function to parse the wire message,
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	// call the Update method of the LocalParty, passing the parsed message as an argument.
	return p.Update(msg)
}

// ValidateMessage  is responsible for validating a parsed message received by the party.
func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// call the ValidateMessage method of the embedded BaseParty  to perform the initial message validation.
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	// check whether the "from index" of the message exceeds the maximum index allowed based on the number of parties in the protocol.
	if maxFromIdx := p.params.PartyCount() - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			p.params.PartyCount(), msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

// StoreMessage function is responsible for storing a parsed message received by the party.
func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	//  ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	// perform a basic validation of the message
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// extract the index of the sender (fromPIdx) from the parsed message.
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	// use a switch/case statement to determine the type of the message content and store it in the appropriate field of the LocalParty.
	switch msg.Content().(type) {
	case *KGRound1Message:
		p.temp.kgRound1Messages[fromPIdx] = msg
	case *KGRound2Message1:
		p.temp.kgRound2Message1s[fromPIdx] = msg
	case *KGRound2Message2:
		p.temp.kgRound2Message2s[fromPIdx] = msg
	case *KGRound3Message:
		p.temp.kgRound3Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

// OriginalIndex method is defined on the LocalPartySaveData type, which represents the saved data of a local party during the protocol execution
// It returns the original index of the party within the protocol execution
func (save LocalPartySaveData) OriginalIndex() (int, error) {
	index := -1
	ki := save.ShareID
	for j, kj := range save.Ks {
		if kj.Cmp(ki) != 0 {
			continue
		}
		index = j
		break
	}
	if index < 0 {
		return -1, errors.New("a party index could not be recovered from Ks")
	}
	return index, nil
}

// PartyID method returns the PartyID of the LocalParty
func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

// String method returns a string representation of the LocalParty
func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
