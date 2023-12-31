// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"sync"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/mta"
	errorspkg "github.com/pkg/errors"

	// "math/big"
	big "github.com/bnb-chain/tss-lib/v2/gmp"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	var alphas = make([]*big.Int, len(round.Parties().IDs()))
	var us = make([]*big.Int, len(round.Parties().IDs()))

	i := round.PartyID().Index
	fmt.Println(i)
	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*2)
	wg := sync.WaitGroup{}
	wg.Add((len(round.Parties().IDs()) - 1) * 2)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		ContextJ := append(round.temp.ssid, new(big.Int).SetUint64(uint64(j)).Bytes()...)
		// ContextJ := append(round.temp.ssid)
		str := string(ContextJ)

		// Alice_end
		go func(j int, Pj *tss.PartyID) {
			ContextJ := []byte(str)
			defer wg.Done()
			r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
			proofBob, err := r2msg.UnmarshalProofBob()
			if err != nil {
				fmt.Println("")
				errChs <- round.WrapError(errorspkg.Wrapf(err, "UnmarshalProofBob failed"), Pj)
				return
			}

			alphaIj, err := mta.AliceEnd(
				ContextJ,
				round.Params().EC(),
				round.key.PaillierPKs[i],
				proofBob,
				round.key.H1j[i],
				round.key.H2j[i],
				round.temp.cis[j],
				new(big.Int).SetBytes(r2msg.GetC1()),
				round.key.NTildej[i],
				round.key.PaillierSK)
			alphas[j] = alphaIj
			if err != nil {
				fmt.Println("mta.AliceEnd failed ", Pj.Index, i)
				errChs <- round.WrapError(err, Pj)
			}
			if Pj.Index == 1 && i == 0 {
				fmt.Println("test222")
			}
		}(j, Pj)
		// Alice_end_wc
		go func(j int, Pj *tss.PartyID) {
			ContextJ := []byte(str)
			defer wg.Done()
			r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
			// fmt.Printf("round3: to:%v,from:%v,r2msg.ProofBobWc: %v\n", i, Pj.Index, r2msg.ProofBobWc)
			proofBobWC, err := r2msg.UnmarshalProofBobWC(round.Parameters.EC())
			// fmt.Printf("round3: to:%v,from:%v,r2msg.ProofBob: %v,r2msg.x: %v\n", i, Pj.Index, *proofBobWC.ProofBob, *proofBobWC.U.X())
			fmt.Printf("round3: to:%v,from:%v,r2msg.x: %v\n", i, Pj.Index, *proofBobWC.U.X())

			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "UnmarshalProofBobWC failed"), Pj)
				return
			}
			// fmt.Printf("round3:i = %v, j = %v, proofBobWC = %+v\n", i, j, proofBobWC.U)
			uIj, err := mta.AliceEndWC(
				ContextJ,
				round.Params().EC(),
				round.key.PaillierPKs[i],
				proofBobWC,
				round.temp.bigWs[j],
				round.temp.cis[j],
				new(big.Int).SetBytes(r2msg.GetC2()),
				round.key.NTildej[i],
				round.key.H1j[i],
				round.key.H2j[i],
				round.key.PaillierSK)
			us[j] = uIj
			if err != nil {
				fmt.Println("mta.AliceEndWC failed ", Pj.Index, i)
				errChs <- round.WrapError(err, Pj)
			} else {
				fmt.Println("mta.AliceEndWC success ", Pj.Index, i)

			}
		}(j, Pj)
	}

	// consume error channels; wait for goroutines
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0, len(round.Parties().IDs()))
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("failed to calculate Alice_end or Alice_end_wc"), culprits...)
	}

	modN := common.ModInt(round.Params().EC().Params().N)
	thelta := modN.Mul(round.temp.k, round.temp.gamma)
	sigma := modN.Mul(round.temp.k, round.temp.w)

	for j := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		thelta = modN.Add(thelta, alphas[j].Add(alphas[j], round.temp.betas[j]))
		sigma = modN.Add(sigma, us[j].Add(us[j], round.temp.vs[j]))
	}

	round.temp.theta = thelta
	round.temp.sigma = sigma
	r3msg := NewSignRound3Message(round.PartyID(), thelta)
	round.temp.signRound3Messages[round.PartyID().Index] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
