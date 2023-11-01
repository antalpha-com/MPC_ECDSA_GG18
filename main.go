// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package main

import (
	// "crypto/ecdsa"
	//	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/communication"
	log "github.com/sirupsen/logrus"
	// "math/big"
	big "github.com/bnb-chain/tss-lib/v2/gmp"
	// "github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen" // "github.com/bnb-chain/tss-lib/tss"
	// "github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// printTips() function is responsible for printing a menu of available options for executing different stages of a protocol.
func printTips() {
	fmt.Println("\nConnection is completed, please type the name of stage you want to execute:(e.g. KeyGen)")
	fmt.Println("[-] KeyGen")
	fmt.Println("[-] Sign")
	fmt.Println("[-] Ctrl+c to exit")
	fmt.Printf(">>> ")
}

// `LocalConn` struct embeds the `communication.LocalConn` and includes pre-parameters for the key generation.
type LocalConn struct {
	communication.LocalConn
	Preparams keygen.LocalPreParams
}

// The `PreparePrePramas` method generates pre-parameters for the key generation and sets them in the `LocalConn` instance.
func (conn *LocalConn) PreparePrePramas() {
	Preparams, _ := keygen.GeneratePreParams(1 * time.Minute)
	conn.Preparams = *Preparams
}

// The `execute` function is responsible for executing different stages of the protocol based on user input.
func execute(localConn *LocalConn) error {
	// Get the center server ID and local ID from the local connection's configuration.
	centerID := localConn.LocalConfig.CenterServerID
	localID := localConn.LocalConfig.LocalPartyID
	//  Determine the stage of the protocol based on whether the local ID matches the center server ID.
	// If they match, it means that the local participant is responsible for initiating the protocol.
	var stage string
	if centerID == localID {
		// If the local ID is the center server ID, prompt the user to enter the stage of the protocol.
		printTips()
		// Read the input from the command line and store it in the variable "stage".
		_, err := fmt.Scanln(&stage)
		if err != nil {
			log.Errorln("Scanln is wrong!")
		}
		// Broadcast the stage instruction to all participants
		err = localConn.BroadcastSend([]byte(stage))
		if err != nil {
			log.Errorln("fail to BroadcastSend")
			log.Errorln("fail to BroadcastSend")
			return err
		}
		log.Infof("step into stage %v", stage)
		common.Logger.Infof("step into stage %v", stage)

	} else {
		// If the local ID is not the center server ID, listen for instructions from the center server.
		// Receive the data from the center server using localConn.P2pReceive() and store it in the variable "data".
		// The received data represents the current stage of the protocol.
		data, err := localConn.P2pReceive(centerID)
		if err != nil {
			log.Errorln("fail to receive instruction from center server %v", centerID)
			//	log.Errorf("fail to receive instruction from center server %v", centerID)
			return err
		}
		stage = string(data[:])
		common.Logger.Infof("step into stage %v", stage)
		// log.Infof("step into stage %v", stage)
	}
	// Call the stepIntoStage function to perform the protocol steps corresponding to the stage
	err := stepIntoStage(localConn, stage)
	// 处理err
	if err != nil {
		log.Errorln("stepIntoStage has error!")
	}
	return nil
}

// The `KeyGen` function performs the key generation protocol.
func KeyGen(localConn *LocalConn, outCh chan tss.Message, endCh chan keygen.LocalPartySaveData) error {
	log.Infof("step into KeyGen func")
	// fmt.Printf("step into KeyGen func")
	// 创建errCh存储错误信息
	errCh := make(chan *tss.Error, localConn.LocalConfig.Threshold)
	// 定义updater更新localparty状态
	updater := test.SharedPartyUpdater
	// 创建一个localparty
	var P *keygen.LocalParty
	P = keygen.NewLocalParty(localConn.Params, outCh, endCh).(*keygen.LocalParty)
	go func(P *keygen.LocalParty) {
		println(P.PartyID().Index, P.PartyID().Moniker, P.PartyID().Id)
		// Call P.Start() to start the execution of the LocalParty
		if err := P.Start(); err != nil {
			errCh <- err
		}
	}(P)
	// Create variables to keep track of received messages and an endSignal channel.
	ReceiveNum := 0
	endSignal := make(chan bool)
	// receive message
	go func() {
		log.Infof("start receive message")
		// Define a flag to indicate when to exit the loop
		flag := false
		for {
			// If the flag is true, it means the loop should exit
			if flag {
				break
			}
			select {
			// Receive a message from the endSignal channel to indicate that the function has finished.
			case <-endSignal:
				log.Infof("message receive finished")
				// Set the flag to true to exit the loop.
				flag = true
			default:
				// Check if ReceiveNum is greater than or equal to 4.
				if ReceiveNum >= 4 {
					break
				}
				ReceiveNum++
				log.Infof("ReceiveNum is %v", ReceiveNum)
				msgMap, err := localConn.BroadcastReceive2()
				// log.Infof("begin BroadcastReceive")
				if err != nil {
					log.Errorln("fail BroadcastReceive")
					return
				}
				wg := sync.WaitGroup{}
				wg.Add(len(msgMap))
				// iterate over the received messages
				for id, msgByte := range msgMap {
					// process each message in parallel using goroutines.
					go func(id string, msgByte []byte) {
						defer wg.Done()
						from := localConn.GetPartyIDFromID(id)
						BroadcastCase := communication.IsBroadcast(msgByte)
						ParsedMessage, err := tss.ParseWireMessage(msgByte[4:], from, BroadcastCase)
						if err != nil {
							log.Errorln("fail to tss.ParseWireMessage")
						}
						go updater(P, ParsedMessage, errCh)
					}(string(id), msgByte)
				}
				wg.Wait()
			}
		}
	}()
	// send message
keygen:
	for {
		select {
		// Receive an error from the errCh channel, exit the loop
		case err := <-errCh:
			log.Errorln("error", err)
			return err
			// Receive a message from the outCh channel, either broadcastsend or p2psend it
		case msg := <-outCh:
			// Serialize the message into a byte array
			BroadcastCase := msg.IsBroadcast()
			MSG, _, err := msg.WireBytes()
			if err != nil {
				log.Errorln("msg.WireBytes failed", err)
			}
			// Check if the message should be broadcasted
			if msg.IsBroadcast() { // 广播
				log.Infof("begin broadcast!")
				err := localConn.BroadcastSend2(MSG, BroadcastCase)
				if err != nil {
					return err
				}
			} else {
				// Get the target participant to send the message to
				to := msg.GetTo()[0]
				// Send the serialized message to the target participant
				log.Infof("p2psend to %s", to.Id)
				err := localConn.P2pSend2(to.Id, MSG, BroadcastCase)
				if err != nil {
					return err
				}
			}
		case save := <-endCh: // Receive a message from endCh indicating KeyGen completion
			log.Infof("localKeyGen finished")
			// store the generated key information in localconn
			localConn.KeyGenResult = save
			// Signal completion using endSignal
			endSignal <- true
			// Exit the KeyGen loop
			break keygen
		default:
		}
	}
	log.Infoln("successfully keygen")
	return nil
}

// The `Signing` function performs the key generation protocol.
func Signing(localConn *LocalConn, outCh chan tss.Message, endCh chan common.SignatureData) error {
	log.Infof("step into Signing func")
	// Create an error channel to receive error messages and exit if errors occur.
	errCh := make(chan *tss.Error, localConn.LocalConfig.Threshold)
	// Update the participant's state.
	updater := test.SharedPartyUpdater
	var P *signing.LocalParty
	msg := big.NewInt(int64(224))
	// Get the key generation phase result.
	key, ok := localConn.KeyGenResult.(keygen.LocalPartySaveData)
	if !ok {
		println("localConn.KeyGenResult has wrong!")
	}
	// Create a local signing party (P) with the message, parameters, key, output channel, and end channel.
	P = signing.NewLocalParty(msg, localConn.Params, key, outCh, endCh).(*signing.LocalParty)
	// Start the local signing party in a goroutine.
	go func(P *signing.LocalParty) {
		if err := P.Start(); err != nil {
			errCh <- err
		}
	}(P)
	// Count the number of received messages and create an endSignal channel.
	ReceiveNum := 0
	endSignal := make(chan bool)
	go func() {
		log.Infof("start receive message in Signing")
		// Define a flag to indicate when to exit the loop
		flag := false
		for {
			// if the flag is true, it means the loop should exit
			if flag {
				break
			}
			select {
			// Receive a message from the endSignal channel to indicate that the function has finished.
			case <-endSignal:
				log.Infof("message receive finished in Signing")
				// set flag to true to exit the loop
			default:
				// Check if ReceiveNum is greater than or equal to 10.
				if ReceiveNum >= 10 {
					break
				}
				ReceiveNum++
				log.Infof("ReceiveNum is %v", ReceiveNum)
				msgMap, err := localConn.BroadcastReceive2()
				if err != nil {
					log.Errorln("fail BroadcastReceive in Signing")
					return
				}
				wg := sync.WaitGroup{}
				wg.Add(len(msgMap))
				// iterate over the received messages
				for id, msgByte := range msgMap {
					// process each message in parallel using goroutines.
					go func(id string, msgByte []byte) {
						defer wg.Done()
						from := localConn.GetPartyIDFromID(id)
						BroadcastCase := communication.IsBroadcast(msgByte)
						ParsedMessage, err := tss.ParseWireMessage(msgByte[4:], from, BroadcastCase)
						if err != nil {
							log.Errorln("fail to tss.ParseWireMessage")
						}
						// Call the updater function to handle the message
						go updater(P, ParsedMessage, errCh)
					}(string(id), msgByte)
				}
				wg.Wait()
			}
		}

	}()
	// send message in signing
signing:
	for {
		select {
		// Receive an error from errCh, log the error, and return it.
		case err := <-errCh:
			log.Errorln("error", err)
			return err
			// Handle  messages (either p2psend or broadcastsend).
		case msg := <-outCh:
			BroadcastCase := msg.IsBroadcast()
			MSG, _, err := msg.WireBytes()
			if err != nil {
				log.Errorln("msg.WireBytes failed", err)
			}
			// Determine whether it's a broadcast message.
			if msg.IsBroadcast() { // 广播

				log.Infof("begin broadcast in sign!")
				// Send the message to all participants except the local participant.
				err := localConn.BroadcastSend2(MSG, BroadcastCase)
				if err != nil {
					return err
				}
			} else { // p2psend
				to := msg.GetTo()[0]
				// Send the serialized message to the target participant.
				log.Infof("p2psend to %s", to.Id)
				err := localConn.P2pSend2(to.Id, MSG, BroadcastCase)
				if err != nil {
					return err
				}

			}
			// Receive a message from endCh, indicating that the local participant has finished signing.
		case localSignResult := <-endCh:
			// save the signature result in localConn
			localConn.SignResult = localSignResult
			// Signal the end of the process.
			endSignal <- true
			break signing
		}
	}
	log.Infoln("successfully key sign")
	return nil
}

func stepIntoStage(localConn *LocalConn, stage string) error {
	log.Infof("func step into stage")
	// println("func step into stage")
	// Use a switch statement to determine the stage of the protocol based on the given stage string.
	switch stage {
	case "KeyGen":
		outCh := make(chan tss.Message, localConn.LocalConfig.TotalPartyCount)
		endCh := make(chan keygen.LocalPartySaveData, localConn.LocalConfig.TotalPartyCount)
		// Call the KeyGen function to execute the protocol logic for KeyGen
		err := KeyGen(localConn, outCh, endCh)
		if err != nil {
			log.Errorln("fail KeyGen", err)
			return err
		}
		break
	case "Sign":
		outCh := make(chan tss.Message, localConn.LocalConfig.TotalPartyCount)
		endCh := make(chan common.SignatureData, localConn.LocalConfig.TotalPartyCount)
		err := Signing(localConn, outCh, endCh)
		if err != nil {
			log.Errorln("fail signing", err)
			return err
		}
		break
	default:
		log.Errorln("Invalid input!")
	}
	return nil
}
func ClusterDeploymentTest() {
	// set up the communication
	localConn := &LocalConn{
		LocalConn: communication.SetUpConn(),
	}
	// prepare pre-parameters
	localConn.PreparePrePramas()
	// execute the protocol
	for {
		err := execute(localConn)
		if err != nil {
			log.Errorln("execute is wrong!")
		}
	}
}
func main() {
	// call the ClusterDeploymentTest function to start multi-party deployment testing
	ClusterDeploymentTest()
}
