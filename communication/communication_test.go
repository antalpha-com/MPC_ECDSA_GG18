// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package communication

import (
	"os"
	"path"
	"runtime"
	"testing"
	"time"

	// "MPC_ECDSA/pkg/party"
	// "MPC_ECDSA/pkg/protocol"
	// pb "MPC_ECDSA/proto/MPC_ECDSA/proto"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/fxamacker/cbor/v2"
	log "github.com/sirupsen/logrus"
)

func Chdir() (err error) {
	err = os.Chdir("../")
	return
}
func getCurrentPath() string {
	_, filename, _, _ := runtime.Caller(1)

	return path.Dir(filename)
}
func TestSetUpConn(t *testing.T) {
	Chdir()
	conn := SetUpConn()
	common.Logger.Infof("conn is %+v\n", conn)
}

type Atest struct {
	A string
	B Btest
}
type AAtest struct {
	A1 bool
	A  string
	B  Btest
}
type Btest struct {
	C int32
	D Ctest
}

type Ctest struct {
	F string
}

func TestComplexStruct_Send2(t *testing.T) {
	Chdir()
	localConn := SetUpConn()
	oID := 'a'
	bb := true
	var test Atest
	test.A = "sxm"
	test.B.C = 24
	test.B.D.F = "okk"

	data, _ := cbor.Marshal(test)
	log.Infof("test p2p send to %v message = %+v", oID, test)

	err := localConn.P2pSend2(string(partyID(oID)), data, bb)
	if err != nil {
		log.Errorln(err)
		return
	}

}
func TestComplexStruct_Recv2(t *testing.T) {
	Chdir()
	localConn := SetUpConn()
	oID := 'b'

	data, err := localConn.P2pReceive2(string(partyID(oID)))
	if err != nil {
		log.Errorln(err)
		return
	}
	Test := IsBroadcast(data)
	println(Test)
	// 测试一下marshal为bytes再unmarshall为结构体
	testNew := &Atest{}
	err = cbor.Unmarshal(data[4:], testNew)
	if err != nil {
		log.Errorf("unmarshall err %+v", err)
	}
	log.Infof("testNew is %+v\n", testNew)
}

// type partyID string
// b发给a
func TestComplexStruct_Send(t *testing.T) {
	Chdir()
	localConn := SetUpConn()
	oID := 'a'

	var test Atest
	test.A = "sxm"
	test.B.C = 24
	test.B.D.F = "okk"

	data, _ := cbor.Marshal(test)
	log.Infof("test p2p send to %v message = %+v", oID, test)

	err := localConn.P2pSend(string(partyID(oID)), data)
	if err != nil {
		log.Errorln(err)
		return
	}

}

// b发给a
func TestComplexStruct_Recv(t *testing.T) {
	Chdir()
	localConn := SetUpConn()
	oID := 'b'

	data, err := localConn.P2pReceive(string(partyID(oID)))
	if err != nil {
		log.Errorln(err)
		return
	}

	// 测试一下marshal为bytes再unmarshall为结构体
	testNew := &Atest{}
	err = cbor.Unmarshal(data, testNew)
	if err != nil {
		log.Errorf("unmarshall err %+v", err)
	}
	log.Infof("testNew is %+v\n", testNew)
}

// 模拟从本地单播发送一个消息给其他参与方
// 模拟从本地广播发送一个消息给其他所有参与方
func TestLocalConn_BroadcastSendRecv(t *testing.T) {
	Chdir()
	localConn := SetUpConn()

	var test Atest
	test.A = string(localConn.LocalConfig.LocalPartyID)
	test.B.C = 24
	test.B.D.F = localConn.LocalConfig.LocalAddr

	data, err := cbor.Marshal(test)
	if err != nil {
		log.Errorln("fail Marshal")
	}

	var msgMap map[partyID][]byte
	go func(msgMap *map[partyID][]byte) {

		*msgMap, err = localConn.BroadcastReceive()
		if err != nil {
			log.Errorln("fail BroadcastReceive")
			return
		}

		for id, msgByte := range *msgMap {
			newAtest := &Atest{}
			err = cbor.Unmarshal(msgByte, newAtest)
			if err != nil {
				log.Errorln("fail unmarshal")
			}
			log.Infof("party %v received message %+v\n", id, newAtest)
		}

	}(&msgMap)

	err = localConn.BroadcastSend(data)
	if err != nil {
		log.Errorln("fail BroadcastSend")
		return
	}

	time.Sleep(10 * time.Second)

}

func TestLocalConn_BroadcastReceive(t *testing.T) {
	Chdir()
	localConn := SetUpConn()

	receiveMsgMap, err := localConn.BroadcastReceive()
	if err != nil {
		log.Errorln("fail BroadcastReceive")
		return
	}

	msgMap := make(map[partyID]Atest, len(receiveMsgMap))
	for fromID, byteMsg := range receiveMsgMap {
		newAtest := new(Atest)
		err := cbor.Unmarshal(byteMsg, newAtest)
		if err != nil {
			return
		}
		msgMap[fromID] = *newAtest
		log.Infof("msg from %v is %+v", fromID, newAtest)
	}

}
