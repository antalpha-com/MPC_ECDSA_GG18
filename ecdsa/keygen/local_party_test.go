// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	// "crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	// "math/big"
	"os"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/crypto/ecdsa"

	// "math/big"
	big "github.com/bnb-chain/tss-lib/v2/gmp"
	//	"github.com/bnb-chain/tss-lib/v2/crypto/elliptic"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	testParticipants = TestParticipants
	testThreshold    = TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func TestStartRound1Paillier(t *testing.T) {
	setUp("debug")

	pIDs := tss.GenerateTestPartyIDs(1)
	p2pCtx := tss.NewPeerContext(pIDs)
	threshold := 1
	params := tss.NewParameters(tss.EC(), p2pCtx, pIDs[0], len(pIDs), threshold)

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	var lp *LocalParty
	out := make(chan tss.Message, len(pIDs))
	if 0 < len(fixtures) {
		lp = NewLocalParty(params, out, nil, fixtures[0].LocalPreParams).(*LocalParty)
	} else {
		lp = NewLocalParty(params, out, nil).(*LocalParty)
	}
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}
	<-out

	// Paillier modulus 2048 (two 1024-bit primes)
	// round up to 256, it was used to be flaky, sometimes comes back with 1 byte less
	len1 := len(lp.data.PaillierSK.LambdaN.Bytes())
	len2 := len(lp.data.PaillierSK.PublicKey.N.Bytes())
	if len1%2 != 0 {
		len1 = len1 + (256 - (len1 % 256))
	}
	if len2%2 != 0 {
		len2 = len2 + (256 - (len2 % 256))
	}
	assert.Equal(t, 2048/8, len1)
	assert.Equal(t, 2048/8, len2)
}

func TestFinishAndSaveH1H2(t *testing.T) {
	setUp("debug")

	pIDs := tss.GenerateTestPartyIDs(1)
	p2pCtx := tss.NewPeerContext(pIDs)
	threshold := 1
	params := tss.NewParameters(tss.EC(), p2pCtx, pIDs[0], len(pIDs), threshold)

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	var lp *LocalParty
	out := make(chan tss.Message, len(pIDs))
	if 0 < len(fixtures) {
		lp = NewLocalParty(params, out, nil, fixtures[0].LocalPreParams).(*LocalParty)
	} else {
		lp = NewLocalParty(params, out, nil).(*LocalParty)
	}
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}

	// RSA modulus 2048 (two 1024-bit primes)
	// round up to 256
	len1 := len(lp.data.H1j[0].Bytes())
	len2 := len(lp.data.H2j[0].Bytes())
	len3 := len(lp.data.NTildej[0].Bytes())
	if len1%2 != 0 {
		len1 = len1 + (256 - (len1 % 256))
	}
	if len2%2 != 0 {
		len2 = len2 + (256 - (len2 % 256))
	}
	if len3%2 != 0 {
		len3 = len3 + (256 - (len3 % 256))
	}
	// 256 bytes = 2048 bits
	assert.Equal(t, 256, len1, "h1 should be correct len")
	assert.Equal(t, 256, len2, "h2 should be correct len")
	assert.Equal(t, 256, len3, "n-tilde should be correct len")
	assert.NotZero(t, lp.data.H1i, "h1 should be non-zero")
	assert.NotZero(t, lp.data.H2i, "h2 should be non-zero")
	assert.NotZero(t, lp.data.NTildei, "n-tilde should be non-zero")
}

func TestBadMessageCulprits(t *testing.T) {
	setUp("debug")

	pIDs := tss.GenerateTestPartyIDs(2)
	p2pCtx := tss.NewPeerContext(pIDs)
	params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[0], len(pIDs), 1)

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	var lp *LocalParty
	out := make(chan tss.Message, len(pIDs))
	if 0 < len(fixtures) {
		lp = NewLocalParty(params, out, nil, fixtures[0].LocalPreParams).(*LocalParty)
	} else {
		lp = NewLocalParty(params, out, nil).(*LocalParty)
	}
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}

	badMsg, _ := NewKGRound1Message(pIDs[1], zero, &paillier.PublicKey{N: zero}, zero, zero, zero, new(dlnproof.Proof), new(dlnproof.Proof))
	ok, err2 := lp.Update(badMsg)
	t.Log(err2)
	assert.False(t, ok)
	if !assert.Error(t, err2) {
		return
	}
	assert.Equal(t, 1, len(err2.Culprits()))
	assert.Equal(t, pIDs[1], err2.Culprits()[0])
	assert.Equal(t,
		"task ecdsa-keygen, party {0,P[1]}, round 1, culprits [{1,2}]: message failed ValidateBasic: Type: binance.tsslib.ecdsa.keygen.KGRound1Message, From: {1,2}, To: all",
		err2.Error())
}

func TestE2EConcurrentAndSaveFixtures(t *testing.T) {
	setUp("info")

	// tss.SetCurve(elliptic.P256())

	threshold := testThreshold
	// 加载密钥生成的测试用例
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		// 生成一组测试用的参与者ID
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}
	// 使用参与者 ID pIDs 创建了一个新的 PeerContext，用于管理参与者之间的通信和协作
	p2pCtx := tss.NewPeerContext(pIDs)
	// 创建了一个长度为 len(pIDs) 的空的 LocalParty 切片，用于存储参与者的本地实例
	parties := make([]*LocalParty, 0, len(pIDs))
	// 创建channel errCH,用于传递错误
	errCh := make(chan *tss.Error, len(pIDs))
	// 创建channel outCH,用于传递消息
	outCh := make(chan tss.Message, len(pIDs))
	// 创建channel endCH,用于本地实例保存数据
	endCh := make(chan LocalPartySaveData, len(pIDs))
	// SharedPartyUpdater 函数的功能是根据传入的消息更新共享状态的参与者
	updater := test.SharedPartyUpdater
	// runtime.NumGoroutine() 函数用于获取当前运行时的 Goroutine 数量，
	// 即正在并发执行的 Go 协程的数量。
	// 通过将初始 Goroutine 数量保存在 startGR 中，
	// 我们可以在后续的代码中对 Goroutine 数量的变化进行比较。
	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		// params 使用 tss.NewParameters 函数创建，该函数接受一些参数来构建一个新的参数对
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		// do not use in untrusted setting
		// params.SetNoProofMod()
		// // do not use in untrusted setting
		// params.SetNoProofFac()
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*LocalParty)
		} else {
			// 直接创建没有额外参数的 LocalParty。
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		}
		// P 添加到 parties 切片中
		parties = append(parties, P)
		go func(P *LocalParty) {
			// 调用 P.Start() 方法来启动 LocalParty 的执行
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
keygen:
	for {
		// 打印当前gotoutine的数量
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		// select 语句，用于监听多个通道的消息，并处理其中的一个消息
		select {
		// 从errCh通道接收到错误消息，结束keygen
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			// 目标消息为nil,广播消息
			if dest == nil { // broadcast!
				// 遍历parties中的每个元素
				for _, P := range parties {
					// 去除自身
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					// 并发调用updater函数
					// 将目标索引对应的parties数组中的元素作为参数传递给updater函数。
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				// 目标信息不为nil，表示点对点消息
				// 检查目标索引是否等于发送者索引
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				// 并发方式调用updater函数，将目标索引对应的parties数组中的元素作为参数传递给updater函数。
				go updater(parties[dest[0].Index], msg, errCh)
			}
			// 如果从endCh通道接收到消息（save := <-endCh），代码会执行一系列操作来处理结束消息
		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			// 保存数据中的原始索引。
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			// 将保存的测试夹具文件写入磁盘。
			tryWriteTestFixtureFile(t, index, save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// combine shares for each Pj to get u
				u := new(big.Int)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					// 对于parties数组中的每个元素，执行一系列验证和断言操作，以确保分享的重构和其他相关属性的正确性。
					for _, P := range parties {
						vssMsgs := P.temp.kgRound2Message1s
						share := vssMsgs[j].Content().(*KGRound2Message1).Share
						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        P.PartyID().KeyInt(),
							Share:     new(big.Int).SetBytes(share),
						}
						pShares = append(pShares, shareStruct)
					}
					uj, err := pShares[:threshold+1].ReConstruct(tss.S256())
					assert.NoError(t, err, "vss.ReConstruct should not throw error")
					// uG test: u*G[j] == V[0]
					// assert.Equal(t, uj, Pj.temp.ui)
					if uj.Cmp(Pj.temp.ui) != 0 {
						assert.Errorf(t, err, "uj not equal pj.temp.ui")
					}
					uG := crypto.ScalarBaseMult(tss.EC(), uj)
					assert.True(t, uG.Equals(Pj.temp.vs[0]), "ensure u*G[j] == V_0")

					// xj tests: BigXj == xj*G
					xj := Pj.data.Xi
					gXj := crypto.ScalarBaseMult(tss.EC(), xj)
					BigXj := Pj.data.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, err := pShares[:threshold].ReConstruct(tss.S256())
						assert.NoError(t, err)
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := tss.EC().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}
					u = new(big.Int).Add(u, uj)
				}

				// build ecdsa key pair
				pkX, pkY := save.ECDSAPub.X(), save.ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				sk := ecdsa.PrivateKey{
					PublicKey: pk,
					D:         u,
				}
				// 公钥测试
				// test pub key, should be on curve and match pkX, pkY
				assert.True(t, sk.IsOnCurve(pkX, pkY), "public key must be on curve")

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				ourPkX, ourPkY := tss.EC().ScalarBaseMult(u.Bytes())
				assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
				assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same ECDSA public key
				for _, Pj := range parties {
					assert.Equal(t, pkX, Pj.data.ECDSAPub.X())
					assert.Equal(t, pkY, Pj.data.ECDSAPub.Y())
				}
				t.Log("Public key distribution test done.")

				// test sign/verify
				// 签名验证
				data := make([]byte, 32)
				for i := range data {
					data[i] = byte(i)
				}
				r, s, err := ecdsa.Sign(rand.Reader, &sk, data)
				assert.NoError(t, err, "sign should not throw an error")
				ok := ecdsa.Verify(&pk, data, r, s)
				assert.True(t, ok, "signature should be ok")
				t.Log("ECDSA signing test done.")

				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}

func tryWriteTestFixtureFile(t *testing.T, index int, data LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(index)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}
