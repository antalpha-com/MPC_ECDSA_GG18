// The package communication is used to establish  communication connection

package communication

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	log "github.com/sirupsen/logrus"

	// "math/big"
	big "github.com/bnb-chain/tss-lib/v2/gmp"
	// "github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type MessageWrapperPartyID struct {
	Id      string `json:"Id"`
	Moniker string `json:"Moniker"`
	Key     []byte `json:"Key"`
}

type PartyIDIMK struct {
	MessageWrapperPartyID MessageWrapperPartyID `json:"MessageWrapperPartyID"`
	Index                 int                   `json:"Index"`
}

// type MessageWrapperPartyIDAfter struct {
// 	Id      string `json:"Id"`
// 	Moniker string `json:"Moniker"`
// 	Key     []byte `json:"Key"`
// }

type PartyIDIMKAfter struct {
	MessageWrapperPartyIDAfter *MessageWrapperPartyID
	Index                      int
}

type Party struct {
	ID       string `json:"id"`
	Addr     string `json:"addr"`
	ConnRole string `json:"connRole"`
}
type LocalConfig struct {
	CaPath         string `json:"caPath"`
	ClientCertPath string `json:"clientCertPath"`
	ServerCertPath string `json:"serverCertPath"`
	ClientKeyPath  string `json:"clientKeyPath"`
	ServerKeyPath  string `json:"serverKeyPath"`
	TimeOutSecond  int    `json:"timeOutSecond"`
	CenterServerID string `json:"centerServerID"`
	// UseMnemonic           bool         `json:"useMnemonic"`
	PartyIDs        []string `json:"partyIDs"`
	LocalPartyID    string   `json:"localPartyID"`
	OtherPartyIDs   []string `json:"otherPartyIDs"`
	LocalAddr       string   `json:"localAddr"`
	TotalPartyCount int      `json:"totalPartyCount"`
	Threshold       int      `json:"threshold"`
	// MessageToSign         string       `json:"messageToSign"`
	LocalCanBeServer      bool         `json:"localCanBeServer"`
	PartyIDsIMK           []PartyIDIMK `json:"partyIDsIMK"`
	LocalPartyIDIMK       PartyIDIMK   `json:"localPartyIDIMK"`
	OtherPartyIDsIMK      []PartyIDIMK `json:"otherPartyIDsIMK"`
	OtherPartyInfo        []Party      `json:"otherPartyInfo"`
	PartyIDsIMKAfter      []PartyIDIMKAfter
	LocalPartyIDIMKAfter  PartyIDIMKAfter
	OtherPartyIDsIMKAfter []PartyIDIMKAfter
}

type partyID string

type LocalConn struct {
	LocalConfig     LocalConfig
	Params          *tss.Parameters
	ResharingParams *tss.ReSharingParameters
	PartIDs         tss.SortedPartyIDs
	IDConnMap       map[partyID]net.Conn
	KeyGenResult    interface{}
	SignResult      interface{}
	// PreSign interface{}
}

func (connConf *LocalConn) GetPartyIDFromID(ID string) *tss.PartyID {
	for _, p := range connConf.PartIDs {
		if p.Id == ID {
			return p
		}
	}
	return nil
}

// 定义一个函数，计算参数并存入localConn
func (connConf *LocalConn) PrepareParams() {
	curve := tss.S256()
	// 从配置文件中获取门限值
	threshold := connConf.LocalConfig.Threshold
	// 从配置文件中获取本地partyID
	// 将PartyIDIMK类型转化为tss.PartyID类型
	id := connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Id
	// println("id:",id)
	common.Logger.Infof("id:", id)
	moniker := connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Moniker
	// println("moniker",moniker)
	// uniqueKey:=connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Key
	key := new(big.Int)
	key.SetBytes(connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Key)

	thisParty := tss.NewPartyID(id, moniker, key)
	thisParty.Index = connConf.LocalConfig.LocalPartyIDIMK.Index

	// id如何从配置文件中获取？并且保持格式一致？
	ids := tss.UnSortedPartyIDs{}

	for _, temp := range connConf.LocalConfig.PartyIDsIMK {
		i := temp.MessageWrapperPartyID.Id
		m := temp.MessageWrapperPartyID.Moniker
		tempkey := new(big.Int)
		tempkey.SetBytes(temp.MessageWrapperPartyID.Key)
		tempParty := tss.NewPartyID(i, m, tempkey)
		ids = append(ids, tempParty)
	}
	//	ids = connConf.LocalConfig.PartyIDsIMK
	parties := tss.SortPartyIDs(ids)
	connConf.PartIDs = parties

	ctx := tss.NewPeerContext(parties)

	// 从配置文件中获取其他partyID
	len := connConf.LocalConfig.TotalPartyCount

	println("config.index:", connConf.LocalConfig.LocalPartyIDIMK.Index)
	connConf.Params = tss.NewParameters(curve, ctx, thisParty, len, threshold)

	println("index", connConf.Params.PartyID().Index, "moniker", connConf.Params.PartyID().Moniker, "id", connConf.Params.PartyID().Id)

	fmt.Printf("%+v\n", connConf.Params)
}
func (connConf *LocalConn) PrepareResharingParams() {
	curve := tss.S256()
	// 从配置文件中获取门限值
	threshold := connConf.LocalConfig.Threshold
	newThreshold := connConf.LocalConfig.Threshold
	PartyCount := connConf.LocalConfig.TotalPartyCount
	newPartyCount := connConf.LocalConfig.TotalPartyCount
	// 从配置文件中获取本地partyID
	// 将PartyIDIMK类型转化为tss.PartyID类型
	id := connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Id
	// common.Logger.Infof("id:", id)
	moniker := connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Moniker
	// uniqueKey:=connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Key
	// key := big.NewInt(int64(connConf.LocalConfig.LocalPartyIDIMK.Index))

	key := new(big.Int)
	key.SetBytes(connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Key)

	thisParty := tss.NewPartyID(id, moniker, key)
	thisParty.Index = connConf.LocalConfig.LocalPartyIDIMK.Index
	// id如何从配置文件中获取？并且保持格式一致？
	ids := tss.UnSortedPartyIDs{}
	for _, temp := range connConf.LocalConfig.PartyIDsIMK {
		i := temp.MessageWrapperPartyID.Id
		m := temp.MessageWrapperPartyID.Moniker
		tempkey := new(big.Int)
		tempkey.SetBytes(temp.MessageWrapperPartyID.Key)
		tempParty := tss.NewPartyID(i, m, tempkey)
		ids = append(ids, tempParty)
	}
	//	ids = connConf.LocalConfig.PartyIDsIMK
	parties := tss.SortPartyIDs(ids)
	ctx := tss.NewPeerContext(parties)
	newctx := tss.NewPeerContext(parties)
	// 从配置文件中获取其他partyID
	connConf.ResharingParams = tss.NewReSharingParameters(curve, ctx, newctx, thisParty, PartyCount, threshold, newPartyCount, newThreshold)
}

// LoadCertPool function loads a certificate authority (CA) file and creates a new x509.CertPool
func LoadCertPool(caFile string) (*x509.CertPool, error) {
	// Read the content of the CA file
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	// Create a new CertPool
	pool := x509.NewCertPool()
	// Append the certificates from the PEM content to the CertPool
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("pool append certs from pem failed")
	}
	return pool, nil
}

// LoadConfig method is responsible for loading the configuration
func (connConf *LocalConn) LoadConfig() error {
	jsonFile, err := os.Open("./config.json")
	if err != nil {
		common.Logger.Error("fail open config.json")
		// log.Errorln("fail open config.json")
		return err
	}
	common.Logger.Infof("successfully open config.json")
	// log.Infoln("successfully open config.json")
	defer jsonFile.Close()
	// Read the contents of the file
	byteValue, _ := io.ReadAll(jsonFile)

	// Unmarshal the JSON data into the LocalConfig struct of the LocalConn instance
	err = json.Unmarshal(byteValue, &connConf.LocalConfig)
	if err != nil {
		common.Logger.Error("fail unmarshal config.json")
		// log.Errorln("fail unmarshal config.json")
		return err
	}
	common.Logger.Infof("done unmarshal config to struct")
	// log.Infoln("done unmarshal config to struct")

	// byteArray := []byte(connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Key)
	TempMessageWrapperPartyIDAfter := &MessageWrapperPartyID{
		Id:      connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Id,
		Moniker: connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Moniker,
		Key:     connConf.LocalConfig.LocalPartyIDIMK.MessageWrapperPartyID.Key,
	}
	connConf.LocalConfig.LocalPartyIDIMKAfter = PartyIDIMKAfter{
		MessageWrapperPartyIDAfter: TempMessageWrapperPartyIDAfter,
		Index:                      connConf.LocalConfig.LocalPartyIDIMK.Index,
	}

	for _, temp := range connConf.LocalConfig.OtherPartyIDsIMK {
		TempMessageWrapperPartyIdAfter := &MessageWrapperPartyID{
			Id:      temp.MessageWrapperPartyID.Id,
			Moniker: temp.MessageWrapperPartyID.Moniker,
			Key:     temp.MessageWrapperPartyID.Key,
		}
		connConf.LocalConfig.OtherPartyIDsIMKAfter = append(connConf.LocalConfig.OtherPartyIDsIMKAfter, PartyIDIMKAfter{
			MessageWrapperPartyIDAfter: TempMessageWrapperPartyIdAfter,
			Index:                      connConf.LocalConfig.LocalPartyIDIMK.Index,
		})
	}
	return nil
}

// SetUpConn function is responsible for setting up the connection
func SetUpConn() LocalConn {
	// Load the configuration file
	var conn LocalConn
	conn.LoadConfig()

	conn.PrepareParams()
	conn.PrepareResharingParams()
	// // Start the server to establish connections with other parties
	conn.StartServer()
	return conn
}

// LoadTLSConfig function loads a TLS configuration by loading a certificate authority (CA) file, a certificate file, and a key file
func LoadTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	// Load the certificate pool from the CA file
	pool, err := LoadCertPool(caFile)
	if err != nil {
		return nil, fmt.Errorf("load cert pool from (%s): %v", caFile, err)
	}
	// Load the X.509 key pair from the certificate and key files
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load x509 key pair from (%s, %s): %v", certFile, keyFile, err)
	}
	// Create a new TLS config with the loaded certificate pool and key pair
	cfg := &tls.Config{
		// RootCAs and ClientCAs are set to the loaded certificate pool.
		RootCAs:   pool,
		ClientCAs: pool,
		// ClientAuth is set to tls.RequireAndVerifyClientCert, which requires and verifies the client certificate.
		ClientAuth: tls.RequireAndVerifyClientCert,
		// MinVersion is set to tls.VersionTLS12, indicating the minimum TLS version to use.
		MinVersion: tls.VersionTLS12,
		// Certificates is set to an array containing the loaded certificate.
		Certificates: []tls.Certificate{cert},
	}
	return cfg, nil
}

// The StartServer function is used to establish connections between parties.
func (connConf *LocalConn) StartServer() error {
	// log.Infoln("start build connection between parties")
	common.Logger.Infof("start build connection between parties")
	timeOut := connConf.LocalConfig.TimeOutSecond
	// set a timeout for the context to ensure the function doesn't run indefinitely.
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Duration(timeOut)*time.Second)
	defer cancelCtx()

	// load the TLS configuration
	tlsConfig, err := LoadTLSConfig(connConf.LocalConfig.CaPath, connConf.LocalConfig.ServerCertPath, connConf.LocalConfig.ServerKeyPath)
	if err != nil {
		common.Logger.Error("fail load TLS config")
		return err
	}
	// retrieve localID，otherIDs，partys，and otherPartyNum from the connConf.LocalConfig.
	localID := connConf.LocalConfig.LocalPartyID
	otherIDs := connConf.LocalConfig.OtherPartyIDs
	partys := connConf.LocalConfig.OtherPartyInfo
	otherPartyNum := connConf.LocalConfig.TotalPartyCount - 1

	// connMap := make(map[party.ID]net.Conn)
	connMap := make(map[partyID]net.Conn)

	// create a channel  to control when to return from the function.
	ch := make(chan struct{}, 1)
	// doneConnPartyNum := 0

	// Establish connections as a client
	for index, oID := range otherIDs {
		// If the other party is a server, this party needs to dial as a client
		if partys[index].ConnRole == "server" {
			// Start a goroutine to act as a client and handle sending
			go func(index int, oID partyID) {
				// log.Infof("begin dial and write %v", oID)
				common.Logger.Infof("begin dial and write %v", oID)
				var conn net.Conn
				for {

					// log.Infof("dial id = %v, addr = %v", oID, partys[index].Addr)
					common.Logger.Infof("dial id = %v, addr = %v", oID, partys[index].Addr)
					conn, err = tls.Dial("tcp", partys[index].Addr, tlsConfig)

					if err == nil {
						break
					}

				}
				// Send its own ID to the other party
				for {
					// log.Infof("向 %v 写入自己的ID %v", oID, localID)
					common.Logger.Infof("writing local ID %v to %v", localID, oID)
					_, err = conn.Write([]byte(localID))
					if err != nil {
						// log.Errorln("fail write local ID")
						common.Logger.Error("fail write local ID")
						panic(err)
					}
					// log.Infof("successfully connect to %v", oID)
					common.Logger.Infof("successfully connect to %v", oID)
					// add the connection to the connMap
					connMap[oID] = conn
					break
				}
				// log.Infoln("done dial and write")
				common.Logger.Infof("done dial and write")

			}(index, partyID(oID))

		}
	}

	// Start a goroutine as a server to accept connection requests
	// If there's no fixed IP, this party cannot be a server, so it cannot listen
	if connConf.LocalConfig.LocalCanBeServer {
		go func(ctx context.Context) {
			buf := make([]byte, 1024)
			// Listen for connections
			listener, err := tls.Listen("tcp", connConf.LocalConfig.LocalAddr, tlsConfig)
			if err != nil {
				// log.Errorln("fail listen tcp")
				common.Logger.Error("fail listen tcp")
			}
			common.Logger.Infof("start listen %v\n", connConf.LocalConfig.LocalPartyID)
			defer listener.Close()

			var otherID partyID
			for {
				// accept a new connection
				conn, err := listener.Accept()
				if err != nil {
					// log.Errorln("fail read Accept")
					common.Logger.Error("fail read Accept")
				}
				// log.Infoln("accept success")
				common.Logger.Infof("accept success")
				// read the other party's ID from the connection
				n, err := conn.Read(buf)
				if err != nil {
					common.Logger.Error("fail read otherID ID")
					panic(err)
				}
				// The ID is extracted from the received bytes.
				otherID = partyID(buf[:n])

				common.Logger.Infof("successfully connect to %v", otherID)
				// add the connection to the connMap
				connMap[otherID] = conn
			}
		}(ctx)
	}

	go func() {
		// wait until all expected connections from other parties are established
		for {
			if len(connMap) == otherPartyNum {
				time.Sleep(5 * time.Second)
				ch <- struct{}{}
			}
		}

	}()

	select {
	case <-ch: // If a value is received from the ch channel, it means that all connections are set up successfully
		// log.Infof("parties set up  %v connections", otherPartyNum)
		common.Logger.Infof("parties set up  %v connections", otherPartyNum)
		connConf.IDConnMap = connMap
	case <-ctx.Done(): // If the ctx.Done() channel is closed, it means that the timeout specified in the context has elapsed.
		log.Errorln("timeout")
		common.Logger.Error("timeout")
		return err
	}
	return nil
}

// P2pSend function is used to send a message to a specific party in a point-to-point manner

func (connConf *LocalConn) P2pSend(toPartyID string, message []byte) error {
	// Prepend the size of the message to the message data
	msgSize := IntToBytes(len(message))
	message = append(msgSize, message...)
	// Write the message to the connection associated with the specified party ID
	_, err := connConf.IDConnMap[partyID(toPartyID)].Write(message)
	if err != nil {
		common.Logger.Errorf("fail send messsage to %v", toPartyID)
		log.Errorf("fail send messsage to %v", toPartyID)
		return err
	}
	return nil
}

// P2pReceive function receives a message from a specific party in a point-to-point manner.
func (connConf *LocalConn) P2pReceive(fromPartyID string) ([]byte, error) {

	buf := make([]byte, 1e6)
	conn := connConf.IDConnMap[partyID(fromPartyID)]
	size := -1
	tmpSize := 0
	n, err := conn.Read(buf)

	var tmpMsgByte []byte
	if err != nil || n <= 4 {
		// common.Logger.Error("fail read message")
		// log.Errorln("fail read message")
		return nil, err
	}
	// extract the size of the message from the first 4 bytes of the buffer.
	sizeByte := buf[:4]
	size = BytesToInt(sizeByte)
	// initialize tmpMsgByte to store the received message data, excluding the size bytes.
	tmpMsgByte = buf[4:n]
	// update tmpSize to indicate the current size of the received data.
	tmpSize = n - 4
	// enter a loop to read additional data from the connection until the size of the received data reaches the expected size
	for tmpSize < size {
		// read data into a new buffer buf and appends it to tmpMsgByte
		buf := make([]byte, 1e6)
		n, err := conn.Read(buf)
		if err != nil {
			common.Logger.Error(err)
			log.Errorln(err)
		}
		tmpMsgByte = append(tmpMsgByte, buf[:n]...)
		tmpSize += n
	}

	if err != nil {
		// common.Logger.Errorf("fail receive messsage from %v", fromPartyID)
		// log.Errorf("fail receive messsage from %v", fromPartyID)
		return nil, err
	}
	// common.Logger.Infof("receive from party %v message len is %v \n", fromPartyID, size)
	log.Infof("receive from party %v message len is %v \n", fromPartyID, size)
	return tmpMsgByte, nil
}

// BroadcastSend function sends a message to each participant individually in a broadcast manner

func (connConf *LocalConn) BroadcastSend(message []byte) error {
	for id := range connConf.IDConnMap {
		go func(id partyID) {
			// call the P2pSend function to send the message to the specified party.
			err := connConf.P2pSend(string(id), message)
			if err != nil {
				// common.Logger.Errorf("fail broadcast messsage to %v", id)
				log.Errorf("fail broadcast messsage to %v", id)
				return
			}
			// common.Logger.Infof("send to party %v message len is %v\n", id, len(message))
			// log.Infof("send to party %v message len is %v\n", id, len(message))
		}(id)

	}
	return nil
}

// BroadcastReceive function receives a message from each of the other participants in a broadcast manner.

func (connConf *LocalConn) BroadcastReceive() (map[partyID][]byte, error) {
	// create a msgMap to store the received messages from other parties
	msgMap := make(map[partyID][]byte, connConf.LocalConfig.TotalPartyCount-1)

	// initialize a mutex to control concurrent writes to the msgMap.
	var mutex sync.Mutex

	// create a WaitGroup wg to control the execution of the message receiving goroutines.
	// The number of goroutines is equal to the total number of other parties
	wg := sync.WaitGroup{}
	wg.Add(connConf.LocalConfig.TotalPartyCount - 1)

	for _, fromPartyID := range connConf.LocalConfig.OtherPartyIDs {
		go func(fromPartyID partyID, msgMap *map[partyID][]byte) {
			defer wg.Done()
			// call the P2pReceive function to receive the message from the specified party.
			receiveMsg, err := connConf.P2pReceive(string(fromPartyID))
			if err != nil {
				// common.Logger.Errorf("receive from %v errror", fromPartyID)
				log.Errorf("receive from %v errror", fromPartyID)
				return
			}
			// common.Logger.Infof("receive from %v msg", fromPartyID)
			log.Infof("receive from %v msg", fromPartyID)
			// If the message is successfully received, it locks the mutex,
			mutex.Lock()
			// update the msgMap with the received message,
			(*msgMap)[fromPartyID] = receiveMsg
			// unlock the mutex.
			mutex.Unlock()
		}(partyID(fromPartyID), &msgMap)

	}
	wg.Wait()
	// common.Logger.Info("received all broadcast messages")
	// log.Infoln("received all broadcast messages")
	return msgMap, nil
}

func (connConf *LocalConn) P2pSend2(toPartyID string, message []byte, isbroadcast bool) error {
	Bo := -1
	// bool to int
	if isbroadcast {
		Bo = 1
	} else {
		Bo = 0
	}
	isbroadcastToByte := IntToBytes(Bo)
	// Prepend the size of the message to the message data
	msgSize := IntToBytes(len(message))
	message = append(msgSize, message...)
	message = append(isbroadcastToByte, message...)

	// Write the message to the connection associated with the specified party ID
	_, err := connConf.IDConnMap[partyID(toPartyID)].Write(message)
	if err != nil {
		common.Logger.Errorf("fail send messsage to %v", toPartyID)
		log.Errorf("fail send messsage to %v", toPartyID)
		return err
	}
	return nil
}
func (connConf *LocalConn) P2pSendandReceive2(toPartyID string, message []byte, isbroadcast bool) error {
	Bo := -1
	// bool to int
	if isbroadcast {
		Bo = 1
	} else {
		Bo = 0
	}
	isbroadcastToByte := IntToBytes(Bo)
	// Prepend the size of the message to the message data
	msgSize := IntToBytes(len(message))
	message = append(msgSize, message...)
	message = append(isbroadcastToByte, message...)

	// Write the message to the connection associated with the specified party ID
	_, err := connConf.IDConnMap[partyID(toPartyID)].Write(message)
	if err != nil {
		common.Logger.Errorf("fail send messsage to %v", toPartyID)
		log.Errorf("fail send messsage to %v", toPartyID)
		return err
	}

	conn := connConf.IDConnMap[partyID(toPartyID)]
	buf := make([]byte, 1e6)
	// BroadcastInt := -1
	size := -1
	tmpSize := 0
	n, err := conn.Read(buf)

	var tmpMsgByte []byte
	if err != nil || n <= 8 {
		// common.Logger.Error("fail read message")
		log.Errorln("fail read message")
		// return nil, err
	}
	// var IsBroadcast bool
	// extract the size of the message from the first 4 bytes of the buffer.
	sizeByte := buf[4:8]
	size = BytesToInt(sizeByte)
	// initialize tmpMsgByte to store the received message data, excluding the size bytes.
	tmpMsgByte = buf[8:n]
	// update tmpSize to indicate the current size of the received data.
	tmpSize = n - 8
	// enter a loop to read additional data from the connection until the size of the received data reaches the expected size
	for tmpSize < size {
		// read data into a new buffer buf and appends it to tmpMsgByte
		buf := make([]byte, 1e6)
		n, err := conn.Read(buf)
		if err != nil {
			common.Logger.Error(err)
			log.Errorln(err)
		}
		tmpMsgByte = append(tmpMsgByte, buf[:n]...)
		tmpSize += n
	}
	BroadcastByte := buf[:4]
	tmpMsgByte = append(BroadcastByte, tmpMsgByte...)
	isb := BytesToInt(BroadcastByte)
	println(isb)
	// if err != nil {
	// 	log.Errorln("")
	// 	// common.Logger.Errorf("fail receive messsage from %v", fromPartyID)
	// 	log.Errorf("fail receive messsage from %v", fromPartyID)
	// 	//return nil, err
	// }

	return nil
}
func IsBroadcast(msgByte []byte) bool {
	BroadcastByte := msgByte[:4]
	BroadcastInt := BytesToInt(BroadcastByte)
	if BroadcastInt != 0 && BroadcastInt != 1 {
		log.Errorln("fail to get IsBroadcast!")
	}
	if BroadcastInt == 0 {
		return false
	}
	return true
}
func (connConf *LocalConn) P2pReceive2(fromPartyID string) ([]byte, error) {
	buf := make([]byte, 1e6)
	conn := connConf.IDConnMap[partyID(fromPartyID)]
	// BroadcastInt := -1
	size := -1
	tmpSize := 0
	n, err := conn.Read(buf)

	var tmpMsgByte []byte
	if err != nil || n <= 8 {
		// common.Logger.Error("fail read message")
		log.Errorln("fail read message")
		return nil, err
	}
	// var IsBroadcast bool
	// extract the size of the message from the first 4 bytes of the buffer.
	sizeByte := buf[4:8]
	size = BytesToInt(sizeByte)
	// initialize tmpMsgByte to store the received message data, excluding the size bytes.
	tmpMsgByte = buf[8:n]
	// update tmpSize to indicate the current size of the received data.
	tmpSize = n - 8
	// enter a loop to read additional data from the connection until the size of the received data reaches the expected size
	for tmpSize < size {
		// read data into a new buffer buf and appends it to tmpMsgByte
		buf := make([]byte, 1e6)
		n, err := conn.Read(buf)
		if err != nil {
			common.Logger.Error(err)
			log.Errorln(err)
		}
		tmpMsgByte = append(tmpMsgByte, buf[:n]...)
		tmpSize += n
	}
	BroadcastByte := buf[:4]
	tmpMsgByte = append(BroadcastByte, tmpMsgByte...)
	if err != nil {
		// common.Logger.Errorf("fail receive messsage from %v", fromPartyID)
		// log.Errorf("fail receive messsage from %v", fromPartyID)
		return nil, err
	}
	// common.Logger.Infof("receive from party %v message len is %v \n", fromPartyID, size)
	// log.Infof("receive from party %v message len is %v \n", fromPartyID, size)
	return tmpMsgByte, nil
}

func (connConf *LocalConn) BroadcastSend2(message []byte, isbroadcast bool) error {
	for id := range connConf.IDConnMap {
		go func(id partyID) {
			// call the P2pSend function to send the message to the specified party.
			err := connConf.P2pSend2(string(id), message, isbroadcast)
			if err != nil {
				// common.Logger.Errorf("fail broadcast messsage to %v", id)
				// log.Errorf("fail broadcast messsage to %v", id)
				return
			}
			// common.Logger.Infof("send to party %v message len is %v\n", id, len(message))
			log.Infof("send to party %v message len is %v\n", id, len(message))
		}(id)

	}
	return nil
}

// BroadcastReceive function receives a message from each of the other participants in a broadcast manner.

func (connConf *LocalConn) BroadcastReceive2() (map[partyID][]byte, error) {
	// create a msgMap to store the received messages from other parties
	msgMap := make(map[partyID][]byte, connConf.LocalConfig.TotalPartyCount-1)
	// var Isbroadcast bool
	// initialize a mutex to control concurrent writes to the msgMap.
	var mutex sync.Mutex
	// create a WaitGroup wg to control the execution of the message receiving goroutines.
	// The number of goroutines is equal to the total number of other parties
	wg := sync.WaitGroup{}
	wg.Add(connConf.LocalConfig.TotalPartyCount - 1)

	for _, fromPartyID := range connConf.LocalConfig.OtherPartyIDs {
		go func(fromPartyID partyID, msgMap *map[partyID][]byte) {
			defer wg.Done()
			// call the P2pReceive function to receive the message from the specified party.
			receiveMsg, err := connConf.P2pReceive2(string(fromPartyID))
			// Isbroadcast = IsbroadcastTemp
			// log.Infof("")
			if err != nil {
				// common.Logger.Errorf("receive from %v errror", fromPartyID)
				// log.Errorf("receive from %v errror", fromPartyID)
				return
			}
			// common.Logger.Infof("receive from %v msg", fromPartyID)
			log.Infof("receive from %v msg", fromPartyID)
			// If the message is successfully received, it locks the mutex,
			mutex.Lock()
			// update the msgMap with the received message,
			(*msgMap)[fromPartyID] = receiveMsg
			// unlock the mutex.
			mutex.Unlock()
		}(partyID(fromPartyID), &msgMap)

	}
	wg.Wait()
	// common.Logger.Info("received all broadcast messages")
	// log.Infoln("received all broadcast messages")
	return msgMap, nil
}

// IntToBytes function converts an integer to a byte slice
func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

// BytesToInt converts a byte slice to an integer.
func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)

	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)

	return int(x)
}
