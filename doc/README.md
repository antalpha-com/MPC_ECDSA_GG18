# GG18开源算法库

[英文版](https://github.com/antalpha-com/MPC_ECDSA_GG18#readme)

## 介绍

多方计算（MPC）技术是一种密码学协议，它允许多个参与方在不泄露其私密输入的情况下协同进行计算。MPC签名是一种高度安全的数字签名方案，用于实现多个参与者之间分布式签名。 MPC签名使多个参与方能够安全地合作进行数字签名，而不必担心私钥泄漏，这对于强调隐私和安全的应用场景十分重要。

在数字资产管理领域，MPC技术具有广泛的应用前景，多方签名和私钥分片将继续提升数字资产的安全性。在隐私计算方面，MPC将被广泛应用于医疗、金融和市场分析等领域，以确保数据隐私的同时进行高效计算。总而言之，MPC技术将成为数字世界中的重要工具，满足不断增长的隐私和安全需求。

GG18是一种具有里程碑意义的门限MPC ECDSA签名方案，允许多个参与者之间进行门限签名。GG18不仅在理论上具有重大意义，还已经成功进入实际应用阶段，在多方协同签名领域占据着重要地位。币安基于GG18的论文开源了go语言版本的MPC签名实现，并且获得了广泛认可和应用。

Antalpha更进一步，在GG18的开源方案基础上，在安全性、性能、功能等方面做了优化与提升，旨在协助业界更好地推广、部署MPC签名方案。此外，我们提供了详细的代码注释和部署示例，以帮助MPC初学者更好的理解并将其整合到项目中。

## 部署

我们可以通过下面的步骤创建一个多方部署实例：

1、拉取项目并安装依赖。

2、修改cgo预编译指令。该步骤是为了调用gmp大数运算库，提升计算效率。

3、生成证书文件。建立TLS连接确保通信安全。

4、自定义配置文件。用户根据自身情况自定义配置文件的各项参数。

5、多个参与方同时启动，运行main函数建立通信。

6、在server端输入指令，运行协议。

详细步骤可查阅[用户手册](https://github.com/antalpha-com/MPC_ECDSA_GG18/blob/master/doc/用户手册gg18.md)。

## 使用

首先建立多方通信，并预计算相关参数。

```go
localConn := &LocalConn{
   LocalConn: communication.SetUpConn(),
}
// prepare pre-parameters
localConn.PreparePrePramas()
```

持续执行协议

```go
for {
   err := execute(localConn)
   if err != nil {
      log.Errorln("execute is wrong!")
   }
}
```

server端进行协议调度，将执行命令广播给其他参与方（client），其他参与方接收调度命令

```go
 // If the local ID is the center server ID, prompt the user to enter the stage of the protocol.
if centerID == localID {
   // Broadcast the stage instruction to all participants
   err = localConn.BroadcastSend([]byte(stage))
} else {
   // If the local ID is not the center server ID, listen for instructions from the center server.
   data, err := localConn.P2pReceive(centerID)
  //handle err...
   }
}
```

根据协议调度命令，执行相关协议（密钥生成/签名）。

### 密钥生成

使用outCh和endCh进行消息收发和存储, `localConn` 变量是在参与方之间建立通信时生成的，用于保存配置项以及TLS连接还有阶段运行产生的中间结果。

```go
outCh := make(chan tss.Message, localConn.LocalConfig.TotalPartyCount)
endCh := make(chan keygen.LocalPartySaveData, localConn.LocalConfig.TotalPartyCount)
// Call the KeyGen function to execute the protocol logic for KeyGen
err := KeyGen(localConn, outCh, endCh)
```

本地参与方使用KeyGen执行密钥生成协议，执行start函数进入协议的各个round，发送在不同round中需要发送给相应的消息给其他参与方，接收来自其他参与方的消息并updater更新状态；获取本地密钥生成结果存储在endCh中，密钥生成协议结束。

```go
    // creat a localparty
   var P *keygen.LocalParty
   P = keygen.NewLocalParty(localConn.Params, outCh, endCh).(*keygen.LocalParty)
   go func(P *keygen.LocalParty) {
      // Call P.Start() to start the execution of the LocalParty
      if err := P.Start(); 
       //handle err...
      }
   }(P)
   // receive message
   go func() {
     //receive message and serialize the message to ParsedMessage
     go updater(P, ParsedMessage, errCh)
     //...
   }()
   // send message
keygen:
   for {
      select {
         //...
      case msg := <-outCh:
         // send message ...
      case save := <-endCh: 
         // store the generated key information in localconn
         localConn.KeyGenResult = save
         //
      default:
      }
   }
}
```

注意：与单机版测试不同的是，多方真实部署时需要将消息发送和接收需要分开处理。

### 签名

使用outCh和endCh进行消息收发和存储, `localConn` 变量是在参与方之间建立通信时生成的，用于保存配置项以及TLS连接还有阶段运行产生的中间结果。

```go
outCh := make(chan tss.Message, localConn.LocalConfig.TotalPartyCount)
		endCh := make(chan common.SignatureData, localConn.LocalConfig.TotalPartyCount)
		err := Signing(localConn, outCh, endCh)
```

本地参与方获取密钥生成的结果，生成本地参与方并执行start函数进行签名阶段，在签名的round中产生消息后，将消息单播/广播给相应的参与方；接收到来自其他参与的消息后，更新本地参与方状态。

```go
  //get the  keygen result from localConn
   key, ok := localConn.KeyGenResult.(keygen.LocalPartySaveData)
   // Create a local signing party (P)
   P = signing.NewLocalParty(msg, localConn.Params, key, outCh, endCh).(*signing.LocalParty)
   // Start the local signing party in a goroutine.
   go func(P *signing.LocalParty) {
      if err := P.Start(); err != nil {
         errCh <- err
      }
   }(P)
   //receive message
   go func() {
      //...
      for {
         //  exit
         select {
         // Receive a message from the endSignal channel to indicate that the function has finished.
         case <-endSignal:
            //Exit loop mechanism...
         default:
           //receive message and serialize the message to ParsedMessage
            go updater(P, ParsedMessage, errCh)
         }
      }
   }()
   // send message 
signing:
   for {
      select {
      
      case err := <-errCh://
         // Handle err....
      case msg := <-outCh:
        //send message
      case localSignResult := <-endCh:
         // store the sign result
         localConn.SignResult = localSignResult
         //Exit...
      }
   }
```

注意：与单机版测试不同的是，多方真实部署时需要将消息发送和接收需要分开处理。

## 参考文献

\[1\][Fast Multiparty Threshold ECDSA with Fast Trustless Setup]( https://eprint.iacr.org/2019/114.pdf)

## License

[Apache License 2.0](https://github.com/antalpha-com/MPC_ECDSA_GG18/blob/master/LICENSE)