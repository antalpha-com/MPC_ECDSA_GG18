# Multi-Party Threshold Signature Scheme

## Introduction

This is an implementation of multi-party {t, n}-threshold ECDSA (Elliptic Curve Digital Signature Algorithm) based on the CCS 2018 paper by Gennaro and Goldfeder [1], along with a similar approach using EdDSA (Edwards-curve Digital Signature Algorithm). This library includes three protocols:

- Key Generation, used to create secret shares ('keygen').
- Signing, used to generate signatures using secret shares ('signing').
- Key Refresh, used to change the group of participants while keeping the secrets ('resharing').

ECDSA is widely used in cryptocurrencies such as Bitcoin, Ethereum (secp256k1 curve), NEO (NIST P-256 curve), and more. EdDSA is also extensively used in cryptocurrencies like Cardano, Aeternity, Stellar Lumens, and others. For these currencies, this technology can be used to create cryptographic wallets where multiple parties must collaborate to sign transactions. Each key/address stores a local secret share, which is kept secure by the protocol and never revealed to others.

Binance has open-sourced a Go language implementation of the MPC signature based on the GG18 paper, which has gained wide recognition and usage. Note that this is a library for developers. You can find a TSS tool that can be used with the Binance Chain CLI [here](https://docs.binance.org/tss.html).

Building upon the GG18 open-source solution, this project further enhances security, performance, and functionality. It aims to assist the industry in promoting and deploying MPC signature schemes more effectively. In addition, we provide detailed code comments and deployment examples to help MPC beginners better understand and integrate it into commercial software and systems. In terms of performance, the project utilizes efficient libraries such as the GMP library, Paillier, and CRT operations, significantly improving computational efficiency. Furthermore, considering that Binance's open-source library provides only local test cases, i.e., single-machine deployment scenarios, this project presents real multi-party deployment scenarios to help beginners better understand MPC signatures and integrate them into commercial software and systems.

## Deployment

We can create a multi-party deployment instance through the following steps:

1. Clone the project and install dependencies.
2. Modify the cgo precompile directive. This step is for invoking the GMP large number arithmetic library to improve computational efficiency.
3. Generate certificate files. Establish TLS connections to ensure communication security.
4. Customize the configuration file. Users can customize various parameters in the configuration file according to their own requirements.
5. Start multiple participants simultaneously by running the main function to establish communication.
6. Enter commands on the server side to execute the protocols.

For detailed steps, please refer to the user manual.



## Use

First, establish multi-party communication and precompute relevant parameters.

```go
localConn := &LocalConn{
   LocalConn: communication.SetUpConn(),
}
// prepare pre-parameters
localConn.PreparePrePramas()
```

Continuously execute the protocol.

```go
for {
   err := execute(localConn)
   //handle err...
}
```

The server schedules the protocol and broadcasts the execution command to other participants (clients), and the other participants receive the scheduling command.

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

Execute the relevant protocol (key generation/signing) based on the protocol scheduling command.

### Key Generation

Use `outCh` and `endCh` for message exchange and storage. The `localConn` variable is generated when establishing communication between participants and is used to store configuration options, TLS connections, and intermediate results generated during the protocol execution.

```go
outCh := make(chan tss.Message, localConn.LocalConfig.TotalPartyCount)
endCh := make(chan keygen.LocalPartySaveData, localConn.LocalConfig.TotalPartyCount)
// Call the KeyGen function to execute the protocol logic for KeyGen
err := KeyGen(localConn, outCh, endCh)
```

The local participant uses KeyGen to execute the key generation protocol. It initiates the `start` function, progressing through the various rounds of the protocol. It sends messages to other participants as required in different rounds and receives messages from other participants to update its state using the updater. The local key generation result is obtained and stored in `endCh`, marking the end of the key generation protocol.

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

Note: Unlike the single-machine testing, when deployed in a multi-party real-world scenario, sending and receiving messages need to be handled separately.

### Signing

Use `outCh` and `endCh` for message exchange and storage. The `localConn` variable is generated when establishing communication between participants and is used to retain configuration options, TLS connections, as well as intermediate results generated during the phase.

```go
outCh := make(chan tss.Message, localConn.LocalConfig.TotalPartyCount)
		endCh := make(chan common.SignatureData, localConn.LocalConfig.TotalPartyCount)
		err := Signing(localConn, outCh, endCh)
```

The local participant retrieves the key generation results, initializes the local participant, and executes the `start` function to enter the signing phase. During the signing rounds, the participant generates messages and unicasts/broadcasts them to the respective participants. Upon receiving messages from other participants, the local participant updates its state.

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

Note: Unlike single-machine testing, in a multi-party real deployment, sending and receiving messages need to be handled separately.

## Reference

\[1\] https://eprint.iacr.org/2019/114.pdf
## License
[License](https://github.com/antalpha-com/MPC_ECDSA_GG18/blob/master/LICENSE)

