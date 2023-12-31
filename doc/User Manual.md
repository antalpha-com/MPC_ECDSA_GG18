# How to deploy

## Pull our program and install dependencies

First, we need to enter our target folder, and pull the project to it using the commands followed. Enter the MPC_ECDSA_GG18folder before we continue.

```Shell
$ git clone https://github.com/antalpha-com/MPC_ECDSA_GG18.git
$ cd MPC_ECDSA_GG18
```

In the root directory, we use `go.mod` to install the dependencies.

```Shell
$ go mod tidy
```

## Modify cgo precompile directives

Next, we need to adjust `/pkg/gmp/int.go` according to our operating system. This project uses cgo to support the call to the gmp large number operation library. The CGO that comes with Golang can support interoperability with the C language interface. First, we need to modify the lines 13 to 23 under the `int.go` file according to the operating system the project is deployed.

**windows**

Under the Windows operating system, the remaining cgo pre-compile instructions should be the following two lines. Please keep them and comment (or delete) other #cgo lines.

```Shell
// windows
#cgo CFLAGS: -Iclib/win/include
#cgo LDFLAGS: -Lclib/win/lib -lgmp
```

**macOS**

Under the MacOS operating system, the remaining cgo pre-compile instructions should be the following two lines. Please keep them and comment (or delete) other #cgo lines.

```Shell
// macOS
//#cgo CFLAGS: -Iclib/mac/include
//#cgo LDFLAGS: -Lclib/mac/lib -lgmp
```

**linux**

Under the MacOS operating system, the remaining cgo pre-compile instructions should be the following two lines. Please keep them and comment (or delete) other #cgo lines.

```Shell
// linux
//#cgo CFLAGS: -Iclib/linux/include
//#cgo LDFLAGS: -Lclib/linux/lib -lgmp
```

## Generate certificate files

Establishing a TLS connection requires openssl to generate certificate related files. The script `getCert.sh` is given in the root directory, responsible for generating certificate related files

```Shell
$ sh getCert.sh
```

After that, we can see certificate files under `communication/config/`.

## Customize config file

The configuration file of this project is the `config.json` file located in the root directory of the project, which requires us to set it according to the actual situation when we deploy. Next, each item of the configuration file is introduced below:

| Index | Item             | Type                                                         | Introduction                                                 |
| ----- | ---------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1     | caPath           | string                                                       | Path of ca.crt file                                          |
| 2     | clientCertPath   | string                                                       | Path of client.crt file                                      |
| 3     | serverCertPath   | string                                                       | Path of server.crt file                                      |
| 4     | clientKeyPath    | string                                                       | Path of client.key file                                      |
| 5     | serverKeyPath    | string                                                       | Path of server.key file                                      |
| 6     | timeOutSecond    | int                                                          | The duration TLS connection becomes timeout                  |
| 7     | centerServerID   | string                                                       | id of the center party which is responsible for indicating stages to execute |
| 8     | partyIDs         | []string                                                     | Ids of all parties                                           |
| 9     | LocalPartyID     | string                                                       | id of this party                                             |
| 10    | OtherPartyIDs    | []string                                                     | Other parties' ids except for this party                     |
| 11    | LocalAddr        | string                                                       | Ip: port of this party                                       |
| 12    | TotalPartyCount  | int                                                          | Total number of parties                                      |
| 13    | Threshold        | int                                                          | threshold to sign                                            |
| 14    | LocalCanBeServer | bool                                                         | Whether this party can be a server                           |
| 15    | LocalPartyIDIMK  | PartyIDIMK                                                   | PartyIDIMK consists of two fields: "MessageWrapperPartyID" and the participant's index "Index." The "MessageWrapperPartyID" is composed of three fields: "id" (participant's ID), "Moniker" (participant's alias), and "Key" (participant's key). |
| 16    | PartyIDsIMK      | []PartyIDIMK                                                 | PartyIDIMK structure array (comprising PartyIDIMK for all participants) |
| 17    | OtherPartyIDsIMK | []PartyIDIMK                                                 | Array of PartyIDIMK structures (PartyIDIMK for all participants except oneself) |
| 18    | OtherPartyInfo   | Array of structures, each unit containing 3 fields：id: stringaddr: stringconnRole:string | Information on connections with other partiesid：id of other partiesaddr：ip:port of other party (Required only if this party's connRole is server)connRole：connections role（server/client） |

After writing the `config.json` file for all parties involved, we are ready to run the project

## Run project

The instructions for running `main.go` by each participant, as shown in the `main.go` file, are as follows:

```Shell
$ go run main.go
```

We can see terminal of the center party prompting us to input stage to be executed. Different parties interact with each other according to the stage name entered by the user.

# Local test

## Multi-party test

This section introduces how to deploy our project with three participants for MPC ECDSA signature. The scenario is as follows:

- Party a: Initiate the execution of ECDSA protocal stage, and act as client in connections with b and c party
- Party b: Act as server in connection with b, and act as client in connection with c
- Party c: Act as client in connections with b and c party
- Message to sign："hello, world!"

If we use IDE to test, please open 3 windows to use the above steps to pull the project and modify the cgo instructions and generate the certificate file respectively

If using the command line, please open three terminals, and create three folders and use the above steps to pull the project and modify the cgo instructions and generate the certificate file

Modify the `config.json` file of party a to

```JSON
{
  "caPath": "./communication/config/ca.crt",
  "clientCertPath" : "./communication/config/client.crt",
  "serverCertPath": "./communication/config/server.crt",
  "clientKeyPath" : "./communication/config/client.key",
  "serverKeyPath" : "./communication/config/server.key",
  "timeOutSecond": 6000,
  "centerServerID": "a",
  "partyIDs":["a", "b", "c"],
  "localPartyID": "a",
  "otherPartyIDs":["b", "c"],
  "localAddr" : "localhost:8000",
  "totalPartyCount" : 3,
  "threshold": 2,
  "localCanBeServer": false,
  "otherPartyInfo":[
    {
      "id": "b",
      "addr": "localhost:8001",
      "connRole": "server"
    },
    {
      "id": "c",
      "addr": "localhost:8002",
      "connRole": "server"
    }
  ],

  "localPartyIDIMK": {
    "MessageWrapperPartyID": {
      "Id": "a",
      "Moniker": "P[1]",
      "Key": [1,2,1]
    },
    "Index": 0
  },
  "partyIDsIMK":[ {
    "MessageWrapperPartyID": {
      "Id": "a",
      "Moniker": "P[1]",
      "Key": [1,2,1]
    },
    "Index": 0
  },
    {
      "MessageWrapperPartyID": {
        "Id": "b",
        "Moniker": "P[2]",
        "Key": [1,2,2]
      },
      "Index": 1
    },
    {
      "MessageWrapperPartyID": {
        "Id": "c",
        "Moniker": "P[3]",
        "Key": [1,2,3]
      },
      "Index": 2
    }],

  "otherPartyIDsIMK":[
    {
      "MessageWrapperPartyID": {
        "Id": "b",
        "Moniker": "P[2]",
        "Key": [1,2,2]
      },
      "Index": 1
    },
    {
      "MessageWrapperPartyID": {
        "Id": "c",
        "Moniker": "P[3]",
        "Key": [1,2,3]
      },
      "Index": 2
    }]
}
```

Modify the `config.json` file of party b to

```JSON
{
  "caPath": "./communication/config/ca.crt",
  "clientCertPath" : "./communication/config/client.crt",
  "serverCertPath": "./communication/config/server.crt",
  "clientKeyPath" : "./communication/config/client.key",
  "serverKeyPath" : "./communication/config/server.key",
  "timeOutSecond": 6000,
  "centerServerID": "a",
  "partyIDs":["a", "b", "c"],
  "localPartyID": "b",
  "otherPartyIDs":["a", "c"],
  "localAddr" : "localhost:8001",
  "totalPartyCount" : 3,
  "threshold": 2,
  "localCanBeServer": true,
  "otherPartyInfo":[
    {
      "id": "a",
      "connRole": "client"
    },
    {
      "id": "c",
      "addr": "localhost:8002",
      "connRole": "server"
    }
  ],

  "localPartyIDIMK": {
    "MessageWrapperPartyID": {
      "Id": "b",
      "Moniker": "P[2]",
      "Key": [1,2,2]
    },
    "Index": 1
  },
  "partyIDsIMK":[ {
    "MessageWrapperPartyID": {
      "Id": "a",
      "Moniker": "P[1]",
      "Key":[1,2,1]
    },
    "Index": 0
  },
    {
      "MessageWrapperPartyID": {
        "Id": "b",
        "Moniker": "P[2]",
        "Key": [1,2,2]
      },
      "Index": 1
    },
    {
      "MessageWrapperPartyID": {
        "Id": "c",
        "Moniker": "P[3]",
        "Key": [1,2,3]
      },
      "Index": 2
    }],

  "otherPartyIDsIMK":[
    {
      "MessageWrapperPartyID": {
        "Id": "a",
        "Moniker": "P[1]",
        "Key": [1,2,1]
      },
      "Index": 0
    },
    {
      "MessageWrapperPartyID": {
        "Id": "c",
        "Moniker": "P[3]",
        "Key": [1,2,3]
      },
      "Index": 2
    }]
}
```

Modify the `config.json` file of party c to

```JSON
{
  "caPath": "./communication/config/ca.crt",
  "clientCertPath" : "./communication/config/client.crt",
  "serverCertPath": "./communication/config/server.crt",
  "clientKeyPath" : "./communication/config/client.key",
  "serverKeyPath" : "./communication/config/server.key",
  "timeOutSecond": 6000,
  "centerServerID": "a",
  "partyIDs":["a", "b", "c"],
  "localPartyID": "c",
  "otherPartyIDs":["a", "b"],
  "localAddr" : "localhost:8002",
  "totalPartyCount" : 3,
  "threshold": 2,
  "localCanBeServer": true,

  "otherPartyInfo":[
    {
      "id": "b",
      "connRole": "client"
    },
    {
      "id": "a",
      "connRole": "client"
    }
  ],

  "localPartyIDIMK": {
    "MessageWrapperPartyID": {
      "Id": "c",
      "Moniker": "P[3]",
      "Key": [1,2,3]
    },
    "Index": 2
  },
  "partyIDsIMK":[ {
    "MessageWrapperPartyID": {
      "Id": "a",
      "Moniker": "P[1]",
      "Key": [1,2,1]
    },
    "Index": 0
  },
    {
      "MessageWrapperPartyID": {
        "Id": "b",
        "Moniker": "P[2]",
        "Key": [1,2,2]
      },
      "Index": 1
    },
    {
      "MessageWrapperPartyID": {
        "Id": "c",
        "Moniker": "P[3]",
        "Key": [1,2,3]
      },
      "Index": 2
    }],

  "otherPartyIDsIMK":[
    {
      "MessageWrapperPartyID": {
        "Id": "b",
        "Moniker": "P[2]",
        "Key": [1,2,2]
      },
      "Index": 1
    },
    {
      "MessageWrapperPartyID": {
        "Id": "a",
        "Moniker": "1",
        "Key": [1,2,1]
      },
      "Index": 0
    }]
}
```

Run main.go for all parties. After the TLS connections are established, enter the stage name at the terminal of the center party to organize three participants for key generation and signing.

## Unit Test

The unit testing for this project follows the test files provided by the `tss-lib` project. This section describes the testing methods for various test files under the `ecdsa/eddsa` packages.

**Key Generation Testing**

Note: In the test files, the variables `testParticipants` and `testThreshold` are set. The test functions in the `local_party_test.go` files in the `keygen` package will generate and save test cases to the `test/_ecdsa_fixtures` or `test/__eddsa_fixtures` packages.

This file is used to test the ecdsa key generation phase's execution process and verify the generated results. Run the following command to execute the tests (or use an IDE to run the test functions):

```Shell
$ go test -v ./ecdsa/keygen/local_party_test.go
```

This file is used to test the eddsa key generation phase's execution process and verify the generated results. Run the following command to execute the tests (or use an IDE to run the test functions):

```Shell
$ go test -v ./eddsa/keygen/local_party_test.go
```

### Key Refresh Testing

Note: During key refresh and signing phases, it is necessary to call the test cases generated by the `keygen` package in the `test` directory. If the user wants to modify `testParticipants` or `testThreshold`, it is necessary to delete the corresponding test cases generated previously and rerun the test function `TestE2EConcurrentAndSaveFixtures` in `local_party_test.go` to ensure smooth execution of the key refresh and signing phases.

This file is used to test the ecdsa key refresh phase's execution process and verify the generated results. Run the following command to execute the tests (or use an IDE to run the test functions):

```Shell
$ go test -v ./ecdsa/resharing/local_party_test.go
```

This file is used to test the eddsa key refresh phase's execution process and verify the generated results. Run the following command to execute the tests (or use an IDE to run the test functions):

```Shell
$ go test -v ./eddsa/resharing/local_party_test.go
```

### Signing Testing

This file is used to test the ecdsa signing phase's execution process and verify the generated results. Run the following command to execute the tests (or use an IDE to run the test functions):

```Shell
$ go test -v ./ecdsa/signing/local_party_test.go
```

This file is used to test the eddsa signing phase's execution process and verify the generated results. Run the following command to execute the tests (or use an IDE to run the test functions):

```Shell
$ go test -v ./eddsa/signing/local_party_test.go
```

# How to customize scheduling

If we want to adjust the logic of executing protocol, the following introduction may be helpful:

## How to add a config item

First, determine the expected type and name of our configuration item. After adding the configuration item in the configuration file `config.json`, we need to add the corresponding item to the `LocalConfig` structure of `communication/communicate.go` file, and indicate the name of json

e.g.: If we want to add a `version` config, add the key-value to `config.json`

```JSON
"version": 1
```

Edit `communication/communicate.go`, midify `LocalConfig`

```Go
// LocalConfig struct represents the local configuration for the application.
type LocalConfig struct {
    ...
    Version int `json:"version"`
}
```

And then, we can process the config structure after unmarshal.

## How to modify the main logic

The current `main.go` file organizes the participants to run the various stages of the protocol according to the logic of [establish TLS connection - enter stage name  in the center party terminal - execute the stage- continue to wait for input]

If you need to modify such logic, you can rewrite the `main.go` file.

**Set up connections**

`communication. SetUpConn()` is called when a connection needs to be established, the configuration items, as well as the TLS connection, and the intermediate results generated by the stage run will be saved in the `localConn` variable.

```Go
//Establish a network connection with other participants.
//The returned value localConn represents the local connection to the network.
localConn := communication.SetUpConn()
```

If necessary, remember to pass the `localConn` variable, for example, when passing parameters during signing.

```Go
func Signing(localConn *LocalConn, outCh chan tss.Message, endCh chan common.SignatureData) 
```

**Execute a stage**

If we need to execute a specific phase in a user-defined file, you can refer to the examples in `main.go`.

On the server-side, input the phase you want to execute: KeyGen/Sign, create message passing channels `outCh`, and signal the end of the phase using `endCh`. Then, execute the phase function by passing `localConn`, `outCh`, and `endCh` as input parameters.

```Go
//Create a new MultiHandler for the Presign protocol
h, err := protocol.NewMultiHandler(protocols.Presign(config, signers, pl), nil, *localConn) //handler表示一个协议的执行
if err != nil {
   log.Errorln(err)
   return err
}
// Get the result of the protocol execution
preSignResult, err := h.Result()
```

Execute the corresponding Start function and perform message exchange in the KeyGen/Signing functions