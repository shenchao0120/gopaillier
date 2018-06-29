package main

import (
	"testing"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"fmt"
	"crypto"
	"math/big"
	"encoding/hex"
	"encoding/json"
	"chaoshen.com/gopaillier/api/core"
	"crypto/rand"
	"chaoshen.com/gopaillier/api/cliapi"
)

func init(){
	//logger.SetLevel(shim.LogDebug)
}

func checkInit(t *testing.T, stub *shim.MockStub, args [][]byte) {
	res := stub.MockInit("1", args)
	if res.Status != shim.OK {
		fmt.Println("Init failed", string(res.Message))
		t.FailNow()
	}
}

func checkState(t *testing.T, stub *shim.MockStub, addr string, plaintext int64,privkey string) {
	accountStructBytes := stub.State[addr]
	if accountStructBytes == nil {
		fmt.Println("State", addr, "failed to get value")
		t.FailNow()
	}
	accountStruct := &CipherAccount{}
	err := json.Unmarshal(accountStructBytes, accountStruct)
	if err != nil {
		t.Fatal("fail to unmarshal transRec")
	}

	plainBytes,err:=gohe.Decrypt([]byte(privkey),[]byte(accountStruct.Balance))

	if err!=nil{
		fmt.Println("decrypt error:",err)
		t.FailNow()
	}
	value:=new(big.Int).SetBytes(plainBytes)

	result:=new(big.Int).SetInt64(plaintext)

	if value.Cmp(result) != 0{
		fmt.Println("State value: ", value.String())
		fmt.Println("result value", result.String())
		t.FailNow()
	}
	fmt.Println("check success.")
}

func getHash(cont string) (string, error) {

	Hasher := crypto.SHA256.New()
	Hasher.Write([]byte(cont))
	HashRes := Hasher.Sum(nil)

	return hex.EncodeToString(HashRes), nil
}

func checkQuery(t *testing.T, stub *shim.MockStub, name string, value string) {
	res := stub.MockInvoke("1", [][]byte{[]byte("query"), []byte(name)})
	if res.Status != shim.OK {
		fmt.Println("Query", name, "failed", string(res.Message))
		t.FailNow()
	}
	if res.Payload == nil {
		fmt.Println("Query", name, "failed to get value")
		t.FailNow()
	}
	if string(res.Payload) != value {
		fmt.Println("Query value", name, "was not", value, "as expected")
		t.FailNow()
	}
}

func checkInvoke(t *testing.T, stub *shim.MockStub, args [][]byte) {
	res := stub.MockInvoke("1", args)
	if res.Status != shim.OK {
		fmt.Println("Invoke", args, "failed", string(res.Message))
		t.FailNow()
	} else {
		fmt.Println(string(args[0]), "res: ", string(res.Payload))
	}
}


func TestHeDemoChaincode_register(t *testing.T) {
	scc := new(TransferChaincode)
	stub := shim.NewMockStub("TransferChaincode", scc)

	privKeyA,err :=  gohe.GenerateKey(rand.Reader,128)
	if err != nil {
		t.Fatalf("fail to generate key for sender")
		t.FailNow()
	}
	pubKeyStrA:=string(gohe.GenPemPublicKey(&privKeyA.PublicKey))
	privKeyStrA:=string(gohe.GenPemPrivateKey(privKeyA))
	hashAddrA,_:= getHash(pubKeyStrA)

	privKeyB,err :=  gohe.GenerateKey(rand.Reader,128)
	if err != nil {
		t.Fatalf("fail to generate key for sender")
		t.FailNow()
	}
	pubKeyStrB:=string(gohe.GenPemPublicKey(&privKeyB.PublicKey))
	privKeyStrB:=string(gohe.GenPemPrivateKey(privKeyB))

	hashAddrB,_:= getHash(pubKeyStrB)


	initBalanceInfoA, err := cliapi.InitBalance("100", pubKeyStrA)
	if err != nil {
		t.Fatal("fail to generate initbalance info")
	}

	initBalanceInfoB, err :=cliapi.InitBalance("200", pubKeyStrB)
	if err != nil {
		t.Fatal("fail to generate initbalance info")
	}

	checkInvoke(t, stub, [][]byte{[]byte("init"), []byte(pubKeyStrA), []byte(initBalanceInfoA)})
	checkInvoke(t, stub, [][]byte{[]byte("init"), []byte(pubKeyStrB), []byte(initBalanceInfoB)})
	checkState(t, stub, hashAddrA, 100,privKeyStrA)
	checkState(t, stub, hashAddrB, 200,privKeyStrB)

	//Tx 1
	//get A's balance
	accountABytes := stub.State[hashAddrA]
	accountAStruct := &CipherAccount{}
	err = json.Unmarshal(accountABytes, accountAStruct)
	if err != nil {
		t.Fatal("fail to unmarshal accountABytes")
	}
	cipherA := accountAStruct.Balance
	//prepare a->b 10
	txInfo, err:= cliapi.PrepareTxInfo(string(cipherA),"10",pubKeyStrA,pubKeyStrB,string(gohe.GenPemPrivateKey(privKeyA)))
	if err !=nil {
		t.Fatal("fail to prepare tx info: ", err.Error())
	}
	//send transaction
	checkInvoke(t, stub, [][]byte{[]byte("Transfer"), []byte(hashAddrA), []byte(hashAddrB),[]byte(txInfo)})
	//check balance
	checkState(t, stub, hashAddrA, 90,privKeyStrA)
	checkState(t, stub, hashAddrB, 210,privKeyStrB)

	//Tx 2
	//get A's balance
	accountABytes = stub.State[hashAddrA]
	err = json.Unmarshal(accountABytes, accountAStruct)
	if err != nil {
		t.Fatal("fail to unmarshal transRec")
	}
	cipherA = accountAStruct.Balance
	//prepare a->b 10
	txInfo, err = cliapi.PrepareTxInfo(string(cipherA),"10",pubKeyStrA,pubKeyStrB,string(gohe.GenPemPrivateKey(privKeyA)))
	if err !=nil {
		t.Fatal("fail to prepare tx info")
	}
	//send transaction
	checkInvoke(t, stub, [][]byte{[]byte("Transfer"), []byte(hashAddrA), []byte(hashAddrB),[]byte(txInfo)})
	//check balance
	checkState(t, stub, hashAddrA, 80,privKeyStrA)
	checkState(t, stub, hashAddrB, 220,privKeyStrB)

	//Tx 3
	//get A's balance
	accountABytes = stub.State[hashAddrB]
	err = json.Unmarshal(accountABytes, accountAStruct)
	if err != nil {
		t.Fatal("fail to unmarshal transRec")
	}
	cipherA = accountAStruct.Balance
	//prepare b->a 50
	txInfo, err = cliapi.PrepareTxInfo(string(cipherA),"50",pubKeyStrB,pubKeyStrA,string(gohe.GenPemPrivateKey(privKeyB)))
	if err !=nil {
		t.Fatal("fail to prepare tx info")
	}
	//send transaction
	checkInvoke(t, stub, [][]byte{[]byte("Transfer"), []byte(hashAddrB), []byte(hashAddrA),[]byte(txInfo)})
	//check balance
	checkState(t, stub, hashAddrA, 130,privKeyStrA)
	checkState(t, stub, hashAddrB, 170,privKeyStrB)


}

func TestHeDemoChaincode_InitBalance(t *testing.T) {
	scc := new(TransferChaincode)
	stub := shim.NewMockStub("TransferChaincode", scc)

	//checkInit(t, stub, [][]byte{[]byte("init"), []byte("A"), []byte("123"), []byte("B"), []byte("234")})

	privKeyA,err :=  gohe.GenerateKey(rand.Reader,128)
	if err != nil {
		t.Fatalf("fail to generate key for sender")
		t.FailNow()
	}
	pubKeyStrA:=string(gohe.GenPemPublicKey(&privKeyA.PublicKey))
	privKeyStrA:=string(gohe.GenPemPrivateKey(privKeyA))
	fmt.Println(privKeyStrA)
	hashAddrA,_:= getHash(pubKeyStrA)

	initBalanceInfoA, err := cliapi.InitBalance("100", pubKeyStrA)

	if err != nil {
		t.Fatal("fail to generate initbalance info")
	}

	checkInvoke(t, stub, [][]byte{[]byte("init"), []byte(pubKeyStrA), []byte(initBalanceInfoA)})
	checkState(t, stub, hashAddrA, 100,privKeyStrA)

	//plainBytes,err:=gohe.Decrypt([]byte(privkey),[]byte(accountStruct.Balance))




}


