package main

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
	"strings"
	"chaoshen.com/gopaillier/api/ccapi"
	"chaoshen.com/gopaillier/api/core"
)

//var logger = util.GetLog("TransChaincode Demo")

var logger = shim.NewLogger("Transfer Chaincode")


type TransferChaincode struct{}

type CipherAccount struct {
	Balance  []byte
	PublicKey []byte
	Remark   []byte
}

func (t *TransferChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func (t *TransferChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("enter Invoke")
	function, args := stub.GetFunctionAndParameters()

	if function == "QueryBalance" {
		return t.queryBalance(stub, args)
	} else if function == "Transfer" {
		return t.transfer(stub, args)

	} else if function == "init" {
		return t.init(stub, args)
	} else if function == "HomoAdd" {
		return t.homoAdd(stub, args)
	}

	return shim.Error("Invalid invoke function name: " + function)
}

func (t *TransferChaincode) transfer(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Debug("enter Transfer")

	if len(args) != 3 {
		logger.Error("Incorrect number of arguments. expect 3 arguments")
		return shim.Error("Incorrect number of arguments. expect 3 arguments")
	}

	AddrA := args[0]
	AddrB := args[1]
	txInfo := args[2]

	if strings.Compare(AddrA, AddrB) == 0 {
		logger.Error("A' addr is the same B'Addr")
		return shim.Error("A' addr is the same B'Addr")
	}

	// read a's trans record
	logger.Debug("read sender: %s trans record", string(AddrA))
	accountA, err := stub.GetState(AddrA)
	if err != nil {
		return shim.Error("Failed to get state")
	}
	if accountA == nil {
		return shim.Error("Entity not found")
	}

	var transferAStruct = CipherAccount{}
	err = json.Unmarshal(accountA, &transferAStruct)
	if err != nil {
		logger.Error("fail to unmarshal user's trans record")
		return shim.Error("fail to unmarshal user's trans record")
	}

	// read b's trans record
	logger.Debugf("read receiver: %s trans record", string(AddrB))
	accountB, err := stub.GetState(AddrB)
	if err != nil {
		return shim.Error("Failed to get state")
	}
	if accountB == nil {
		return shim.Error("Entity not found")
	}

	var transferBStruct = CipherAccount{}
	err = json.Unmarshal(accountB, &transferBStruct)
	if err != nil {
		logger.Error("fail to unmarshal user's trans record")
		return shim.Error("fail to unmarshal user's trans record")
	}

	//validate transfer information
	logger.Debugf("validate transfer information")
	logger.Debugf("tx information: ")
	logger.Debugf("%+v\n", string(txInfo))
	cipherBalanceA := transferAStruct.Balance
	cipherBalanceB := transferBStruct.Balance
	newCipherBalanceA,newCipherBalanceB,err:=ccapi.ValidateTxInfo(txInfo,string(cipherBalanceA),string(cipherBalanceB))
	if err != nil {
		logger.Error("fail to validate transaction information")
		return shim.Error("fail to validate transaction information")
	}

	// update a's balance
	transferAStruct.Balance = []byte(newCipherBalanceA)


	AvalbytesUpdate, err := json.Marshal(transferAStruct)
	if err != nil {
		logger.Error("fail to marshal balance update info")
		return shim.Error("Marshal Error")
	}

	logger.Debug("update sender -> " + string(AvalbytesUpdate))
	err = stub.PutState(AddrA, AvalbytesUpdate)
	if err != nil {
		logger.Error("fail to store state: ", err.Error())
		return shim.Error(err.Error())
	}

	// update b's balance
	transferBStruct.Balance = []byte(newCipherBalanceB)
	BvalbytesUpdate, err := json.Marshal(transferBStruct)
	if err != nil {
		logger.Error("fail to marshal balance update info")
		return shim.Error("Marshal Error")
	}

	logger.Debug("update receiver -> " + string(BvalbytesUpdate))
	err = stub.PutState(AddrB, BvalbytesUpdate)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success([]byte("Success"))
}

func (t *TransferChaincode) init(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Debug("enter init Balance")
	if len(args) != 2 {
		logger.Error("parameters number is not correct")
		return shim.Error("parameters number is not correct")
	}

	PubKey := string(args[0])
	balanceStr := string(args[1])

	hashPubkey, err := t.calcAddr(PubKey)

	logger.Debug("encrypt initial balance")

	UserPubKey, err := stub.GetState(hashPubkey)
	if err != nil {
		logger.Error("Error on query addr")
		return shim.Error("fail to query addr")
	}

	if UserPubKey != nil {
		logger.Error("addr already register")
		return shim.Error("addr already register")
	}

	//validate balance
	cipherBalance, err := ccapi.ValidateInitBalance(balanceStr, PubKey)
	if err != nil {
		logger.Error("fail to Validate InitBalance ")
		return shim.Error("fail toValidate InitBalance")
	}

	logger.Debug("prepare init balance record:")
	account := &CipherAccount{}
	account.PublicKey = []byte(PubKey)
	account.Balance = []byte(cipherBalance)

	accountBytes, err := json.Marshal(account)

	if err != nil {
		logger.Error("fail to marshal Cipher Account")
		return shim.Error("fail to marshal Cipher Account")
	}

	logger.Debug("serialized Cipher Account: ", string(accountBytes)[1:64], "...")
	logger.Debug("serialized Cipher Account length: ", len(accountBytes))
	// store user's trans record
	err = stub.PutState(hashPubkey, accountBytes)
	if err != nil {
		logger.Error("fail to store trans record")
		return shim.Error("fail to store trans record")
	}

	return shim.Success([]byte("Success"))
}

/*
query account's balance
*/
func (t *TransferChaincode) queryBalance(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		logger.Error("Incorrect number of arguments. Expecting addr to query")
		return shim.Error("Incorrect number of arguments. Expecting addr to query")
	}

	Addr := string(args[0])
	// Get the state from the ledger
	balance, err := stub.GetState(Addr)
	if err != nil {
		logger.Error("fail to get state for: ", Addr)
		return shim.Error("fail to get state for: " + Addr)
	}

	if balance == nil {
		logger.Error("nil amount for: ", Addr)
		return shim.Error("nil amount for: " + Addr)
	}

	logger.Debug("state for: ", Addr, "is: ", balance)
	return shim.Success(balance)
}

/*
call homomorphic addition function
*/
func (t *TransferChaincode) homoAdd(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		logger.Error("Incorrect number of arguments. Expecting two cipher")
		return shim.Error("Incorrect number of arguments. Expecting two cipher")
	}

	cipher1 := []byte(args[0])
	cipher2 := []byte(args[1])
	pubKey :=[]byte(args[2])

	// Get the state from the ledger
	homoaddRes,err:= gohe.AddCipher(pubKey,cipher1,cipher2)
	if err != nil {
		logger.Error("error on homoadd", err.Error())
		return shim.Error("error on homoadd" + err.Error())
	}

	return shim.Success(homoaddRes)
}


func (t *TransferChaincode) calcAddr(cont string) (string, error) {

	Hasher := crypto.SHA256.New()
	Hasher.Write([]byte(cont))
	HashRes := Hasher.Sum(nil)

	return hex.EncodeToString(HashRes), nil
}

func main() {
	logger.Debug("start transaction chaincode")
	err := shim.Start(new(TransferChaincode))
	if err != nil {
		logger.Error("Error starting Simple chaincode: ", err.Error())
	}
}
