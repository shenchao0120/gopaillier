package main

import (
	"crypto"
	"encoding/hex"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
	"strings"
)

type IDChaincode struct{}

var logger = shim.NewLogger("ID Chaincode")

func (t *IDChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func (t *IDChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("enter Invoke")
	function, args := stub.GetFunctionAndParameters()

	if function == "Register" {
		return t.register(stub, args)
	} else if function == "QueryPubkey" {
		return t.query(stub, args)
	}

	return shim.Error("Invalid invoke function name.")
}


//query public key of user account

func (t *IDChaincode) register(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) != 2 {
		logger.Error("wrong parameters")
		return shim.Error("wrong parameters")
	}

	pubkey := args[0]
	Addr := calcAddr(pubkey)
	UserPubKey, err := stub.GetState(Addr)
	if err != nil {
		logger.Error("Error on query addr")
		return shim.Error("fail to query addr")
	}

	if UserPubKey != nil {
		logger.Error("addr already register")
		return shim.Error("addr already register")
	}

	err = stub.PutState(Addr, []byte(pubkey))
	if err != nil {
		logger.Error("Error on store user pubkey: ", err.Error())
		return shim.Error("Error on store user pubkey: " + err.Error())
	}

	return shim.Success([]byte(pubkey))
}

func (t *IDChaincode) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) != 1 {
		logger.Error("wrong parameters")
		return shim.Error("wrong parameters")
	}

	Addr := args[0]
	UserPubKey, err := stub.GetState(Addr)
	if err != nil {
		logger.Error("Error on query addr")
		return shim.Error("fail to query addr")
	}

	if UserPubKey == nil {
		logger.Error("addr is not register")
		return shim.Error("addr is not register")
	}

	//check addr match pub key
	hash := calcAddr(string(UserPubKey))

	if strings.Compare(hash, Addr) != 0 {
		logger.Error("addr is not match public key in chaincode" + string(UserPubKey))
		return shim.Error("addr is not match public key in chaincode:%s" + string(UserPubKey))
	}

	return shim.Success([]byte(UserPubKey))
}

func calcAddr(cont string) string {

	Hasher := crypto.SHA256.New()
	Hasher.Write([]byte(cont))
	HashRes := Hasher.Sum(nil)

	return hex.EncodeToString(HashRes)
}

func main() {
	logger.Debug("start ID  chaincode")
	err := shim.Start(new(IDChaincode))
	if err != nil {
		logger.Error("Error starting ID  chaincode: ", err.Error())
	}
}
