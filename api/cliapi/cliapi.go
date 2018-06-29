package cliapi

import (
	"chaoshen.com/gopaillier/api/core"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	//"fmt"
)

type txInfo struct {
	CipherBalanceA []byte
	CipherTxA      []byte
	CipherTXB      []byte
	PubKeyA        []byte
	PubKeyB        []byte
}

func PrepareTxInfo(cipherBalanceA, transNumStr, pubKeyA, pubKeyB, privKeyA string) (txinfo []byte, err error) {

	// Check if the balance is enough
	balanceA, err := gohe.Decrypt([]byte(privKeyA), []byte(cipherBalanceA))
	amtA := new(big.Int).SetBytes(balanceA)
	// Parse transfer amount from string
	transNum ,err  := strconv.Atoi(transNumStr)
	if err != nil {
		return nil,err
	}
	transBigInt := new(big.Int).SetInt64(int64(transNum))
	//fmt.Println(amtA,transBigInt)
	result := new(big.Int).Sub(amtA, transBigInt)
	if result.Sign() < 0 {
		return nil, errors.New("Insufficient balance for transfer.")
	}
	// Encrypt the transfer amt

	CipherTxA, err := gohe.Encrypt([]byte(pubKeyA), transBigInt.Bytes())
	if err != nil {
		return nil, err
	}
	CipherTxB, err := gohe.Encrypt([]byte(pubKeyB), transBigInt.Bytes())
	if err != nil {
		return nil, err
	}

	tx := &txInfo{
		CipherBalanceA: []byte(cipherBalanceA),
		CipherTxA:      CipherTxA,
		CipherTXB:      CipherTxB,
		PubKeyA:        []byte(pubKeyA),
		PubKeyB:        []byte(pubKeyB),
	}

	txByte, err := json.Marshal(tx)
	if err != nil {
		return nil, err
	}
	return txByte, nil
}


func InitBalance (amount,pubKey string) (balanceInfo []byte ,err error) {
	amt,err:=strconv.Atoi(amount)
	if err != nil {
		return nil ,err
	}

	amtInt:=new(big.Int).SetInt64(int64(amt))
	balanceInfo, err = gohe.Encrypt([]byte(pubKey), amtInt.Bytes())
	if err != nil {
		return nil,err
	}
	return balanceInfo,nil
}