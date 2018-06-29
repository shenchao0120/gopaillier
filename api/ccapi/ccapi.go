package ccapi

import (
	"encoding/json"
	"errors"
	"chaoshen.com/gopaillier/api/core"
	//"strconv"
)

type txInfo struct {
	CipherBalanceA []byte
	CipherTxA      []byte
	CipherTXB      []byte
	PubKeyA        []byte
	PubKeyB        []byte
}

func ValidateTxInfo(txInfoStr, cipherBalanceA, cipherBalanceB string) (newCipherBalanceA,newCipherBalanceB string,err error){
	var ti txInfo
	err = json.Unmarshal([]byte(txInfoStr),&ti)
	if err != nil {
		return "","",err
	}
	// check whether the balance of account A has been changed
	if string(ti.CipherBalanceA) != cipherBalanceA{
		return "","",errors.New("The cipher balance has been changed.")
	}

	//  subtract cipher amount from account A
	newCipherBalanceAStr ,err:= gohe.SubCipher(ti.PubKeyA,ti.CipherBalanceA,ti.CipherTxA)

	if err != nil {
		return "","",err
	}

	//  Add cipher amount to account B
	newCipherBalanceBStr, err:= gohe.AddCipher(ti.PubKeyB,[]byte(cipherBalanceB),ti.CipherTXB)

	if err != nil {
		return "","",err
	}

	return string(newCipherBalanceAStr),string(newCipherBalanceBStr),nil
}


func ValidateInitBalance(balance, PubKey string) (cipherBalance string, err error){
	/*
	initBalance,err:=strconv.Atoi(balance)
	if err != nil {
		return "",err
	}
	if initBalance < 0 {
		return "", errors.New("The initial amount cannot be less than 0.")
	}

	cipherBal,err:=gohe.Encrypt([]byte(PubKey),[]byte(balance))
	if err != nil{
		return "",err
	}
	*/
	return balance,nil

}