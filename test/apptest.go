package main

import (
	//"crypto/rand"
	paillier "chaoshen.com/gopaillier/api/core"
	"github.com/op/go-logging"
	//"strconv"
	"math/big"
	"fmt"
	"io/ioutil"
)

var logger =logging.MustGetLogger("main")

func main(){
	privByte,err:=ioutil.ReadFile("core/priv.pem")
	if err != nil {
		fmt.Println(err)
	}


	pubByte,err:=ioutil.ReadFile("core/pub.pem")
	if err != nil {
		fmt.Println(err)
	}
	pubKey,err:=paillier.ParsePublicKey(pubByte)
	if err != nil {
		fmt.Println(err)
	}

	privKey.PublicKey=*pubKey
	//privKey, _ := paillier.GenerateKey(rand.Reader, 128)
	m15 := new(big.Int).SetInt64(-1)
	m150 := new(big.Int).SetInt64(1500000)

	c15, _ := paillier.Encrypt(&privKey.PublicKey, m15.Bytes())
	fmt.Println(c15)
	c150, _ := paillier.Encrypt(&privKey.PublicKey, m150.Bytes())


	// Decrypt the number "15".
	d, _ := paillier.Decrypt(privKey, c15)
	plainText := new(big.Int).SetBytes(d)
	fmt.Println("Decryption Result of 15: ", plainText.String()) // 15


	// Encrypt the number "20".
	m20 := new(big.Int).SetInt64(20)
	c20, _ := paillier.Encrypt(&privKey.PublicKey, m20.Bytes())

	// Add the encrypted integers 15 and 20 together.
	plusM150M20 := paillier.AddCipher(&privKey.PublicKey, c150, c20)
	decryptedAddition, _ := paillier.Decrypt(privKey, plusM150M20)
	fmt.Println("Result of 150+20 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 35!

	subM20M15:=paillier.SubCipher(&privKey.PublicKey,c20,c15)

	decryptedSub, _ := paillier.Decrypt(privKey, subM20M15)
	fmt.Println("Result of 20-15 after decryption: ",
		new(big.Int).SetBytes(decryptedSub).String(),"AAAA",decryptedSub)

	mulM15:=paillier.Mul(&privKey.PublicKey,c15,new(big.Int).SetInt64(20).Bytes())

	decryptedMul,err:=paillier.Decrypt(privKey,mulM15)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Result of 15*20 after decryption: ",
	new(big.Int).SetBytes(decryptedMul).String())
	/*
	// Add the encrypted integer 15 to plaintext constant 10.
	plusE15and10 := paillier.Add(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedAddition, _ = paillier.Decrypt(privKey, plusE15and10)
	fmt.Println("Result of 15+10 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 25!

	// Multiply the encrypted integer 15 by the plaintext constant 10.
	mulE15and10 := paillier.Mul(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedMul, _ := paillier.Decrypt(privKey, mulE15and10)
	fmt.Println("Result of 15*10 after decryption: ",
		new(big.Int).SetBytes(decryptedMul).String()) // 150!
	*/




}
