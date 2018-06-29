package gohe

import (
	"testing"
	"fmt"
	"crypto/rand"
	"encoding/pem"
	"os"
	"io/ioutil"
)

func TestMarshalPrivateKey(t *testing.T) {
	privKey, _ := GenerateKey(rand.Reader, 128)

	fmt.Println(privKey)
	res:=MarshalPrivateKey(privKey)

	fmt.Println(res)
	block := &pem.Block{
		Type:  "私钥",
		Bytes: res,
	}
	file, err := os.Create("priv.pem")
	if err != nil {
		fmt.Println(err)
	}
	err = pem.Encode(file, block)
	if err != nil {
		fmt.Println(err)
	}

}

func TestGenPemPrivateKey(t *testing.T) {
	privKey, _ := GenerateKey(rand.Reader, 128)
	res:=GenPemPrivateKey(privKey)
	fmt.Println(res)
	file,err:=os.Create("priv.pem")
	file.WriteString(string(res))

	file2,err:=os.Create("pub.pem")
	defer file2.Close()
	if err != nil {
		fmt.Println(err)
	}
	pub:=GenPemPublicKey(&privKey.PublicKey)

	file2.WriteString(string(pub))

}

func TestParseKey(t *testing.T) {
	// Get private key
	privByte,err:=ioutil.ReadFile("priv.pem")
	if err != nil {
		fmt.Println(err)
	}
	privKey,err:=ParsePrivateKey(privByte)
	if err != nil {
		fmt.Println(err)
	}

	pubByte,err:=ioutil.ReadFile("pub.pem")
	if err != nil {
		fmt.Println(err)
	}
	pubKey,err:=ParsePublicKey(pubByte)
	if err != nil {
		fmt.Println(err)
	}
	cipher,err:=Encrypt(pubKey,[]byte("lalala  "))

	res,_:=Decrypt(privKey,cipher)
	fmt.Println("decode string",string(res))




}