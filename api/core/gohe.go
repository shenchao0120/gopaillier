package gohe

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var one = big.NewInt(1)

// ErrMessageTooLong is returned when attempting to encrypt a message which is
// too large for the size of the public key.
var ErrMessageTooLong = errors.New("paillier: message too long for Paillier public key size")

// GenerateKey generates an Paillier keypair of the given bit size using the
// random source random (for example, crypto/rand.Reader).
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	p, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// n = p * q
	n := new(big.Int).Mul(p, q)

	// l = phi(n) = (p-1) * q(-1)
	l := new(big.Int).Mul(
		new(big.Int).Sub(p, one),
		new(big.Int).Sub(q, one),
	)

	return &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        new(big.Int).Add(n, one), // g = n + 1
		},
		L: l,
		U: new(big.Int).ModInverse(l, n),
	}, nil
}

// PrivateKey represents a Paillier key.
type PrivateKey struct {
	PublicKey
	L *big.Int // phi(n), (p-1)*(q-1)
	U *big.Int // l^-1 mod n
}

// PublicKey represents the public part of a Paillier key.
type PublicKey struct {
	N        *big.Int // modulus
	G        *big.Int // n+1, since p and q are same length
	NSquared *big.Int
}

// specific private key.
type specPrivateKey struct {
	Version int
	N       *big.Int
	G       *big.Int
	P       *big.Int
	L       *big.Int
	U       *big.Int
}

type specPublicKey struct {
	N *big.Int
	G *big.Int
}

// Encrypt encrypts a plain text represented as a byte array. The passed plain
// text MUST NOT be larger than the modulus of the passed public key.
func Encrypt(pubKeyBytes []byte, plainText []byte) ([]byte, error) {

	pubKey,err:=ParsePublicKey(pubKeyBytes)
	if err != nil {
		return nil,err
	}

	r, err := rand.Prime(rand.Reader, pubKey.N.BitLen())
	if err != nil {
		return nil, err
	}

	m := new(big.Int).SetBytes(plainText)
	if pubKey.N.Cmp(m) < 1 { // N < m
		return nil, ErrMessageTooLong
	}

	// c = g^m * r^n mod n^2
	n := pubKey.N
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(pubKey.G, m, pubKey.NSquared),
			new(big.Int).Exp(r, n, pubKey.NSquared),
		),
		pubKey.NSquared,
	)

	return c.Bytes(), nil
}

// Decrypt decrypts the passed cipher text.
func Decrypt(privKeyBytes []byte, cipherText []byte) ([]byte, error) {

	privKey,err:=ParsePrivateKey(privKeyBytes)
	if err != nil {
		return nil,err
	}

	c := new(big.Int).SetBytes(cipherText)
	if privKey.NSquared.Cmp(c) < 1 { // c < n^2
		return nil, ErrMessageTooLong
	}

	// c^l mod n^2
	a := new(big.Int).Exp(c, privKey.L, privKey.NSquared)

	// L(a)
	// (a - 1) / n
	l := new(big.Int).Div(
		new(big.Int).Sub(a, one),
		privKey.N,
	)

	// m = L(c^l mod n^2) * u mod n
	m := new(big.Int).Mod(
		new(big.Int).Mul(l, privKey.U),
		privKey.N,
	)

	return m.Bytes(), nil
}

// AddCipher homomorphically adds together two cipher texts.
// To do this we multiply the two cipher texts, upon decryption, the resulting
// plain text will be the sum of the corresponding plain texts.
func AddCipher(pubKeyBytes []byte, cipher1, cipher2 []byte) ([]byte,error) {

	pubKey,err:=ParsePublicKey(pubKeyBytes)
	if err != nil {
		return nil,err
	}
	x := new(big.Int).SetBytes(cipher1)
	y := new(big.Int).SetBytes(cipher2)

	// x * y mod n^2
	return new(big.Int).Mod(
		new(big.Int).Mul(x, y),
		pubKey.NSquared,
	).Bytes(),nil
}

func SubCipher(pubKeyBytes []byte, cipher1, cipher2 []byte) ([]byte,error){
	pubKey,err:=ParsePublicKey(pubKeyBytes)
	if err != nil {
		return nil,err
	}

	x := new(big.Int).SetBytes(cipher1)
	y := new(big.Int).SetBytes(cipher2)

	neg := new(big.Int).ModInverse(y, pubKey.NSquared)
	m := new(big.Int).Mul(x, neg)
	return new(big.Int).Mod(m, pubKey.NSquared).Bytes(),nil
}

// Add homomorphically adds a passed constant to the encrypted integer
// (our cipher text). We do this by multiplying the constant with our
// ciphertext. Upon decryption, the resulting plain text will be the sum of
// the plaintext integer and the constant.
func Add(pubKeyBytes []byte, cipher, constant []byte) ([]byte,error) {
	pubKey,err:=ParsePublicKey(pubKeyBytes)
	if err != nil {
		return nil,err
	}

	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c * g ^ x mod n^2
	return new(big.Int).Mod(
		new(big.Int).Mul(c, new(big.Int).Exp(pubKey.G, x, pubKey.NSquared)),
		pubKey.NSquared,
	).Bytes(),nil
}

// Mul homomorphically multiplies an encrypted integer (cipher text) by a
// constant. We do this by raising our cipher text to the power of the passed
// constant. Upon decryption, the resulting plain text will be the product of
// the plaintext integer and the constant.
func Mul(pubKeyBytes []byte, cipher []byte, constant []byte) ([]byte,error) {
	pubKey,err:=ParsePublicKey(pubKeyBytes)
	if err != nil {
		return nil,err
	}
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c ^ x mod n^2
	return new(big.Int).Exp(c, x, pubKey.NSquared).Bytes(),nil
}

func MarshalPrivateKey(key *PrivateKey) []byte {

	spec := specPrivateKey{
		Version: 1,
		N:       key.PublicKey.N,
		G:       key.PublicKey.G,
		P:       key.PublicKey.NSquared,
		L:       key.L,
		U:       key.U,
	}

	b, _ := asn1.Marshal(spec)

	return b
}

// MarshalPublicKey serialises a public key to DER-encoded  format.
func MarshalPublicKey(pub *PublicKey) []byte {

	spec := specPublicKey{
		N: pub.N,
		G: pub.G,
	}

	b, _ := asn1.Marshal(spec)
	return b
}

func ParsePrivateKey(key []byte) (*PrivateKey, error) {

	block, _ := pem.Decode(key)

	var spec specPrivateKey
	res, err := asn1.Unmarshal(block.Bytes, &spec)

	if err != nil {
		return nil, err
	}
	if len(res) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	privkey := &PrivateKey{PublicKey{spec.N, spec.G, spec.P}, spec.L, spec.U}

	return privkey, nil
}

func ParsePublicKey(key []byte) (*PublicKey, error) {
	block, _ := pem.Decode(key)

	var spec specPublicKey
	res, err := asn1.Unmarshal(block.Bytes, &spec)
	if err != nil {
		return nil, err
	}
	if len(res) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	pubkey := &PublicKey{spec.N, spec.G, new(big.Int).Mul(spec.N, spec.N)}

	return pubkey, nil
}

func GenPemPublicKey(pub *PublicKey) []byte {

	marshalBytes := MarshalPublicKey(pub)
	block := &pem.Block{
		Type:  "public key",
		Bytes: marshalBytes,
	}

	var buffer bytes.Buffer

	err := pem.Encode(&buffer, block)
	if err != nil {
		fmt.Println(err)
	}
	return buffer.Bytes()
}

func GenPemPrivateKey(key *PrivateKey) []byte {
	marshalBytes := MarshalPrivateKey(key)
	block := &pem.Block{
		Type:  "private key",
		Bytes: marshalBytes,
	}

	var buffer bytes.Buffer

	err := pem.Encode(&buffer, block)
	if err != nil {
		fmt.Println(err)
	}
	return buffer.Bytes()
}

