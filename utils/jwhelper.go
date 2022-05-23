/************
*	File implementing some methods and variables that makes using JsonWebToken easier and more intuitive
*
*	Author: Jose Jesus Sanchez Gomez (sanchezg@lcc.uma.es)
*	2021, NICS Lab (University of Malaga)
*
*************/

package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Gets Json string (or nothing) and adds received key and value, if it doesnt receive a value or key, it does nothing
func JsonRecursiveMarshall(key string, value string, jplain *string) {
	if key == "" || value == "" {
		return
	}
	if !strings.HasPrefix(value, "{") { // If the value of the claim starts with "{", that means the claim has another json inside, wich must not be included between commas
		value = `"` + value + `"`
	}
	if *jplain == "" {
		*jplain = `{"` + key + `":` + value + `}`
	} else {
		*jplain = (*jplain)[:len(*jplain)-1] + `,"` + key + `":` + value + `}`
	}
}

type JsonWebToken struct {
	Header           string
	Payload          string
	EncodedHeader    string
	EncodedPayload   string
	EncodedSignature string
}

func (token *JsonWebToken) SetHeader(algorithm string) {
	token.Header = `{"alg":"` + algorithm + `","typ":"JWT"}`
}

func (token *JsonWebToken) AddHeader(key string, value string) {
	JsonRecursiveMarshall(key, value, &token.Header)
}

func (token *JsonWebToken) AddClaim(key string, value string) {
	JsonRecursiveMarshall(key, value, &token.Payload)
}

func (token *JsonWebToken) Encode() {
	token.EncodedHeader = base64.RawURLEncoding.EncodeToString([]byte(token.Header))
	token.EncodedPayload = base64.RawURLEncoding.EncodeToString([]byte(token.Payload))
}

func (token *JsonWebToken) AssymSign(privKey crypto.PrivateKey) error {
	token.Encode()
	var signature []byte
	var err error
	hashed := sha256.Sum256([]byte(token.EncodedHeader + "." + token.EncodedPayload)) //SHA 256 HASH
	switch typ := privKey.(type) {
	case *rsa.PrivateKey:
		rsaPriv, _ := privKey.(*rsa.PrivateKey)
		signature, err = rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA256, hashed[:])
		if err != nil {
			return err
		}
	case *ecdsa.PrivateKey: // https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
		ecdsaPriv, _ := privKey.(*ecdsa.PrivateKey)
		rSign, sSign, err := ecdsa.Sign(rand.Reader, ecdsaPriv, hashed[:])
		if err != nil {
			return err
		}
		signature = rSign.Bytes() // APPENDS r,s in big endian
		signature = append(signature, sSign.Bytes()...)
	default:
		return fmt.Errorf("error: can not sign jwt: invalid key type: %T", typ)
	}
	token.EncodedSignature = base64.RawURLEncoding.EncodeToString(signature)
	return nil
}

// Signs the token. In case of HS signature, string key must be given.
func (token *JsonWebToken) SymmSign(key string) {
	token.Encode()
	token.EncodedSignature = base64.RawURLEncoding.EncodeToString([]byte(GenerateHmac(token.EncodedHeader+"."+token.EncodedPayload, key)))
}

func (token JsonWebToken) GetFullToken() string {
	return token.EncodedHeader + "." + token.EncodedPayload + "." + token.EncodedSignature
}

func (token JsonWebToken) GetHeader() string {
	return token.Header
}

func (token JsonWebToken) GetPayload() string {
	return token.Payload
}

// From a signed jwt received, gets header and payload
func (token *JsonWebToken) DecodeFromFull(input string) error {
	parts := strings.Split(input, ".")
	if len(parts) != 3 {
		return errors.New("JWT not composed by 3 parts")
	}
	token.EncodedHeader = parts[0]
	token.EncodedPayload = parts[1]
	token.EncodedSignature = parts[2]
	header, err := base64.RawURLEncoding.DecodeString(token.EncodedHeader)
	if err != nil {
		return err
	}
	token.Header = string(header)
	payload, err := base64.RawURLEncoding.DecodeString(token.EncodedPayload)
	if err != nil {
		return err
	}
	token.Payload = string(payload)
	return nil
}

// Checks if the token is signed correctly. In case of HS, key as string must be given. In case of RSA, rsa.PubKey or PEM string can be given
func (token JsonWebToken) CheckSignature(key interface{}) error {
	if strings.Contains(token.Header, `HS256`) {
		strKey, ok := key.(string)
		if ok && base64.RawURLEncoding.EncodeToString([]byte(GenerateHmac(token.EncodedHeader+"."+token.EncodedPayload, strKey))) == token.EncodedSignature {
			return nil
		} else {
			return errors.New("invalid hs256 signature")
		}
	}
	return errors.New("invalid signing method")
}

func (token JsonWebToken) CheckAssymSignature(key crypto.PublicKey) (err error) {
	signature, err := base64.RawURLEncoding.DecodeString(token.EncodedSignature)
	if err != nil {
		return err
	}
	switch typ := key.(type) {
	case *rsa.PublicKey:
		pubKey := key.(*rsa.PublicKey)
		//Checks signature ParsePKIXPublicKey
		msgHasher := sha256.New()
		msgHasher.Write([]byte(token.EncodedHeader + "." + token.EncodedPayload))
		msgHash := msgHasher.Sum(nil)
		err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, msgHash, signature)
		return err
	case *ecdsa.PublicKey:
		pubKey := key.(*ecdsa.PublicKey)
		// https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
		if pubKey.Curve != elliptic.P256() {
			return errors.New("elliptic curve type not supported")
		}
		var r, s *big.Int
		r = new(big.Int)
		s = new(big.Int)
		r.SetBytes(signature[:32])
		s.SetBytes(signature[32:])
		// We have to hash the token to check it
		hashed := sha256.Sum256([]byte(token.EncodedHeader + "." + token.EncodedPayload))
		if !ecdsa.Verify(pubKey, hashed[:], r, s) {
			err = errors.New("invalid ecdsa signature")
		}
		return err
	default:
		return fmt.Errorf("public key alg not supported: %t", typ)
	}
}

type ExtendedJwt struct {
	Token         JsonWebToken
	HeaderClaims  map[string]string
	PayloadClaims map[string]string
}

func (ext *ExtendedJwt) DecodeFromFull(input string) error {
	err := ext.Token.DecodeFromFull(input)
	if err != nil {
		return err
	}
	err = json.Unmarshal([]byte(ext.Token.Header), &ext.HeaderClaims)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(ext.Token.Payload), &ext.PayloadClaims)
}
