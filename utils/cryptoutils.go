/************
*	File implementing multiple cryptographic support for the implementation
*
*	Author: Jose Jesus Sanchez Gomez (sanchezg@lcc.uma.es)
*	2021, NICS Lab (University of Malaga)
*
*************/

package utils

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Gets rsa key in pem format and decodes it into rsa.privatekey
func PemDecodeRSA(pemKey string, privKey **rsa.PrivateKey) error {
	pemBlock, _ := pem.Decode([]byte(pemKey)) // Gets pem_block from raw key
	// Checking key type and correct decodification
	if pemBlock == nil {
		return errors.New("private key not found or is not in pem format")
	}
	if pemBlock.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("invalid private key, wrong type: %T", pemBlock.Type)
	}
	// Parses obtained pem block
	var parsedKey interface{} //Still dont know what key type we need to parse
	parsedKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		parsedKey, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return err //errors.New("Unable to parse RSA private key")
		}
	}
	// Gets private key from parsed key
	*privKey = parsedKey.(*rsa.PrivateKey)
	return nil
}

// Gets rsa pub key in pem format and decodes it into rsa.publickey
func PemDecodeRSAPub(pemKey string, pubKey **rsa.PublicKey) error {
	pemBlock, _ := pem.Decode([]byte(pemKey))
	if pemBlock == nil {
		return errors.New("public Key not found or is not in pem format")
	}
	if (pemBlock.Type != "RSA PUBLIC KEY") && (pemBlock.Type != "PUBLIC KEY") {
		return fmt.Errorf("invalid public key, wrong type: %s", pemBlock.Type)
	}
	var parsedKey interface{}
	parsedKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		parsedKey, err = x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return err
		}
	}
	*pubKey = parsedKey.(*rsa.PublicKey)
	return nil
}

// Gets ECDSA key in pem format and decodes it into ecdsa.PrivateKey
func PemDecodeECDSA(pemKey string, privKey **ecdsa.PrivateKey) error {
	pemBlock, _ := pem.Decode([]byte(pemKey))
	if pemBlock == nil {
		return errors.New("private key not found or is not in pem format")
	}
	if pemBlock.Type != "EC PRIVATE KEY" {
		return fmt.Errorf("invalid private key, wrong type: %T", pemBlock.Type)
	}
	var parsedKey interface{}
	parsedKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		parsedKey, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return err
		}
	}
	*privKey = parsedKey.(*ecdsa.PrivateKey)
	return nil
}

// Generates RSA private key of given size
func GenRsaKey(size int, privKey **rsa.PrivateKey) error {
	if size%8 != 0 || size < 2048 {
		size = 2048
	}
	auxKey, err := rsa.GenerateKey(rand.Reader, size)
	*privKey = auxKey
	if err != nil {
		return err
	}
	return nil
}

// Generates ECDSA private Key of Curve
func GenEcdsaKey(curve elliptic.Curve, privKey **ecdsa.PrivateKey) error {
	auxKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	*privKey = auxKey
	return nil
}

// Gets rsa private key from pem file
func ImportRsaKey(filename string, privKey **rsa.PrivateKey) error {
	privFile, err := os.Open(filename)
	if err != nil {
		return err
	}
	prvFileInfo, err := privFile.Stat() // Gets info of io
	if err != nil {
		return err
	}
	prvBytes := make([]byte, prvFileInfo.Size())
	prvBuffer := bufio.NewReader(privFile)
	_, err = prvBuffer.Read(prvBytes)
	if err != nil {
		return err
	}
	err = PemDecodeRSA(string(prvBytes), privKey)
	return err
}

// Gets rsa public ket from pem file
func ImportRsaPubKey(filename string, pubKey **rsa.PublicKey) error {
	pubFile, err := os.Open(filename)
	if err != nil {
		return err
	}
	pubFileInfo, err := pubFile.Stat()
	if err != nil {
		return err
	}
	pubBytes := make([]byte, pubFileInfo.Size())
	pubBuffer := bufio.NewReader(pubFile)
	_, err = pubBuffer.Read(pubBytes)
	if err != nil {
		return err
	}
	err = PemDecodeRSAPub(string(pubBytes), pubKey)
	return err
}

// Gets ecdsa private key from pem file
func ImportEcdsaKey(filename string, privKey **ecdsa.PrivateKey) error {
	privFile, err := os.Open(filename)
	if err != nil {
		return err
	}
	prvFileInfo, err := privFile.Stat() // Gets info of io
	if err != nil {
		return err
	}
	prvBytes := make([]byte, prvFileInfo.Size())
	prvBuffer := bufio.NewReader(privFile)
	_, err = prvBuffer.Read(prvBytes)
	if err != nil {
		return err
	}
	err = PemDecodeECDSA(string(prvBytes), privKey)
	return err
}

// Returns RSA Keys as string in PEM format
func PemEncodeRSA(privKey *rsa.PrivateKey) (strPrivKey string, strPubKey string, err error) {
	// Creates pem block from given key
	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	// Encodes pem block to byte buffer, then gets the string from it
	privBuf := new(bytes.Buffer)
	err = pem.Encode(privBuf, &privBlock)
	if err != nil {
		return
	}
	strPrivKey = privBuf.String()

	// Same with public key
	pubBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privKey.PublicKey),
	}
	pubBuf := new(bytes.Buffer)
	err = pem.Encode(pubBuf, &pubBlock)
	if err != nil {
		return
	}
	strPubKey = pubBuf.String()
	return
}

// Returns ECDSA Keys as string in PEM format
func PemEncodeECDSA(privKey *ecdsa.PrivateKey) (strPrivKey string, strPubKey string, err error) {
	byteKey, _ := x509.MarshalECPrivateKey(privKey)
	privBlock := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: byteKey,
	}
	buf := bytes.NewBuffer(nil)
	if err = pem.Encode(buf, &privBlock); err != nil {
		return
	}
	strPrivKey = buf.String()
	buf.Reset()
	byteKey, _ = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubBlock := pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: byteKey,
	}
	if err = pem.Encode(buf, &pubBlock); err != nil {
		return
	}
	strPubKey = buf.String()
	return
}

// Export KeyPair to files named as given (ECDSA and RSA supported, pointers to privKey must be given)
func ExportKeyPair(privKey crypto.PrivateKey, privFileName string, pubFileName string) error {
	switch typ := privKey.(type) {
	case *rsa.PrivateKey:
		rsaPriv, _ := privKey.(*rsa.PrivateKey)
		if privFileName != "" {
			privBlock := pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(rsaPriv),
			}
			privFile, err := os.Create(privFileName) //".rsa"
			if err != nil {
				return err
			}
			defer privFile.Close()
			err = pem.Encode(privFile, &privBlock)
			if err != nil {
				return err
			}
		}
		if pubFileName != "" {
			pubBlock := pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(&rsaPriv.PublicKey),
			}
			pubFile, err := os.Create(pubFileName) // + ".rsa.pub"
			if err != nil {
				return err
			}
			defer pubFile.Close()
			err = pem.Encode(pubFile, &pubBlock)
			if err != nil {
				return err
			}
		}

	case *ecdsa.PrivateKey:
		ecdsaPriv, _ := privKey.(*ecdsa.PrivateKey)
		if privFileName != "" {
			ecdsaByt, _ := x509.MarshalECPrivateKey(ecdsaPriv)
			privBlock := pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: ecdsaByt,
			}
			privFile, err := os.Create(privFileName) //+ ".ec"
			if err != nil {
				return err
			}
			defer privFile.Close()
			err = pem.Encode(privFile, &privBlock)
			if err != nil {
				return err
			}
		}
		if pubFileName != "" {
			ecdsaByt2, _ := x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
			pubBlock := pem.Block{
				Type:  "EC PUBLIC KEY",
				Bytes: ecdsaByt2,
			}
			pubFile, err := os.Create(pubFileName) // + ".ec.pub"
			if err != nil {
				return err
			}
			defer pubFile.Close()
			err = pem.Encode(pubFile, &pubBlock)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("key type not supported: %T", typ)
	}
	return nil
}

// Implements all methods to interact with JWK
type JsonWebKey struct {
	Thumb  string `json:"-"`
	Type   string `json:"kty"`
	Use    string `json:"use,omitempty"`
	PubMod string `json:"n,omitempty"`   // RSA
	PubExp string `json:"e,omitempty"`   // RSA
	Curve  string `json:"crv,omitempty"` //ECDSA
	Xcoord string `json:"x,omitempty"`   //ECDSA
	Ycoord string `json:"y,omitempty"`   //ECDSA
}

// Initializes json web key from public key
func (jkey *JsonWebKey) Initialize(pubKey crypto.PublicKey, use string) error {
	//jkey.Use = "sig"
	jkey.Use = use
	switch typ := pubKey.(type) {
	case *rsa.PublicKey:
		jkey.Type = "RSA"
		rsaPubKey := pubKey.(*rsa.PublicKey)
		jkey.PubExp = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPubKey.E)).Bytes()) // To get it as bytes, we first convert to big int, which has a method Bytes()
		jkey.PubMod = base64.RawURLEncoding.EncodeToString(rsaPubKey.N.Bytes())
	case *ecdsa.PublicKey:
		jkey.Type = "EC"
		ecdsaPubKey := pubKey.(*ecdsa.PublicKey)
		jkey.Curve = fmt.Sprintf("P-%v", ecdsaPubKey.Curve.Params().BitSize)
		jkey.Xcoord = base64.RawURLEncoding.EncodeToString(ecdsaPubKey.X.Bytes())
		jkey.Ycoord = base64.RawURLEncoding.EncodeToString(ecdsaPubKey.Y.Bytes())
	default:
		return fmt.Errorf("error: can not initialize jwk with pubkey of type: %T", typ)
	}
	jkey.Thumb = jkey.GenThumbprint()
	return nil
}

func (jkey *JsonWebKey) GenThumbprint() string {
	var thumbprint string
	switch jkey.Type {
	case "RSA":
		JsonRecursiveMarshall("e", jkey.PubExp, &thumbprint)
		JsonRecursiveMarshall("kty", jkey.Type, &thumbprint)
		JsonRecursiveMarshall("n", jkey.PubMod, &thumbprint)
	case "ECDSA":
		JsonRecursiveMarshall("crv", jkey.Curve, &thumbprint)
		JsonRecursiveMarshall("kty", jkey.Type, &thumbprint)
		JsonRecursiveMarshall("x", jkey.Xcoord, &thumbprint)
		JsonRecursiveMarshall("y", jkey.Ycoord, &thumbprint)
	}
	// For the thumbprint, now SHA-256, then encode into Base-64
	sha256Hash := sha256.Sum256([]byte(thumbprint))
	return base64.RawURLEncoding.EncodeToString(sha256Hash[:])
	// Strings in go are UTF-8, so we could get thumbprint (RFC7638) Using MD-5 hash (), RFC7638 recommends SHA256
	//md5hash := md5.Sum([]byte(jkey.Thumb))
	//jkey.Thumb = string(base64.RawURLEncoding.EncodeToString(md5hash[:]))
}

//	Gets the received JWK and unmarshalls it, returns error if fails to unmarshall
func (jkey *JsonWebKey) Unmarshall(rcv string) error {
	err := json.Unmarshal([]byte(rcv), jkey)
	if err != nil {
		return err
	}
	jkey.Thumb = jkey.GenThumbprint()
	return err
}

// From JsonWebKey struct, returns marshalled text
func (jkey *JsonWebKey) Marshal() string {
	marsh, err := json.Marshal(jkey)
	if err != nil {
		return ""
	}
	return string(marsh[:])
}

// POP Token is a especial type of JWT. Because of that,
type PopToken struct {
	HeaderClaims  map[string]string // TYP, ALG, JWK
	PayloadClaims map[string]string // IAT, JTI
	Jwk           JsonWebKey
	Jwt           JsonWebToken
}

// Gets the received token as string, and unmarshalls it. JWK, JWT and claims fields are all filled
func (popToken *PopToken) Unmarshal(token string) error {
	popToken.HeaderClaims = make(map[string]string)
	popToken.PayloadClaims = make(map[string]string)
	// Decodes full token into header and payload
	popToken.Jwt.DecodeFromFull(token)
	// Starting with header
	var headerMap map[string]json.RawMessage
	err := json.Unmarshal([]byte(popToken.Jwt.Header), &headerMap)
	if err != nil {
		return err
	}
	for key, value := range headerMap {
		popToken.HeaderClaims[key] = string(value[1 : len(value)-1])
	}
	popToken.HeaderClaims["jwk"] = string(headerMap["jwk"]) // Key must be unmarshalled
	// Then we decode the key
	if err := popToken.Jwk.Unmarshall(popToken.HeaderClaims["jwk"]); err != nil {
		return errors.New("can not decode key in poptoken")
	}
	// Continue with payload
	var payloadMap map[string]json.RawMessage
	err = json.Unmarshal([]byte(popToken.Jwt.Payload), &payloadMap)
	for key, value := range payloadMap {
		popToken.PayloadClaims[key] = string(value[1 : len(value)-1])
	}
	return err
}

// Initializes popToken from claims and public key. Make sure the private key used to sign is the same used to initialize
func (popToken *PopToken) Initialize(headerMap, payloadMap map[string]string, pubKey crypto.PublicKey) error {
	popToken.HeaderClaims = make(map[string]string)
	popToken.PayloadClaims = make(map[string]string)
	// Copy header
	for key, value := range headerMap {
		popToken.HeaderClaims[key] = value
	}
	// Sets header typ
	popToken.HeaderClaims["typ"] = "dpop+jwt"
	for key, value := range payloadMap {
		popToken.PayloadClaims[key] = value
	}
	// Sets header alg
	switch pubKey.(type) {
	case *rsa.PublicKey:
		popToken.HeaderClaims["alg"] = "RS256"
	case *ecdsa.PublicKey:
		popToken.HeaderClaims["alg"] = "ES256"
	}
	// Initializes jwk var + sets header jwk
	if err := popToken.Jwk.Initialize(pubKey, "sign"); err != nil {
		return err
	}
	popToken.HeaderClaims["jwk"] = popToken.Jwk.Marshal()
	// Copy payload
	for key, value := range payloadMap {
		popToken.PayloadClaims[key] = value
	}
	return nil
}

// Generates popToken from PrivateKey, can be used even if popToken is not created / initialized
func (popToken PopToken) GenerateToken(privKey crypto.PrivateKey) (token string, err error) {
	// Initialization if is not
	if popToken.HeaderClaims == nil {
		if rsaPriv, ok := privKey.(*rsa.PrivateKey); ok {
			if err = popToken.Initialize(nil, nil, &rsaPriv.PublicKey); err != nil {
				return
			}
		} else if ecdsaPriv, ok := privKey.(*ecdsa.PrivateKey); ok {
			if err = popToken.Initialize(nil, nil, &ecdsaPriv.PublicKey); err != nil {
				return
			}
		} else {
			err = errors.New("error: invalid key for signature, type not compatible")
			return
		}
	}
	// New payload claims: iat + jti
	iat := int((time.Now().Unix()))
	popToken.PayloadClaims["iat"] = strconv.Itoa(iat)
	//No need to use exp, servers will check iat + jti to check the validity
	//popToken.PayloadClaims["exp"] = strconv.Itoa(iat + 30)
	unparsedId, err := uuid.NewRandom()
	if err != nil { // Better way to generate uuid than calling an ext program
		return
	}
	popToken.PayloadClaims["jti"] = unparsedId.String()
	// Marshal header (must be in order)
	iterator := []string{"typ", "alg", "jwk"}
	for _, iter := range iterator {
		popToken.Jwt.AddHeader(iter, popToken.HeaderClaims[iter])
		delete(popToken.HeaderClaims, iter) // Delete so it does not repeat
	}
	for key, value := range popToken.HeaderClaims {
		popToken.Jwt.AddHeader(key, value)
	}
	// Mashal payload
	for key, value := range popToken.PayloadClaims {
		popToken.Jwt.AddClaim(key, value)
	}
	// Sign the token
	if err = popToken.Jwt.AssymSign(privKey); err != nil {
		return
	}
	return popToken.Jwt.GetFullToken(), nil
}

func (popToken PopToken) GetPubRsa() (*rsa.PublicKey, error) {
	pubKey := new(rsa.PublicKey)
	// Decode n and e
	byteN, err := base64.RawURLEncoding.DecodeString(popToken.Jwk.PubMod)
	if err != nil {
		return pubKey, err
	}
	byteE, err := base64.RawURLEncoding.DecodeString(popToken.Jwk.PubExp)
	if err != nil {
		return pubKey, err
	}
	// Converts n and e to big int and int
	e := new(big.Int)
	e.SetBytes(byteE)
	pubKey.N = new(big.Int)
	pubKey.N.SetBytes(byteN)
	pubKey.E = int(e.Int64())
	return pubKey, nil
}

func (popToken PopToken) GetPubEcdsa() (*ecdsa.PublicKey, error) {
	pubKey := new(ecdsa.PublicKey)
	// Curve. Only P-256 is supported at the moment
	switch popToken.Jwk.Curve {
	case "P-256":
		pubKey.Curve = elliptic.P256()
	default:
		return nil, errors.New("Curve " + popToken.Jwk.Curve + " not supported")
	}
	byteXCoord, err := base64.RawURLEncoding.DecodeString(popToken.Jwk.Xcoord)
	if err != nil {
		return nil, err
	}
	byteYCoord, err := base64.RawURLEncoding.DecodeString(popToken.Jwk.Ycoord)
	if err != nil {
		return nil, err
	}
	pubKey.X = new(big.Int)
	pubKey.X.SetBytes(byteXCoord)
	pubKey.Y = new(big.Int)
	pubKey.Y.SetBytes(byteYCoord)

	return pubKey, nil
}

// Validates keys: same alg, same thumprint...
func (popToken PopToken) CheckThumb(thumprint string) (bool, string) {
	if thumprint != "" || thumprint != popToken.Jwk.Thumb {
		return false, "Invalid Thumbprint"
	}
	return true, "ok"
}

func (popToken *PopToken) CheckAud(aud string) (bool, string) {
	if valid := popToken.PayloadClaims["aud"] == aud; !valid {
		return false, "Aud not valid"
	}
	return true, ""
}

// Checks signature, checks that alg used to sign is the same as in key (to avoid exploits)
func (popToken *PopToken) CheckSignature() error {
	switch popToken.HeaderClaims["alg"] {
	case "RS256":
		rsaPubKey, err := popToken.GetPubRsa()
		if err != nil {
			return err
		}
		return popToken.Jwt.CheckAssymSignature(rsaPubKey)
	case "ES256":
		ecdsaPubKey, err := popToken.GetPubEcdsa()
		if err != nil {
			return err
		}
		return popToken.Jwt.CheckAssymSignature(ecdsaPubKey)
	default:
		return errors.New("Invalid signing algorithm: " + popToken.HeaderClaims["alg"])
	}
}

// Check exp time
func (popToken PopToken) CheckExp() (bool, string) {
	exp, err := strconv.Atoi(popToken.PayloadClaims["exp"])
	if err != nil {
		return false, "No exp claim"
	}
	act := int(time.Now().Unix())
	if act > exp {
		return false, "Expired"
	}
	return true, "OK"
}

// Check iats. Gap is the possible error between clocks. lifetime is the maximum time after is creation that the token can be used
func (popToken PopToken) CheckIat(gap int, lifetime int) (bool, string) {
	act := int(time.Now().Unix())
	iat, err := strconv.Atoi(popToken.PayloadClaims["iat"])
	if err != nil {
		return false, "No iat claim"
	}
	if iat-gap >= act { // Iat marks before the actual time
		return false, "Bad iat"
	}

	if act > iat+lifetime+gap { // Check if token is still valid
		return false, "Expired"
	}
	return true, "OK"
}

// Returns a bool that tells if the pop token is valid.
func (popToken *PopToken) Validate(thumbprint, aud string, gap, lifetime int) (valid bool, info string) {
	// Validates time
	if valid, info = popToken.CheckIat(gap, lifetime); !valid {
		return
	}
	//if valid, info = popToken.CheckExp(); !valid {
	//	return
	//}
	// Makes sure to exist claim "aud"
	if valid, info = popToken.CheckAud(aud); !valid {
		return
	}
	// Checks key
	if valid, info = popToken.CheckThumb(thumbprint); !valid {
		return
	}
	// Checks signature
	if err := popToken.CheckSignature(); err != nil {
		return false, fmt.Sprintf("%v", err)
	}
	return valid, info
}
