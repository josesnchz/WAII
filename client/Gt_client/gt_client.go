/************
*	Grand Touring Client: AGT, AT and VissV2 client.
*
*
*	Author: Jose Jesus Sanchez Gomez (sanchezg@lcc.uma.es)
*	2021, NICS Lab (University of Malaga)
*
*************/

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/josesnchz/WAII/utils"
)

/*
const AGT_URL = "http://127.0.0.1:7500/agts"
const AT_URL = "http://127.0.0.1:8600/ats"
const VISS_GET_URL = "http://127.0.0.1:8888/" //....
*/
const AGT_URL = "http://agt_url:61057/agts"
const AT_URL = "http://at_url:61061/ats"
const VISS_GET_URL = "http://viss_url:61063/Vehicle/Cabin/Door/Row1/Right/IsOpen" //...
const VISS_WS_URL = "viss_url:61059/VISSv2"

type StringMap map[string]string
type TokenMap map[string]*utils.ExtendedJwt

// To associate tokens with a key
type NoPopList struct {
	agTokens TokenMap
	aTokens  TokenMap
}

type RsaList struct {
	privKey  *rsa.PrivateKey
	agTokens TokenMap
	aTokens  TokenMap
}
type EcdsaList struct {
	privKey  *ecdsa.PrivateKey
	agTokens TokenMap
	aTokens  TokenMap
}

func getUserInput() string {
	var input string
	fmt.Scanln(&input)
	return input
	/*
		reader := bufio.NewReader(os.Stdin)
		// Disable input buffer
		exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
		//Get the character
		input, err := reader.ReadByte()
		//Clear the line
		fmt.Println("\r     \r")
		if err != nil {
			return fmt.Sprint(err)
		}
		return fmt.Sprintf("%c", input)*/
}

// Makes a post request on the url given. Body must be given as string, header must be passed as map[string]string
func postRequest(url string, reqBody string, reqHeader StringMap) (string, error) {
	client := &http.Client{}
	// Creates a new request, body filled
	request, err := http.NewRequest("POST", url, bytes.NewBufferString(reqBody))
	if err != nil {
		return "", err
	}
	// Fills header
	request.Header.Add("content", "application/json") // Should be filled by the caller
	for param, content := range reqHeader {
		request.Header.Add(param, content)
	}
	// Sends the request
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	// Waits for func finalization to close the body
	defer response.Body.Close()
	// Reads the body and returns it
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

// Makes a post request on the url given. Body must be given as string, header must be passed as map[string]string
func getRequest(url string, reqBody string, reqHeader StringMap) (string, error) {
	client := &http.Client{}
	// Creates a new request, body filled
	request, err := http.NewRequest("GET", url, bytes.NewBufferString(reqBody))
	if err != nil {
		return "", err
	}
	// Fills header
	request.Header.Add("content", "application/json") // Should be filled by the caller
	for param, content := range reqHeader {
		request.Header.Add(param, content)
	}
	// Sends the request
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	// Waits for func finalization to close the body
	defer response.Body.Close()
	// Reads the body and returns it
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

// STRINGMAPS MANAGEMENT METHODS
func (claimMap StringMap) initAGTClaim() {
	claimMap[`vin`] = `GEO001`
	claimMap[`context`] = `Independent+OEM+Cloud`
	claimMap[`proof`] = `ABC`
}
func (claimMap StringMap) deleteClaim(key string) {
	delete(claimMap, key)
}
func (claimMap StringMap) addClaim(key string, value string) {
	claimMap[key] = value
}
func (claimMap StringMap) getFull() string {
	str := `{\n`
	for key, element := range claimMap {
		str = str + `\t"` + key + `" : "` + element + `",\n`
	}
	str = str + `}`
	return str
}
func (claimMap StringMap) generateReq() string {
	var req string
	for key, value := range claimMap {
		utils.JsonRecursiveMarshall(key, value, &req)
	}
	return req
}

// TOKEN MAPS METHODS
func (tokenMap *TokenMap) UnmarshalAdd(id string, res string) string {
	(*tokenMap)[id] = new(utils.ExtendedJwt)
	tempMap := make(map[string]string)
	err := json.Unmarshal([]byte(res), &tempMap)
	err2 := (*tokenMap)[id].DecodeFromFull(tempMap["token"])
	if err != nil || err2 != nil {
		delete((*tokenMap), id)
		return fmt.Sprintf("Token may not be valid, cannot decode: %s\n", err)
	}
	return fmt.Sprintf("Token with id %s saved \n", id)
}

func (tokenMap *TokenMap) Add(id string, tokenStr string) string {
	(*tokenMap)[id] = new(utils.ExtendedJwt)
	err := (*tokenMap)[id].DecodeFromFull(tokenStr)
	if err != nil {
		delete((*tokenMap), id)
		return fmt.Sprintf("Token may not be valid, cannot decode: %s\n", err)
	}
	return fmt.Sprintf("Token with id %s saved \n", id)
}

func (tokenMap *TokenMap) Show() string {
	var ret string
	for key, value := range *tokenMap {
		ret += fmt.Sprintf("- TOKEN ID:%s\n", key)
		indentedHead, err := json.MarshalIndent(value.HeaderClaims, "\t", "\t")
		if err != nil {
			ret += fmt.Sprintf("Cannot marshal token %s, It may not be valid.\n%s\n", key, value.Token.GetFullToken())
		} else {
			indentedPayl, err := json.MarshalIndent(value.PayloadClaims, "\t", "\t")
			if err != nil {
				ret += fmt.Sprintf("Cannot marshal token %s, It may not be valid.\n%s\n", key, value.Token.GetFullToken())
			} else {
				ret += fmt.Sprintf("\tHeader: \n\t%s\n", indentedHead)
				ret += fmt.Sprintf("\tPayload: \n\t%s\n", indentedPayl)
			}
		}
	}
	return ret
}

func (tokenMap *TokenMap) Delete(id string) string {
	_, exist := (*tokenMap)[id]
	if exist {
		delete(*tokenMap, id)
		return fmt.Sprintln("Deleted\n ")
	}
	return fmt.Sprintln("Id not found\n ")
}

func main() {
	//var pubKey1 rsa.PublicKey
	//var privKey2 rsa.PrivateKey
	//var pubKey2 rsa.PublicKey

	// To associate key with tokens received
	rsaList := new(RsaList)
	rsaList.agTokens = make(TokenMap)
	rsaList.aTokens = make(TokenMap)
	ecdsaList := new(EcdsaList)
	ecdsaList.agTokens = make(TokenMap)
	ecdsaList.aTokens = make(TokenMap)
	noPopList := new(NoPopList)
	noPopList.agTokens = make(TokenMap)
	noPopList.aTokens = make(TokenMap)
	// For AGT Requests
	AGTClaims := make(StringMap)
	AGTClaims.initAGTClaim()
	AGTPOPClaims := make(StringMap)
	AGTPOPClaims.addClaim("aud", "vissv2/agts")
	// For AT Requests
	ATClaims := make(StringMap)
	ATPOPClaims := make(StringMap)
	ATPOPClaims.addClaim("aud", "vissv2/ats")
	// For VISSV2 Requests
	VissClaims := make(StringMap)
	// FAST INITIALIZATION
	fmt.Println("---   GT CLIENT   ---\n\tPress 1 for fast initialization")
	if getUserInput() == "1" {
		fmt.Println("\tTrying to import keys ----")
		err := utils.ImportRsaKey("rsa_priv.rsa", &rsaList.privKey)
		if err != nil {
			fmt.Println("\tRSA not imported, generating key")
			err = utils.GenRsaKey(256, &rsaList.privKey)
			if err != nil {
				panic("Could not either generate key,")
			} else {
				fmt.Println("\tRSA key generated")
			}
		} else {
			fmt.Println("\tRSA key imported")
		}

		err = utils.ImportEcdsaKey("ecdsa_priv.ec", &ecdsaList.privKey)
		if err != nil {
			fmt.Println("\tECDSA not imported, generating key")
			err = utils.GenEcdsaKey(elliptic.P256(), &ecdsaList.privKey)
			if err != nil {
				panic("Could not either generate key,")
			} else {
				fmt.Println("\tECDSA key generated")
			}
		} else {
			fmt.Println("\tECDSA key imported\n ")
		}
	}

	for {
		fmt.Println("---   GT CLIENT   ---\n\t1 - Initialize client\n\t2 - AGT Server Communication\n\t3 - AT Server Communication \n\t4 - VISSv2 Server Communication")
		var Opt string
		Opt = "1"
		Opt = getUserInput()
		switch Opt {
		// Client initialization
		case "1":
			fmt.Println("CLIENT INITIALIZATION")
			fmt.Println("\t1 - Configure RSA Authentication\n\t2 - Configure ECDSA Authentication\n\t0 - Back to Main Menu")
			initOpt := "1"
			initOpt = getUserInput()
			switch initOpt {
			case "1": // RSA configuration
				var rsaOpt string
				for rsaOpt != "0" {
					fmt.Printf("RSA AUTHENTICATION CONFIGURATION -----\n  - RSA configured: %v", rsaList.privKey != nil)
					fmt.Printf("\n\t1 - Generate new RSA KeyPair\n\t2 - Print RSA KeyPair\n\t3 - Export RSA Keys\n\t4 - Import keys from file (name: rsa_priv.rsa)\n\t0 - Back to main menu\n")
					rsaOpt = getUserInput()
					//fmt.Scanln(&initOpt)
					switch rsaOpt {
					case "1": // New RSA Keypair
						err := utils.GenRsaKey(2048, &rsaList.privKey)
						if err != nil {
							fmt.Println("Couldn't generate RSA KeyPair")
						} else {
							fmt.Println("Key Generated correctly. RSA Configured Correctly")
						}
					case "2": // Print RSA Keys
						privStr, pubStr, err := utils.PemEncodeRSA(rsaList.privKey)
						if err != nil {
							fmt.Println("Couldn't get keys")
						} else {
							fmt.Printf("%s\n%s\n", privStr, pubStr)
						}
					case "3": // Export keys to file
						prvKeyFile := "rsa_priv"
						pubKeyFile := "rsa_pub"
						//fmt.Print("Private key filename (w/o ext.): ")
						//fmt.Scanln(&prvKeyFile)
						//fmt.Print("Public key filename: ")
						///fmt.Scanln(&pubKeyFile)
						err := utils.ExportKeyPair(rsaList.privKey, prvKeyFile, pubKeyFile)
						if err != nil {
							fmt.Printf("Could not export keys, error: %s", err)
						} else {
							fmt.Println("Keys exported correctly")
						}
					case "4": // Import keys from file
						err := utils.ImportRsaKey("rsa_priv.rsa", &rsaList.privKey)
						if err != nil {
							fmt.Printf("Could not import keys, error: %s\n", err)
						} else {
							fmt.Println("Keys imported correctly. RSA Configured\n ")
						}
					case "0":
						fmt.Println()
					default:
						fmt.Printf("Unknown input: %s", rsaOpt)
					}
				}
			case "2":
				var ecdsaOpt string
				for ecdsaOpt != "0" {
					fmt.Printf("ECDSA AUTHENTICATION CONFIGURATION -----\n  - ECDSA configured: %v", ecdsaList.privKey != nil)
					fmt.Printf("\n\t1 - Generate new ECDSA KeyPair\n\t2 - Print ECDSA KeyPair\n\t3 - Export ECDSA Keys\n\t4 - Import keys from file (name: ecdsa_priv.ec)\n\t0 - Back to main menu\n")
					ecdsaOpt = "1"
					ecdsaOpt = getUserInput()
					//fmt.Scanln(&initOpt)
					switch ecdsaOpt {
					case "1": // New Keypair
						err := utils.GenEcdsaKey(elliptic.P256(), &ecdsaList.privKey)
						if err != nil {
							fmt.Println("Couldn't generate ECDSA KeyPair")
						} else {
							fmt.Println("Key Generated correctly. ECDSA Configured")
						}
					case "2": // Print Keys
						privStr, pubStr, err := utils.PemEncodeECDSA(ecdsaList.privKey)
						if err != nil {
							fmt.Println("Couldn't get keys")
						} else {
							fmt.Printf("%s\n%s\n", privStr, pubStr)
						}
					case "3": // Export keys to file
						prvKeyFile := "ecdsa_priv"
						pubKeyFile := "ecdsa_pub"
						//fmt.Print("Private key filename (w/o ext.): ")
						//fmt.Scanln(&prvKeyFile)
						//fmt.Print("Public key filename: ")
						//fmt.Scanln(&pubKeyFile)
						err := utils.ExportKeyPair(ecdsaList.privKey, prvKeyFile, pubKeyFile)
						if err != nil {
							fmt.Printf("Could not export keys, error: %s", err)
						} else {
							fmt.Println("Keys exported correctly")
						}
					case "4": // Import keys from file
						err := utils.ImportEcdsaKey("ecdsa_priv.ec", &ecdsaList.privKey)
						if err != nil {
							fmt.Printf("\nCould not import keys, error: %s\n", err)
						} else {
							fmt.Println("Keys imported correctly. ECDSA Configured\n ")
						}
					case "0":
						fmt.Println()
					default:
						fmt.Printf("Unknown input: %s", ecdsaOpt)
					}
				}
			}
		case "2": // AGT Communication
			var agtOpt string
			for agtOpt != "0" {
				fmt.Println("AGT Communication\n\t1 - Send token request\n\t2 - Claims Management\n\t3 - Tokens received\n\t0 - Back to main menu")
				agtOpt = "1"
				agtOpt = getUserInput()
				switch agtOpt {
				case "1": // Send token Request
					var response, signMethod string
					var err error
					// Checks for signing methods avaliable
					if ecdsaList.privKey != nil || rsaList.privKey != nil {
						fmt.Printf("Request for long term is avaliable, what signature method do you want to use?")
						fmt.Printf("\n 1 - Not using LT")
						if rsaList.privKey != nil {
							fmt.Printf("\n 2 - RSA")
						}
						if ecdsaList.privKey != nil {
							fmt.Printf("\n 3 - ECDSA")
						}
						fmt.Printf("\n")
						signMethod = getUserInput()
					}
					switch signMethod {
					case "1", "n", "": // No long term
						postContent := AGTClaims.generateReq()
						fmt.Printf("No authentication being used \nSending POST Request to %s: \n%s\n", AGT_URL, postContent)
						response, err = postRequest(AGT_URL, postContent, nil)
						if err != nil {
							fmt.Printf("Error during POST Request sending: %s\n", err)
						} else if response != "" {
							fmt.Printf("\nPOST Response received: \n%s\nSave post response? y/n   ", response)
							if input := getUserInput(); input == "y" || input == "1" {
								fmt.Printf("ID: ")
								id := getUserInput()
								fmt.Printf("%s", noPopList.agTokens.UnmarshalAdd(id, response))
							}
						}
					case "2", "r": // RSA long term
						fmt.Println("RSA authentication being used. Generating POP Token")
						var popToken utils.PopToken
						var token string
						err = popToken.Initialize(nil, AGTPOPClaims, &rsaList.privKey.PublicKey)
						if err != nil {
							fmt.Printf("Could not generate POP token: %s", err)
							break
						}
						token, err = popToken.GenerateToken(rsaList.privKey)
						if err != nil {
							fmt.Printf("\nCould not generate POP token: %s", err)
							break
						}
						fmt.Printf("\nPOP Token (in header): \n%s\n", token)
						AGTClaims.addClaim("key", popToken.Jwk.Thumb)
						postContent := AGTClaims.generateReq()
						AGTClaims.deleteClaim("key")
						fmt.Printf("\n Sending POST Request to %s: \n%s\n", AGT_URL, postContent)
						response, err = postRequest(AGT_URL, postContent, map[string]string{"PoP": token})
						if err != nil {
							fmt.Printf("\nError during POST Request sending: %s\n", err)
						}
						if response != "" {
							fmt.Printf("\nPOST Response received: \n%s\nSave post response? y/n   ", response)
							if input := getUserInput(); input == "y" || input == "1" {
								fmt.Printf("ID: ")
								id := getUserInput()
								fmt.Printf("%s", rsaList.agTokens.UnmarshalAdd(id, response))
							}
						}
					case "3", "e": // ECDSA long term
						fmt.Println("ECDSA authentication being used. Generating POP Token")
						var popToken utils.PopToken
						var token string
						err = popToken.Initialize(nil, map[string]string{"aud": "vissv2/Agt"}, &ecdsaList.privKey.PublicKey)
						if err != nil {
							fmt.Printf("\nCould not generate POP token: %s", err)
							break
						}
						token, err = popToken.GenerateToken(ecdsaList.privKey)
						if err != nil {
							fmt.Printf("\nCould not generate POP token: %s", err)
							break
						}
						fmt.Printf("\nPOP Token (in header): \n%s\n", token)
						AGTClaims.addClaim("key", popToken.Jwk.Thumb)
						postContent := AGTClaims.generateReq()
						AGTClaims.deleteClaim("key")
						fmt.Printf("\n Sending POST Request to %s: \n%s\n", AGT_URL, postContent)
						response, err = postRequest(AGT_URL, postContent, map[string]string{"PoP": token})
						if err != nil {
							fmt.Printf("\nError during POST Request sending: %s\n", err)
						}
						if response != "" {
							fmt.Printf("\nPOST Response received: \n%s\nSave post response? y/n   ", response)
							if input := getUserInput(); input == "y" || input == "1" {
								fmt.Printf("ID: ")
								id := getUserInput()
								fmt.Printf("%s", ecdsaList.agTokens.UnmarshalAdd(id, response))
							}
						}
					default: // Nothing
						fmt.Println("Nothing done")
					}
				case "2": // Claims management
					fmt.Printf("\t\t Actual claims:\n%s", AGTClaims.getFull())
					fmt.Println("\t\t Want to make any changes? (y/n)")
					var option string
					fmt.Scanln(option)
					if option == "y" {
						fmt.Println("\t\t1 - Default values\n\t\t2 - Add/Change Claim\n\t\t3 - Remove Claim")
						fmt.Scanln(option)
						switch option {
						case "1":
							fmt.Println("\t\t Initialized to default values")
							AGTClaims.initAGTClaim()
						case "2":
							var key, value string
							fmt.Println("\t\t")
							fmt.Println("\t\t\tKey: ")
							fmt.Scanln(key)
							fmt.Println("\t\t\tNew Value: ")
							fmt.Scanf(value)
							AGTClaims.addClaim(key, value)
						case "3":
							var key string
							fmt.Println("\t\t\tKey to delete: ")
							fmt.Scanf(key)
							AGTClaims.deleteClaim(key)
						default:
							fmt.Println("Wrong Option")
						}
					}
				case "3": // Tokens management
					tokenOpt := "1"
					for tokenOpt != "0" {
						fmt.Println("AGTokens\n\t1 - See all tokens\n\t2 - Delete by id\n\t3 - Manual Input\n\t0 - Back to main menu ")
						tokenOpt = getUserInput()
						switch tokenOpt {
						case "1":
							// Shows No pop req tokens
							fmt.Printf("\nNo POP Tokens ---\n")
							fmt.Printf("%s\n", noPopList.agTokens.Show())
							// Shows RSA key tokens
							fmt.Printf("\nRSA Tokens ---\n")
							fmt.Printf("%s\n", rsaList.agTokens.Show())
							// Shows ECDSA key tokens
							fmt.Printf("\nECDSA Tokens ---\n")
							fmt.Printf("%s\n", ecdsaList.agTokens.Show())
						case "2":
							// It is required to tell the token type and its id
							fmt.Printf("Token type? 1: No POP, 2: RSA, 3:ECDSA :")
							tokenTyp := getUserInput()
							fmt.Printf("Token id: ")
							tokenId := getUserInput()
							switch tokenTyp {
							case "1":
								fmt.Printf("%s", noPopList.agTokens.Delete(tokenId))
							case "2":
								fmt.Printf("%s", rsaList.agTokens.Delete(tokenId))
							case "3":
								fmt.Printf("%s", ecdsaList.agTokens.Delete(tokenId))
							default:
								fmt.Printf("Wrong type")
							}
						case "3": // Manual input
							// It is required to tell the token type and its id
							fmt.Printf("Token type? 1: No POP, 2: RSA, 3:ECDSA :")
							tokenTyp := getUserInput()
							fmt.Printf("Token id: ")
							tokenId := getUserInput()
							fmt.Printf("Token: ")
							tokenIn := getUserInput()
							switch tokenTyp {
							case "1":
								fmt.Printf("%s", noPopList.agTokens.Add(tokenId, tokenIn))
							case "2":
								fmt.Printf("%s", rsaList.agTokens.Add(tokenId, tokenIn))
							case "3":
								fmt.Printf("%s", ecdsaList.agTokens.Add(tokenId, tokenIn))
							default:
								fmt.Printf("Wrong type")
							}
						}
					}
				}
			}
		case "3": // AT Communication
			var atOpt string
			for atOpt != "0" {
				fmt.Println("AT Communication\n\t1 - Send AT request\n\t2 - Claims Management\n\t3 - Tokens received\n\t0 - Back to main menu")
				atOpt = "1"
				atOpt = getUserInput()
				switch atOpt {
				case "1": // Send token Request
					// First, It is neccesary to have an AgTokens. Those are obtained by making a request to the AGT server
					fmt.Printf("1 - No pop Request - Avaliable: %v\n", len(noPopList.agTokens) > 0)
					fmt.Printf("2 - RSA pop Request - Avaliable: %v\n", len(rsaList.agTokens) > 0)
					fmt.Printf("3 - ECDSA pop Request - Avaliable: %v\n", len(ecdsaList.agTokens) > 0)
					fmt.Printf("Alg: ")
					reqAlg := getUserInput()
					switch reqAlg {
					case "1", "n":
						if !(len(noPopList.agTokens) > 0) {
							fmt.Println("No tokens avaliable")
							break
						}
						fmt.Printf("POP disabled Tokens avaliable: \n%s", noPopList.agTokens.Show())
						fmt.Printf("\n Id to use: ")
						usedId := getUserInput()
						if _, exists := noPopList.agTokens[usedId]; !exists {
							fmt.Printf("Token with id: %s doesnt exist. Sending nothing", usedId)
							break
						}
						ATClaims.addClaim("purpose", "fuel-status")
						ATClaims.addClaim("token", noPopList.agTokens[usedId].Token.GetFullToken())
						postContent := ATClaims.generateReq()
						fmt.Printf("No authentication being used \nSending POST Request to %s: \n%s\n", AT_URL, postContent)
						response, err := postRequest(AT_URL, postContent, nil)
						if err != nil {
							fmt.Printf("Error during POST Request sending: %s\n", err)
						} else if response != "" {
							fmt.Printf("\nPOST Response received: \n%s\nSave post response? y/n   ", response)
							if input := getUserInput(); input == "y" || input == "1" {
								fmt.Printf("ID: ")
								id := getUserInput()
								fmt.Printf("%s", noPopList.aTokens.UnmarshalAdd(id, response))
							}
						}
					case "2", "r":
						if !(len(rsaList.agTokens) > 0) {
							fmt.Println("No tokens avaliable")
							break
						}
						fmt.Printf("RSA pop Tokens avaliable: \n%s", rsaList.agTokens.Show())
						fmt.Printf("\n Id to use: ")
						usedId := getUserInput()
						if _, exists := rsaList.agTokens[usedId]; !exists {
							fmt.Printf("Token with id: %s does not exist. Sending nothing\n", usedId)
							break
						}
						fmt.Printf("Generating POP\n")
						var popToken utils.PopToken
						err := popToken.Initialize(nil, ATPOPClaims, &rsaList.privKey.PublicKey)
						if err != nil {
							fmt.Printf("Cannot initialize popToken, err=%v\n", err)
							break
						}
						popStr, err := popToken.GenerateToken(rsaList.privKey)
						if err != nil {
							fmt.Printf("Cannot generate POPToken, err = %v", err)
						}
						ATClaims.addClaim("purpose", "fuel-status")
						ATClaims.addClaim("token", rsaList.agTokens[usedId].Token.GetFullToken())
						ATClaims.addClaim("pop", popStr)
						postContent := ATClaims.generateReq()
						fmt.Printf("No authentication being used \nSending POST Request to %s: \n%s\n", AT_URL, postContent)
						response, err := postRequest(AT_URL, postContent, nil)
						if err != nil {
							fmt.Printf("Error during POST Request sending: %s\n", err)
						} else if response != "" {
							fmt.Printf("\nPOST Response received: \n%s\nSave post response? y/n   ", response)
							if input := getUserInput(); input == "y" || input == "1" {
								fmt.Printf("ID: ")
								id := getUserInput()
								fmt.Printf("%s", rsaList.aTokens.UnmarshalAdd(id, response))
							}
						}
					case "3", "e":
						if !(len(ecdsaList.agTokens) > 0) {
							fmt.Println("No tokens avaliable")
							break
						}
						fmt.Printf("ECDSA pop Tokens avaliable: \n%s", ecdsaList.agTokens.Show())
						fmt.Printf("\n Id to use: ")
						usedId := getUserInput()
						if _, exists := ecdsaList.agTokens[usedId]; !exists {
							fmt.Printf("Token with id: %s does not exist. Sending nothing\n", usedId)
							break
						}
						fmt.Printf("Generating POP\n")
						var popToken utils.PopToken
						err := popToken.Initialize(nil, ATPOPClaims, &ecdsaList.privKey.PublicKey)
						if err != nil {
							fmt.Printf("Cannot initialize popToken, err=%v\n", err)
							break
						}
						popStr, err := popToken.GenerateToken(ecdsaList.privKey)
						if err != nil {
							fmt.Printf("Cannot generate POPToken, err = %v", err)
						}
						ATClaims.addClaim("purpose", "fuel-status")
						ATClaims.addClaim("token", ecdsaList.agTokens[usedId].Token.GetFullToken())
						ATClaims.addClaim("pop", popStr)
						postContent := ATClaims.generateReq()
						fmt.Printf("No authentication being used \nSending POST Request to %s: \n%s\n", AT_URL, postContent)
						response, err := postRequest(AT_URL, postContent, nil)
						if err != nil {
							fmt.Printf("Error during POST Request sending: %s\n", err)
						} else if response != "" {
							fmt.Printf("\nPOST Response received: \n%s\nSave post response? y/n   ", response)
							if input := getUserInput(); input == "y" || input == "1" {
								fmt.Printf("ID: ")
								id := getUserInput()
								fmt.Printf("%s", ecdsaList.aTokens.UnmarshalAdd(id, response))
							}
						}
					default:
						fmt.Printf("\nRequest cancelled\n")
					}
				case "2": // Claims management
				case "3": // Tokens management
					tokenOpt := "1"
					for tokenOpt != "0" {
						fmt.Println("ATokens\n\t1 - See all tokens\n\t2 - Delete by id\n\t3 - Manual Input\n\t0 - Back to main menu ")
						tokenOpt = getUserInput()
						switch tokenOpt {
						case "1":
							// Shows No pop req tokens
							fmt.Printf("\nNo POP Tokens ---\n")
							fmt.Printf("%s\n", noPopList.aTokens.Show())
							// Shows RSA key tokens
							fmt.Printf("\nRSA Tokens ---\n")
							fmt.Printf("%s\n", rsaList.aTokens.Show())
							// Shows ECDSA key tokens
							fmt.Printf("\nECDSA Tokens ---\n")
							fmt.Printf("%s\n", ecdsaList.aTokens.Show())
						case "2":
							// It is required to tell the token type and its id
							fmt.Printf("Token type? 1: No POP, 2: RSA, 3:ECDSA :")
							tokenTyp := getUserInput()
							fmt.Printf("Token id: ")
							tokenId := getUserInput()
							switch tokenTyp {
							case "1":
								fmt.Printf("%s", noPopList.aTokens.Delete(tokenId))
							case "2":
								fmt.Printf("%s", rsaList.aTokens.Delete(tokenId))
							case "3":
								fmt.Printf("%s", ecdsaList.aTokens.Delete(tokenId))
							default:
								fmt.Printf("Wrong type")
							}
						case "3": // Manual input
							// It is required to tell the token type and its id
							fmt.Printf("Token type? 1: No POP, 2: RSA, 3:ECDSA :")
							tokenTyp := getUserInput()
							fmt.Printf("Token id: ")
							tokenId := getUserInput()
							fmt.Printf("Token: ")
							tokenIn := getUserInput()
							switch tokenTyp {
							case "1":
								fmt.Printf("%s", noPopList.aTokens.Add(tokenId, tokenIn))
							case "2":
								fmt.Printf("%s", rsaList.aTokens.Add(tokenId, tokenIn))
							case "3":
								fmt.Printf("%s", ecdsaList.aTokens.Add(tokenId, tokenIn))
							default:
								fmt.Printf("Wrong type")
							}
						}
					}

				}
			}
		case "4": // Viss Communication
			var vissOpt string
			for vissOpt != "0" {
				fmt.Println("VISS Communication\n\t1 - HTTP request\n\t0 - Back to main menu")
				vissOpt = "1"
				vissOpt = getUserInput()
				switch vissOpt {
				case "1":
					// There is no need to give pop to viss server. All tokens can be used
					fmt.Printf("\nTokens avaliable for data request:\n")
					if len(noPopList.aTokens) > 0 {
						fmt.Printf("No Key linked:\n%s", noPopList.aTokens.Show())

					}
					if len(rsaList.aTokens) > 0 {
						fmt.Printf("RSA key linked:\n%s", rsaList.aTokens.Show())
					}
					if len(ecdsaList.aTokens) > 0 {
						fmt.Printf("ECDSA key linked: \n%s", ecdsaList.aTokens.Show())
					}
					var token *utils.ExtendedJwt
					fmt.Printf("\nType: (1 - NoKey, 2 - RSA, 3 - ECDSA) : ")
					typ := getUserInput()
					fmt.Printf("\nID: ")
					id := getUserInput()
					switch typ {
					case "1":
						if _, exist := noPopList.aTokens[id]; exist {
							token = noPopList.aTokens[id]
						}
					case "2":
						if _, exist := rsaList.aTokens[id]; exist {
							token = rsaList.aTokens[id]
						}
					case "3":
						if _, exist := ecdsaList.aTokens[id]; exist {
							token = ecdsaList.aTokens[id]
						}
					}
					if token == nil {
						fmt.Println("\nNo token found.")
					} else {
						VissClaims.addClaim("action", "get")
						VissClaims.addClaim("path", "Vehicle.Powertrain.FuelSystem")
						VissClaims.addClaim("filter", `{"type":"paths","value":["Level","Range"]}`)
						VissClaims.addClaim("requestId", "235")
						VissClaims.addClaim("authorization", token.Token.GetFullToken())
						postContent := VissClaims.generateReq()
						fmt.Printf("\nSending POST Request to %s: \n%s\n", VISS_GET_URL, postContent)
						response, err := getRequest(VISS_GET_URL, postContent, nil)
						if err != nil {
							fmt.Printf("Error during POST Request sending: %s\n", err)
						} else if response != "" {
							fmt.Printf("\nPOST Response received: \n%s\n", response)
						}
					}
				default:
					fmt.Printf("\nRequest cancelled\n")
				}
			}

		}
	}
}
