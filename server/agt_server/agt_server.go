/**
* (C) 2020 Geotab Inc
*
* All files and artifacts in the repository at https://github.com/MEAE-GOT/WAII
* are licensed under the provisions of the license provided by the LICENSE file in this repository.
*
**/

package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/MEAE-GOT/WAII/utils"
	"github.com/akamensky/argparse"
	"github.com/google/uuid"
)

const LT_DURATION = 4 * 60 * 60 // 4 hours
var privKey *rsa.PrivateKey

// Used for clock unsync tolerance
const GAP = 3
const LIFETIME = 5

// Stores a cache of the jwt ids received to not be reused
var jtiCache map[string]struct{}

type Payload struct {
	Vin     string `json:"vin"`
	Context string `json:"context"`
	Proof   string `json:"proof"`
	//Key     utils.JsonWebKey `json:"key"`
	Key string `json:"key"`
}

func makeAgtServerHandler(serverChannel chan string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		utils.Info.Printf("agtServer:url=%s", req.URL.Path)
		if req.URL.Path != "/agts" {
			http.Error(w, "404 url path not found.", 404)
		} else if req.Method != "POST" {
			http.Error(w, "400 bad request method.", 400)
		} else {
			bodyBytes, err := ioutil.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "400 request unreadable.", 400)
			} else {
				utils.Info.Printf("agtServer:received POST request=%s\n", string(bodyBytes))
				serverChannel <- string(bodyBytes) // If everything works fine, sends to serverChannel the body
				// It is also necessary to send to serverChannel the POP (if it exists)
				pop := string(req.Header.Get("PoP"))
				if pop != "" {
					utils.Info.Printf("agtServer: received POP = %s", pop)
				}
				serverChannel <- pop
				response := <-serverChannel // Receives the response and sends it
				utils.Info.Printf("agtServer:POST response=%s", response)
				if len(response) == 0 {
					http.Error(w, "400 bad input.", 400)
				} else {
					w.Header().Set("Access-Control-Allow-Origin", "*")
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(response))
				}
			}
		}
	}
}

func initAgtServer(serverChannel chan string, muxServer *http.ServeMux) {
	utils.Info.Printf("initAtServer(): :7500/agts")
	agtServerHandler := makeAgtServerHandler(serverChannel)
	muxServer.HandleFunc("/agts", agtServerHandler)
	utils.Error.Fatal(http.ListenAndServe(":7500", muxServer))
}

// Load key from file, if not, creates new key file
func initKey(prvDirectory string) {
	if err := utils.ImportRsaKey(prvDirectory, &privKey); err != nil {
		utils.Error.Printf("Error importing private key: %s, generating one.", err)
		if err := utils.GenRsaKey(256, &privKey); err != nil {
			utils.Error.Printf("Error generating private key: %s. Signature not avaliable", err)
			return
		}
		// Key generated, must export it
		utils.Info.Printf("RSA key generated correctly")
		if err := os.Remove(prvDirectory); err != nil && !errors.Is(err, fs.ErrNotExist) {
			utils.Error.Printf("Error exporting private key, cannot remove previous file: %s", err)
		} else if err := utils.ExportKeyPair(privKey, prvDirectory, ""); err != nil {
			utils.Error.Printf("Error exporting private key: %s", err)
		}
		utils.Info.Printf("RSA key exported")
		return
	}
	utils.Info.Printf("RSA key imported correctly")
}

// GenerateResponse must unmarshall the payload, then ask for AGT Generation
func generateResponse(input string, pop string) string {
	var payload Payload
	err := json.Unmarshal([]byte(input), &payload)
	if err != nil {
		utils.Error.Printf("generateResponse:error input=%s", input)
		return `{"error": "Client request malformed"}`
	}
	if authenticateClient(payload) {
		if pop != "" {
			return generateLTAgt(payload, pop)
		}
		return generateAgt(payload)
	}
	return `{"error": "Client authentication failed"}`
}

// Part of roles
func checkUserRole(userRole string) bool {
	if userRole != "OEM" && userRole != "Dealer" && userRole != "Independent" && userRole != "Owner" && userRole != "Driver" && userRole != "Passenger" {
		return false
	}
	return true
}

// Part of user role
func checkAppRole(appRole string) bool {
	if appRole != "OEM" && appRole != "Third party" {
		return false
	}
	return true
}

// Part of user role
func checkDeviceRole(deviceRole string) bool {
	if deviceRole != "Vehicle" && deviceRole != "Nomadic" && deviceRole != "Cloud" {
		return false
	}
	return true
}

// Part of user role
func checkRoles(context string) bool {
	if strings.Count(context, "+") != 2 {
		return false
	}
	delimiter1 := strings.Index(context, "+")
	delimiter2 := strings.Index(context[delimiter1+1:], "+")
	if !checkUserRole(context[:delimiter1]) || !checkAppRole(context[delimiter1+1:delimiter1+1+delimiter2]) || !checkDeviceRole(context[delimiter1+1+delimiter2+1:]) {
		return false
	}
	return true
}

// Client should prove he is who he says he is. Proof of possesion now exist, authentication not.
func authenticateClient(payload Payload) bool {
	if checkRoles(payload.Context) && payload.Proof == "ABC" { // a bit too simple validation...
		return true
	}
	return false
}

func deleteJti(jti string) {
	time.Sleep((GAP + LIFETIME + 5) * time.Second)
	delete(jtiCache, jti)
}

// Checks if jwt id exist in cache, if it does, return false. If not, it adds it and automatically clear it from cache when it expires
func addCheckJti(jti string) bool {
	if jtiCache == nil { // If map is empty (first time), it doesnt even check, initializes and add
		jtiCache = make(map[string]struct{})
		jtiCache[jti] = struct{}{}
		go deleteJti(jti)
		return true
	}
	if _, ok := jtiCache[jti]; ok { // Check if jti exist in cache
		return false
	}
	// If we get here, it does not exist in cache
	jtiCache[jti] = struct{}{}
	go deleteJti(jti)
	return true
}

// Checks pop before doing anything
func generateLTAgt(payload Payload, pop string) string {
	var popToken utils.PopToken
	err := popToken.Unmarshal(pop)
	if err != nil {
		utils.Error.Printf("generateLTAgt: Error unmarshalling pop, err = %s", err)
		return `{"error": "Client request malformed"}`
	}
	if !addCheckJti(popToken.PayloadClaims["jti"]) {
		utils.Error.Printf("generateLTAgt: JTI used")
		return `{"error": "Repeated JTI"}`
	}
	err = popToken.CheckSignature()
	if err != nil {
		utils.Info.Printf("generateLTAgt: Invalid POP signature")
		return `{"error": "Invalid POP signature"}`
	}
	if ok, info := popToken.Validate(payload.Key, "vissv2/agts", GAP, LIFETIME); !ok {
		utils.Info.Printf("generateLTAgt: Not valid POP Token: %s", info)
		return `{"error": "Invalid POP Token"}`
	}
	// Generates the response token
	var jwtoken utils.JsonWebToken
	var unparsedId uuid.UUID
	if unparsedId, err = uuid.NewRandom(); err != nil { // Better way to generate uuid than calling an ext program
		utils.Error.Printf("generateAgt:Error generating uuid, err=%s", err)
		return `{"error": "Internal error"}`
	}
	iat := int(time.Now().Unix())
	exp := iat + LT_DURATION // defined by const
	jwtoken.SetHeader("RS256")
	jwtoken.AddClaim("vin", payload.Vin) // No need to check if it is filled, if not, it does nothing (new imp makes this claim not mandatory)
	jwtoken.AddClaim("iat", strconv.Itoa(iat))
	jwtoken.AddClaim("exp", strconv.Itoa(exp))
	jwtoken.AddClaim("clx", payload.Context)
	jwtoken.AddClaim("aud", "w3org/gen2")
	jwtoken.AddClaim("jti", unparsedId.String())
	jwtoken.AddClaim("pub", payload.Key)
	//utils.Info.Printf("generateAgt:jwtHeader=%s", jwtoken.GetHeader())
	//utils.Info.Printf("generateAgt:jwtPayload=%s", jwtoken.GetPayload())
	jwtoken.Encode()
	jwtoken.AssymSign(privKey)
	return `{"token":"` + jwtoken.GetFullToken() + `"}`
}

func generateAgt(payload Payload) string {
	var jwtoken utils.JsonWebToken
	uuid, err := exec.Command("uuidgen").Output()
	if err != nil {
		utils.Error.Printf("generateAgt:Error generating uuid, err=%s", err)
		return `{"error": "Internal error"}`
	}
	uuid = uuid[:len(uuid)-1] // remove '\n' char
	iat := int(time.Now().Unix())
	exp := iat + 4*60*60 // 4 hours
	jwtoken.SetHeader("RS256")
	jwtoken.AddClaim("vin", payload.Vin)
	jwtoken.AddClaim("iat", strconv.Itoa(iat))
	jwtoken.AddClaim("exp", strconv.Itoa(exp))
	jwtoken.AddClaim("clx", payload.Context)
	jwtoken.AddClaim("aud", "w3org/gen2")
	jwtoken.AddClaim("jti", string(uuid))
	utils.Info.Printf("generateAgt:jwtHeader=%s", jwtoken.GetHeader())
	utils.Info.Printf("generateAgt:jwtPayload=%s", jwtoken.GetPayload())
	jwtoken.Encode()
	jwtoken.AssymSign(privKey)
	return `{"token":"` + jwtoken.GetFullToken() + `"}`
}

func main() {
	// Create new parser object
	parser := argparse.NewParser("agt_server", "Process that simulates the behaviour of the Access Grant Server")
	// Create string flag
	logFile := parser.Flag("", "logfile", &argparse.Options{Required: false, Help: "outputs to logfile in ./logs folder"})
	logLevel := parser.Selector("", "loglevel", []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"}, &argparse.Options{
		Required: false,
		Help:     "changes log output level",
		Default:  "info"})

	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	utils.InitLog("agtserver-log.txt", "./logs", *logFile, *logLevel)
	serverChan := make(chan string) // Communication between methods and dif process
	muxServer := http.NewServeMux() // ServeMux for routing
	initKey("agt_private_key.rsa")

	go initAgtServer(serverChan, muxServer)

	for {
		//select {
		//case request := <-serverChan:
		request := <-serverChan
		pop := <-serverChan
		// Server is running concurrently, generateResponse is called when anything is received from it
		response := generateResponse(request, pop)
		serverChan <- response
		//}
	}
}
