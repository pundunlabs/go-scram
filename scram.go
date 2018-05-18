///===================================================================
// author Erdem Aksu
// copyright 2016 Pundun Labs AB
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// -------------------------------------------------------------------
// Taken from http://tools.ietf.org/html/rfc5802
// SaltedPassword  := Hi(Normalize(password), salt, i)
// ClientKey       := HMAC(SaltedPassword, "Client Key")
// StoredKey       := H(ClientKey)
// AuthMessage     := client-first-message-bare + "," +
//                    server-first-message + "," +
//                    client-final-message-without-proof
// ClientSignature := HMAC(StoredKey, AuthMessage)
// ClientProof     := ClientKey XOR ClientSignature
// ServerKey       := HMAC(SaltedPassword, "Server Key")
// ServerSignature := HMAC(ServerKey, AuthMessage)
///===================================================================

package scram

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"
	"github.com/xdg/stringprep"
)

func Authenticate(conn net.Conn, user, pass string) error {
	log.Println("Scram Authenticate called..")

	prepUser, err := stringprep.SASLprep.Prepare(user)
	if err != nil {
		return err
	}

	prepPass, err := stringprep.SASLprep.Prepare(pass)
	if err != nil {
		return err
	}

	state := map[string]string{
		"user": prepUser,
		"pass": prepPass,
	}

	state, err = clientFirstMessage(conn, state)
	if err != nil {
		return err
	}

	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)

	if err != nil {
		return err
	}

	serverFirstMsg := string(bytes.Trim(buffer, "\x00"))
	state["server_first_msg"] = serverFirstMsg

	state = parse(buffer, state)

	state, err = clientFinalMessage(conn, state)
	if err != nil {
		return err
	}

	buffer = make([]byte, 1024)
	_, err = conn.Read(buffer)
	state = parse(buffer, state)

	err = verifyServerSignature(state)

	if err == nil {
		log.Println("Authentication succeeded")
	}
	return err
}

func clientFirstMessage(conn net.Conn, state map[string]string) (map[string]string, error) {
	h := gs2Header()
	state, err := clientFirstMessageBare(state)

	if err != nil {
		return state, err
	}

	buffer := bytes.NewBufferString(h)
	buffer.WriteString(state["client_first_msg_bare"])

	_, err = conn.Write(buffer.Bytes())

	return state, err
}

func gs2Header() string {
	return "n,,"
}

func clientFirstMessageBare(state map[string]string) (map[string]string, error) {
	var buffer = bytes.NewBufferString("n=")

	buffer.WriteString(state["user"])
	buffer.WriteString(",r=")
	nonce, err := nonce()

	if err != nil {
		return state, err
	}
	state["nonce"] = nonce

	buffer.WriteString(nonce)
	str := buffer.String()
	state["client_first_msg_bare"] = str

	return state, err
}

func clientFinalMessage(conn net.Conn, state map[string]string) (map[string]string, error) {
	iterationCount, err := strconv.ParseInt(state["i"], 10, 64)
	if err != nil {
		log.Printf("error at parsing iteration count: %v", err)
		return state, err
	}

	salt, err := base64.StdEncoding.DecodeString(state["s"])
	if err != nil {
		log.Printf("error at decoding salt: %v", err)
		return state, err
	}

	saltedPassword := hi([]byte(state["pass"]), salt, iterationCount)

	clientFinalMessageWoProof := clientFinalMessageWoProof(state["r"])

	var authMsg = bytes.NewBufferString(state["client_first_msg_bare"])
	authMsg.WriteString(",")
	authMsg.WriteString(state["server_first_msg"])
	authMsg.WriteString(",")
	authMsg.WriteString(clientFinalMessageWoProof)

	clientProof := clientProof(saltedPassword, authMsg.Bytes())

	state["salted_password"] = string(saltedPassword)
	state["auth_msg"] = authMsg.String()

	var clientFinalMsg = bytes.NewBufferString(clientFinalMessageWoProof)
	clientFinalMsg.WriteString(",p=")
	clientFinalMsg.WriteString(clientProof)

	_, err = conn.Write(clientFinalMsg.Bytes())
	state["client_final_msg"] = clientFinalMsg.String()

	return state, err
}

func clientFinalMessageWoProof(nonce string) string {
	h := gs2Header()
	encoded := base64.StdEncoding.EncodeToString([]byte(h))
	var buffer = bytes.NewBufferString("c=")
	buffer.WriteString(encoded)
	buffer.WriteString(",r=")
	buffer.WriteString(nonce)
	return buffer.String()
}

func clientProof(saltedPassword, authMsg []byte) string {
	mac := hmac.New(sha1.New, saltedPassword)
	mac.Write([]byte("Client Key"))
	clientKey := mac.Sum(nil)

	storedKey := sha1.Sum(clientKey)

	mac2 := hmac.New(sha1.New, storedKey[:])
	mac2.Write(bytes.Trim(authMsg, "\x00"))
	clientSignature := mac2.Sum(nil)

	clientProof := exor(clientKey, clientSignature)
	return base64.StdEncoding.EncodeToString(clientProof)

}

func verifyServerSignature(state map[string]string) error {
	verifier := state["v"]
	saltedPassword := []byte(state["salted_password"])
	authMsg := []byte(state["auth_msg"])

	mac := hmac.New(sha1.New, saltedPassword)
	mac.Write([]byte("Server Key"))
	serverKey := mac.Sum(nil)

	mac2 := hmac.New(sha1.New, serverKey)
	mac2.Write(authMsg)
	serverSignature := mac2.Sum(nil)
	compare := base64.StdEncoding.EncodeToString(serverSignature)
	switch strings.Compare(verifier, compare) {
	case 0:
		return nil
	default:
		log.Println("Server Signature not verified.")
		return errors.New("Server Signature not verified")
	}

}

func nonce() (string, error) {
	buffer := make([]byte, 10)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}

	str := sha1.Sum(buffer)
	return hex.EncodeToString(str[:20]), err
}

func parse(buf []byte, state map[string]string) map[string]string {
	tokens := bytes.Split(buf, []byte(","))
	for i := range tokens {
		state[string(tokens[i][:1])] = string(bytes.Trim(tokens[i][2:], "\x00"))
	}
	return state
}

func hi(str, salt []byte, iterationCount int64) []byte {
	mac := hmac.New(sha1.New, str)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	ui := mac.Sum(nil)
	switch iterationCount {
	case 1:
		return ui
	default:
		return hi_iter(str, ui, iterationCount-1)
	}
}

func hi_iter(str, ui []byte, iterationCount int64) []byte {
	switch iterationCount {
	case 0:
		return ui
	default:
		mac := hmac.New(sha1.New, str)
		mac.Write(ui)
		return exor(hi_iter(str, mac.Sum(nil), iterationCount-1), ui)
	}

}

func exor(a, b []byte) []byte {
	var buffer bytes.Buffer
	lena := len(a)
	lenb := len(b)
	var n int
	if lena < lenb {
		n = lena
	} else {
		n = lenb
	}
	for i := 0; i < n; i++ {
		buffer.WriteByte(a[i] ^ b[i])
	}
	return buffer.Bytes()
}

