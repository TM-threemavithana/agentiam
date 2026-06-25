package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// ParseSCRAMSecret parses a PostgreSQL SCRAM secret string:
// SCRAM-SHA-256$<iterations>:<salt>$<storedkey>:<serverkey>
func ParseSCRAMSecret(secret string) (iterations int, salt []byte, storedKey []byte, serverKey []byte, err error) {
	if !strings.HasPrefix(secret, "SCRAM-SHA-256$") {
		return 0, nil, nil, nil, fmt.Errorf("invalid prefix")
	}
	parts := strings.SplitN(secret[14:], "$", 2)
	if len(parts) != 2 {
		return 0, nil, nil, nil, fmt.Errorf("invalid format")
	}

	part1 := strings.SplitN(parts[0], ":", 2)
	if len(part1) != 2 {
		return 0, nil, nil, nil, fmt.Errorf("invalid format")
	}
	iterations, err = strconv.Atoi(part1[0])
	if err != nil {
		return 0, nil, nil, nil, err
	}
	salt, err = base64.StdEncoding.DecodeString(part1[1])
	if err != nil {
		return 0, nil, nil, nil, err
	}

	part2 := strings.SplitN(parts[1], ":", 2)
	if len(part2) != 2 {
		return 0, nil, nil, nil, fmt.Errorf("invalid format")
	}
	storedKey, err = base64.StdEncoding.DecodeString(part2[0])
	if err != nil {
		return 0, nil, nil, nil, err
	}
	serverKey, err = base64.StdEncoding.DecodeString(part2[1])
	if err != nil {
		return 0, nil, nil, nil, err
	}

	return iterations, salt, storedKey, serverKey, nil
}

func VerifySCRAM(clientFirstBare string, serverFirst string, clientFinalWithoutProof string, clientProofStr string, storedKey []byte, serverKey []byte) (serverSignature string, err error) {
	clientProof, err := base64.StdEncoding.DecodeString(clientProofStr)
	if err != nil {
		return "", err
	}

	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
	
	mac := hmac.New(sha256.New, storedKey)
	mac.Write([]byte(authMessage))
	clientSignature := mac.Sum(nil)

	if len(clientProof) != len(clientSignature) {
		return "", fmt.Errorf("client proof length mismatch")
	}

	clientKey := make([]byte, len(clientProof))
	for i := 0; i < len(clientProof); i++ {
		clientKey[i] = clientProof[i] ^ clientSignature[i]
	}

	hash := sha256.New()
	hash.Write(clientKey)
	hashedClientKey := hash.Sum(nil)

	if !bytes.Equal(hashedClientKey, storedKey) {
		return "", fmt.Errorf("SCRAM authentication failed")
	}

	macServer := hmac.New(sha256.New, serverKey)
	macServer.Write([]byte(authMessage))
	serverSigBytes := macServer.Sum(nil)
	serverSignature = base64.StdEncoding.EncodeToString(serverSigBytes)

	return serverSignature, nil
}
