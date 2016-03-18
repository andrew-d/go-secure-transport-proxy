package main

import (
	"crypto/rand"
	"encoding/hex"
)

func randomHex(byteLen int) string {
	b := make([]byte, byteLen)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)
}
