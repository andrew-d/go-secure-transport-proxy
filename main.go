package main

import (
	"log"
)

func main() {
	log.Println("Started")

	enc, err := GetIdentityEncryptedPrivateKey("adunham")
	if err != nil {
		log.Fatal(err)
	}

	dec, err := DecryptEncryptedPEM(enc, "dummy")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Finished")
}
