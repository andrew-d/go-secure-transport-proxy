package main

import (
	"log"
)

func main() {
	log.Println("Started")

	password := randomHex(32)

	enc, err := GetIdentityEncryptedPrivateKey("adunham", password)
	if err != nil {
		log.Fatal(err)
	}

	dec, err := DecryptEncryptedPEM(enc, password)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%+v", dec)

	log.Println("Finished")
}
