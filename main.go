package main

import (
	"log"
)

func main() {
	log.Println("Started")

	password := randomHex(32)

	cert, encPkey, err := GetIdentity("adunham", password)
	if err != nil {
		log.Fatal(err)
	}

	decPkey, err := DecryptEncryptedPEM(encPkey, password)
	if err != nil {
		log.Fatal(err)
	}

	log.Print(PEMToString(cert))
	log.Print(PEMToString(decPkey))

	log.Println("Finished")
}
