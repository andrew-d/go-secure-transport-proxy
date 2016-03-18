package main

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
)

func DecryptEncryptedPEM(b *pem.Block, password string) (*pem.Block, error) {
	if b.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("input block type is not encrypted: %q", b.Type)
	}

	// Create a pipe that we write our password to
	rd, wr, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("could not create pipe: %s", err)
	}

	// Write the password there.
	wr.WriteString(password)
	wr.Close()

	// Go currently doesn't support this, so we run OpenSSL instead.
	cmd := exec.Command("/usr/bin/openssl",
		"pkcs8",
		"-inform", "PEM",
		"-outform", "PEM",
		"-passin", "fd:3",
	)

	// We pass the encrypted PEM in on stdin
	cmd.Stdin = bytes.NewBuffer(pem.EncodeToMemory(b))

	// Pass the password in as FD 3
	cmd.ExtraFiles = []*os.File{rd}

	// Run the command and get the output, which should be our decrypted PEM file.
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running OpenSSL: %s", err)
	}

	// Create the PEM block
	ret, _ := pem.Decode(out)
	if ret == nil {
		return nil, fmt.Errorf("could not decode decrypted PEM block")
	}

	return ret, nil
}
