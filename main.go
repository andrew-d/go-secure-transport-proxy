package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
)

var (
	// Arguments
	argListenAddr   string
	argListenCert   string
	argListenKey    string
	argUpstreamAddr string
	argIdentity     string
)

func parseArgs() error {
	argListenAddr = os.Args[1]
	argListenCert = os.Args[2]
	argListenKey = os.Args[3]
	argUpstreamAddr = os.Args[4]

	if len(os.Args) >= 6 {
		argIdentity = os.Args[5]
	} else {
		u, err := user.Current()
		if err != nil {
			return err
		}

		log.Printf("defaulting to username (%q) as identity name", u.Username)
		argIdentity = u.Username
	}

	return nil
}

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "Usage: %s <listen> <listen-cert> <listen-key> <upstream> [<identity>]\n", os.Args[0])
		os.Exit(1)
	}

	log.Println("started")

	if err := parseArgs(); err != nil {
		log.Fatal(err)
	}

	tlsListenCert, err := tls.LoadX509KeyPair(argListenCert, argListenKey)
	if err != nil {
		log.Fatal(err)
	}

	clientCert, err := getTLSClientCert(argIdentity)
	if err != nil {
		log.Fatal(err)
	}

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsListenCert},
		MinVersion:   tls.VersionTLS12,
	}

	l, err := tls.Listen("tcp", argListenAddr, serverConfig)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("accepting connections on: %s", l.Addr())

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("error accepting connection: %s", err)
			continue
		}

		log.Printf("accepted connection from: %s", conn.RemoteAddr())

		go func() {
			if err := handleConnection(conn, argUpstreamAddr, *clientCert); err != nil {
				log.Printf("error proxying to %q: %s", conn.RemoteAddr(), err)
			}

			log.Printf("finished proxying to %q", conn.RemoteAddr())
		}()
	}

	log.Println("finished")
}

func getTLSClientCert(identity string) (*tls.Certificate, error) {
	password := randomHex(32)
	cert, encPkey, err := GetIdentity(identity, password)
	if err != nil {
		return nil, err
	}
	decPkey, err := DecryptEncryptedPEM(encPkey, password)
	if err != nil {
		return nil, err
	}

	// log.Print(PEMToString(cert))
	// log.Print(PEMToString(decPkey))

	clientCert, err := CertificateFromPEM(cert, decPkey)
	if err != nil {
		return nil, err
	}

	return &clientCert, nil

}

func handleConnection(conn net.Conn, addr string, clientCert tls.Certificate) error {
	upstream, err := dialWithClientCert(addr, clientCert)
	if err != nil {
		return err
	}

	// Copy everything
	go io.Copy(conn, upstream)
	io.Copy(upstream, conn)

	return nil
}

func dialWithClientCert(addr string, cert tls.Certificate) (*tls.Conn, error) {
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return tls.Dial("tcp", addr, config)
}
