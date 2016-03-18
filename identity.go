package main

/*
#cgo CFLAGS: -x objective-c -Wall -Wextra
#cgo LDFLAGS: -framework Security -framework Foundation

#include <stdint.h>
#include <stdlib.h>
int ExportIdentity(
    const char *identityName, const char* password,
    uint8_t **certificateOut, int *certificateLen,
    uint8_t **privateKeyOut, int *privateKeyLen
);
*/
import "C"

import (
	"encoding/pem"
	"errors"
	"unsafe"
)

func GetIdentity(name, password string) (*pem.Block, *pem.Block, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	var (
		certData, privateKeyData *C.uint8_t
		certSize, privateKeySize C.int
	)
	ret := C.ExportIdentity(cName, cPassword, &certData, &certSize, &privateKeyData, &privateKeySize)
	if ret != 0 {
		return nil, nil, errors.New("could not get private key")
	}
	defer C.free(unsafe.Pointer(certData))
	defer C.free(unsafe.Pointer(privateKeyData))

	cert := C.GoBytes(unsafe.Pointer(certData), certSize)
	pkey := C.GoBytes(unsafe.Pointer(privateKeyData), privateKeySize)

	certBlock, _ := pem.Decode(cert)
	if certBlock == nil {
		return nil, nil, errors.New("could not load PEM cert block")
	}

	privateKeyBlock, _ := pem.Decode(pkey)
	if privateKeyBlock == nil {
		return nil, nil, errors.New("could not load PEM private key block")
	}

	return certBlock, privateKeyBlock, nil
}
