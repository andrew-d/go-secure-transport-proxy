package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Security -framework Foundation

#include <stdint.h>
#include <stdlib.h>
int GetIdentityPrivateKey(const char *identityName, const char* password, uint8_t **out, int *len);
*/
import "C"

import (
	"encoding/pem"
	"errors"
	"unsafe"
)

func GetIdentityEncryptedPrivateKey(name, password string) (*pem.Block, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	var (
		data *C.uint8_t
		size C.int
	)
	ret := C.GetIdentityPrivateKey(cName, cPassword, &data, &size)
	if ret != 0 {
		return nil, errors.New("could not get private key")
	}
	defer C.free(unsafe.Pointer(data))

	d := C.GoBytes(unsafe.Pointer(data), size)

	block, _ := pem.Decode(d)
	if block == nil {
		return nil, errors.New("could not load PEM block")
	}

	return block, nil
}
