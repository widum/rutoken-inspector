package main

import "encoding/pem"

func pemDecodeCert(b []byte) ([]byte, bool) {
	p, _ := pem.Decode(b)
	if p != nil && p.Type == "CERTIFICATE" {
		return p.Bytes, true
	}
	return nil, false
}