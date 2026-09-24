package main

import "crypto/x509"

func main() {
	certificate := &x509.Certificate{}
	_ = certificate.VerifyHostname("localhost")
}
