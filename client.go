package main

import (
	"crypto/tls"
	//"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	// Read the key pair to create certificate
	cert, err := LoadX509KeyPairDER("tls/tlscert.der", "tls/tlskey.der")
	if err != nil {
		log.Fatal(err)
	}

	/*
	// Create a CA certificate pool and add cert.pem to it
	caCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)
	*/

	// Create a HTTPS client and supply the created CA pool and certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					/*
					opts := x509.VerifyOptions{
						//DNSName:       cs.ServerName,
						Intermediates: x509.NewCertPool(),
						Roots: caCertPool,
					}
					for _, cert := range cs.PeerCertificates[1:] {
						opts.Intermediates.AddCert(cert)
					}
					_, err := cs.PeerCertificates[0].Verify(opts)
					*/
					err = ra_tls_verify(cs.PeerCertificates[0].Raw)
					return err
				},
			},
		},
	}

	// Request /hello via the created HTTPS client over port 8443 via GET
	r, err := client.Get("https://localhost:8443/hello")
	if err != nil {
		log.Fatal(err)
	}

	// Read the response body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Print the response body to stdout
	fmt.Printf("%s\n", body)
}

