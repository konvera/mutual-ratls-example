package main

import (
	"crypto/tls"
	"os"
	"path"

	//"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	ratls_wrapper "github.com/konvera/gramine-ratls-golang"

	mutual_ratls "github.com/konvera/mutual-ratls-example"
)

func main() {
	log.Println("Client started...")

	// Read the key pair to create certificate
	tlsFilePath := os.Getenv("RATLS_ENCLAVE_PATH")

	if tlsFilePath == "" {
		panic("invalid TLS certificate or key")
	}

	// Read the key pair to create certificate
	cert, err := mutual_ratls.LoadX509KeyPairDER(path.Join(tlsFilePath, "tlscert.der"), path.Join(tlsFilePath, "tlskey.der"))
	if err != nil {
		log.Fatal(err)
	}

	// Create a HTTPS client and supply the created CA pool and certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					err = ratls_wrapper.RATLSVerifyDer(cs.PeerCertificates[0].Raw, nil, nil, nil, nil)
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
	fmt.Printf("Response: %s\n", body)
}
