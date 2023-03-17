package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"os"
	"path"

	ratls_wrapper "github.com/konvera/gramine-ratls-golang"
	mutual_ratls "github.com/konvera/mutual-ratls-example"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	// Write "Hello, world!" to the response body
	io.WriteString(w, "Hello, world!\n")
}

func main() {
	// Set up a /hello resource handler
	http.HandleFunc("/hello", helloHandler)

	tlsFilePath := os.Getenv("RATLS_FILE_PATH")
	tlsCertPath := "tls/tlscert.der"
	tlsKeyPath := "tls/tlskey.der"

	if tlsFilePath != "" {
		tlsCertPath = path.Join(tlsFilePath, "tlscert.der")
		tlsKeyPath = path.Join(tlsFilePath, "tlskey.der")
	}

	// create TLS certificate and key
	err := ratls_wrapper.LoadRATLSLibs()
	if err != nil {
		log.Fatal(err.Error())
	}

	err = ratls_wrapper.RATLSCreateKeyAndCrtDer(tlsCertPath, tlsKeyPath)
	if err != nil {
		log.Fatal(err.Error())
	}

	// Read the key pair to create certificate
	derCrt, err := mutual_ratls.LoadX509KeyPairDER(tlsCertPath, tlsKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			err = ratls_wrapper.RATLSVerifyDer(cs.PeerCertificates[0].Raw, nil, nil, nil, nil)
			return err
		},
	}

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(mutual_ratls.ListenAndServeTLS(server, derCrt))
}
