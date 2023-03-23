package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"

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

	// create TLS certificate and key
	err := ratls_wrapper.LoadRATLSLibs()
	if err != nil {
		log.Fatal(err.Error())
	}

	derKey, derCrt, err := ratls_wrapper.RATLSCreateKeyAndCrtDer()
	if err != nil {
		log.Fatal(err.Error())
	}

	cert, err := mutual_ratls.X509KeyPairDER(derKey, derCrt)
	if err != nil {
		log.Fatal(err.Error())
	}

	mrenclave := mutual_ratls.GetSGXEnvVar("MRENCLAVE")
	if mrenclave == nil {
		log.Fatal("required mrenclave for enclave measurement")
	}

	mrsigner := mutual_ratls.GetSGXEnvVar("MRSIGNER")
	isvProdID := mutual_ratls.GetSGXEnvVar("ISV_PROD_ID")
	isvSVN := mutual_ratls.GetSGXEnvVar("ISV_SVN")

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			err = ratls_wrapper.RATLSVerifyDer(cs.PeerCertificates[0].Raw, mrenclave, mrsigner, isvProdID, isvSVN)
			return err
		},
	}

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(mutual_ratls.ListenAndServeTLS(server, cert))
}
