package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	ratls_wrapper "github.com/konvera/gramine-ratls-golang"

	mutual_ratls "github.com/konvera/mutual-ratls-example"
)

func main() {
	log.Println("Client started...")

	// create TLS certificate and key
	err := ratls_wrapper.LoadRATLSLibs()
	if err != nil {
		log.Fatal(err.Error())
	}

	derKey, derCert, err := ratls_wrapper.RATLSCreateKeyAndCrtDer()
	if err != nil {
		log.Fatal(err.Error())
	}

	// Read the key pair to create certificate
	cert, err := mutual_ratls.X509KeyPairDER(derKey, derCert)
	if err != nil {
		log.Fatal(err)
	}

	mrenclave := mutual_ratls.GetSGXEnvVar("MRENCLAVE")
	if mrenclave == nil {
		log.Fatal("required mrenclave for enclave measurement.")
	}

	mrsigner := mutual_ratls.GetSGXEnvVar("MRSIGNER")
	isvProdID := mutual_ratls.GetSGXEnvVar("ISV_PROD_ID")
	isvSVN := mutual_ratls.GetSGXEnvVar("ISV_SVN")

	// Create a HTTPS client and supply the created CA pool and certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					err = ratls_wrapper.RATLSVerifyDer(cs.PeerCertificates[0].Raw, mrenclave, mrsigner, isvProdID, isvSVN)
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
