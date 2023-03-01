package main

import (
	"crypto/tls"
	//"crypto/x509"
	"io"
	"log"
	"net/http"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	// Write "Hello, world!" to the response body
	io.WriteString(w, "Hello, world!\n")
}

func main() {
	// Set up a /hello resource handler
	http.HandleFunc("/hello", helloHandler)

	// Read the key pair to create certificate
	der_cert, err := LoadX509KeyPairDER("tls/tlscert.der", "tls/tlskey.der")
	if err != nil {
		log.Fatal(err)
	}

	/*
	// Create a CA certificate pool and add cert.pem to it
	caCert, err := x509.ParseCertificate(der_cert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)
	*/

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			/*
			opts := x509.VerifyOptions{
				//DNSName:       cs.ServerName,
				Intermediates: x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(ListenAndServeTLS(server, der_cert))
}

