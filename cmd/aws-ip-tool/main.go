package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	// URL of the JSON file to download
	fileURL := "https://ip-ranges.amazonaws.com/ip-ranges.json"

	// Name to give the file when saving it locally
	fileName := "ip-tanges.json"

	// Download and parse the JSON file
	data, err := downloadAndParseJSON(fileURL, fileName)
	if err != nil {
		fmt.Println("Error downloading and parsing JSON:", err)
		return
	}

	fmt.Println("JSON file downloaded and parsed successfully")
	fmt.Printf("Parsed data: %+v\n", data)
}

func downloadAndParseJSON(url string, fileName string) (map[string]interface{}, error) {
	// Create a custom transport with TLS configuration
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	tlsConfig := &tls.Config{
		RootCAs:            rootCAs,
		InsecureSkipVerify: false,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Create a client with the custom transport
	client := &http.Client{Transport: transport}

	// Get the data
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %v", err)
	}
	defer resp.Body.Close()

	// Check server certificate
	if err := verifyServerCert(resp.TLS); err != nil {
		return nil, fmt.Errorf("TLS certificate verification failed: %v", err)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse JSON
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	// Save the raw JSON to a file
	err = os.WriteFile(fileName, body, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to save JSON file: %v", err)
	}

	return data, nil
}

func verifyServerCert(connState *tls.ConnectionState) error {
	if connState == nil {
		return fmt.Errorf("TLS connection state is nil")
	}

	opts := x509.VerifyOptions{
		DNSName:       connState.ServerName,
		Intermediates: x509.NewCertPool(),
	}

	for _, cert := range connState.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	_, err := connState.PeerCertificates[0].Verify(opts)
	return err
}
