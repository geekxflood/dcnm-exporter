package main

// Library of all the generic functions

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func SetInsecureSSL() {
	// Create a new transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Create a new client
	http.DefaultClient = &http.Client{Transport: tr}
}

// function apiCaller will do a REST API Call
// The function takes as argument the URL of the API, the method (GET, POST, PUT, DELETE),
// the body of the request (if any) and the headers (if any)
// The function return the response body, the status code and an error
func ApiCaller(url string, method string, body io.Reader, headers map[string]string) ([]byte, int, error) {

	// Create a new request
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, 0, err
	}

	// Add the headers to the request
	for key, value := range headers {
		req.Header.Add(key, value)
	}

	// Do the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return respBody, resp.StatusCode, nil
}

// loginDCNM logs into the DCNM server and returns an authentication token and the token's TTL.
func loginDCNM(url, username, password string) (string, time.Duration, error) {
	method := "POST"
	payload := strings.NewReader(fmt.Sprintf(`{"expirationTime": %d}`, expirationTime))
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))

	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Basic %s", auth),
	}

	respBody, statusCode, err := ApiCaller(url, method, payload, headers)
	if err != nil {
		return "", 0, err
	}

	if statusCode != http.StatusOK {
		return "", 0, fmt.Errorf("failed to log in, status code: %d", statusCode)
	}

	var loginResp LoginResponse
	err = json.Unmarshal(respBody, &loginResp)
	if err != nil {
		return "", 0, err
	}

	return loginResp.Token, time.Duration(loginResp.TTL) * time.Millisecond, nil
}

// refreshToken refreshes the authentication token.
func (tr *TokenRefresher) refreshToken() error {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	token, ttl, err := loginDCNM(tr.dcnmURL, tr.username, tr.password)
	if err != nil {
		return err
	}

	tr.token = token
	tr.ttl = ttl

	return nil
}

// autoRefresh refreshes the authentication token periodically.
func (tr *TokenRefresher) autoRefresh() {
	for {
		time.Sleep(tr.refreshTime)

		err := tr.refreshToken()
		if err != nil {
			fmt.Printf("Error refreshing token: %v\n", err)
		} else {
			fmt.Println("Token refreshed successfully")
		}
	}
}
