package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

func init() {
	dcnmURL = os.Getenv("DCNM_URL")
	username = os.Getenv("DCNM_USERNAME")
	password = os.Getenv("DCNM_PASSWORD")

	expirationTimeString := os.Getenv("DCNM_EXPIRATION_TIME")
	if expirationTimeString != "" {
		var err error
		expirationTime, err = strconv.ParseInt(expirationTimeString, 10, 64)
		if err != nil {
			fmt.Printf("Error parsing DCNM_EXPIRATION_TIME: %v\n", err)
			expirationTime = 90000000
		}
	} else {
		expirationTime = 90000000
	}

	// Check if expiration time is less than 5 minutes
	if expirationTime < 300000 {
		log.Fatal("Expiration time should be greater than or equal to 5 minutes (300000 milliseconds)")
	}

	tokenRefresher = &TokenRefresher{
		dcnmURL:     dcnmURL,
		username:    username,
		password:    password,
		refreshTime: 5 * time.Minute, // Set a custom time duration before the token expires
	}
}

func main() {
	if err := tokenRefresher.refreshToken(); err != nil {
		log.Printf("Error logging in: %v\n", err)
		return
	}

	go tokenRefresher.autoRefresh()
}
