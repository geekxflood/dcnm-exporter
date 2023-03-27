package main

import (
	"sync"
	"time"
)

type LoginResponse struct {
	Token string `json:"Dcnm-Token"`
	TTL   int    `json:"expirationTime"`
}

type TokenRefresher struct {
	mu          sync.Mutex
	dcnmURL     string
	username    string
	password    string
	token       string
	ttl         time.Duration
	refreshTime time.Duration
}
