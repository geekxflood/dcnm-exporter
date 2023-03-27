package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	dcnmURL        string
	username       string
	password       string
	expirationTime int64
	tokenRefresher *TokenRefresher

	// ongoingAlarms is the number of ongoing alarms.
	ongoingAlarms = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dcnm_ongoing_alarms",
		Help: "Total number of ongoing alarms",
	})

	// alarmMetrics is the individual alarm metrics.
	alarmMetrics = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dcnm_alarm",
			Help: "Individual alarm metrics",
		},
		[]string{
			"deviceName",
			"deviceAttributes",
			"message",
			"lastScanTimeStamp",
			"eventSwitch",
			"eventType",
			"description",
			"severity",
		},
	)

	// etherInterfaceStats is the Ethernet interface statistics.
	etherInterfaceStats = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dcnm_ether_interface_stats",
			Help: "Ethernet interface statistics",
		},
		[]string{
			"entityName",
			"swIfName",
			"avgDiscardStr",
			"maxRxStr",
			"maxTxStr",
			"speedStr",
			"avgRxStr",
			"avgTxStr",
			"errorStr",
		},
	)

	// serverStatus is the DCNM server status.
	serverStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dcnm_server_status",
			Help: "DCNM server status",
		},
		[]string{
			"service",
		},
	)
)

// LoginResponse is the structure of the login response.
type LoginResponse struct {
	Token string `json:"Dcnm-Token"`
	TTL   int    `json:"expirationTime"`
}

// TokenRefresher is the structure of the token refresher.
type TokenRefresher struct {
	mu          sync.Mutex
	dcnmURL     string
	username    string
	password    string
	token       string
	ttl         time.Duration
	refreshTime time.Duration
}

// EtherInterfaceStat is the structure of the Ethernet interface statistics.
type EtherInterfaceStat struct {
	EntityName    string `json:"entityName"`
	SwIfName      string `json:"swIfName"`
	AvgDiscardStr string `json:"avgDiscardStr"`
	MaxRxStr      string `json:"maxRxStr"`
	MaxTxStr      string `json:"maxTxStr"`
	SpeedStr      string `json:"speedStr"`
	AvgRxStr      string `json:"avgRxStr"`
	AvgTxStr      string `json:"avgTxStr"`
	ErrorStr      string `json:"errorStr"`
}

// setInsecureSSL sets the SSL verification to false.
func setInsecureSSL() {
	// Create a new transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Create a new client
	http.DefaultClient = &http.Client{Transport: tr}
}

// apiCaller is a generic function to call the DCNM API.
func apiCaller(url string, method string, body io.Reader, headers map[string]string) ([]byte, int, error) {

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

	respBody, statusCode, err := apiCaller(url, method, payload, headers)
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

// getAlarms gets all the alarms from the DCNM server.
func getAllAlarms(start, end int) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/fm/fmrest/alarms/alarmlist/?history=false&navId=-1", dcnmURL)

	tokenRefresher.mu.Lock()
	authToken := tokenRefresher.token
	tokenRefresher.mu.Unlock()

	headers := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Cache-Control": "no-cache",
		"Dcnm-Token":    authToken,
		"Range":         fmt.Sprintf("items=%d-%d", start, end),
	}

	respBody, statusCode, err := apiCaller(url, http.MethodGet, nil, headers)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get alarms, status code: %d", statusCode)
	}

	var alarms []map[string]interface{}
	err = json.Unmarshal(respBody, &alarms)
	if err != nil {
		return nil, err
	}

	return alarms, nil
}

// printAlarmsPeriodically prints the alarms periodically.
func printAlarmsPeriodically(interval time.Duration) {
	for {
		alarms, err := getAllAlarms(0, 10000)
		if err != nil {
			log.Printf("Error getting alarms: %v\n", err)
		} else {
			ongoingAlarms.Set(float64(len(alarms)))
			alarmMetrics.Reset()
			for _, alarm := range alarms {
				// ...
				eventsStr := alarm["associatedEvents"].(string)
				var events []map[string]interface{}
				json.Unmarshal([]byte(eventsStr), &events)

				for _, event := range events {
					// ...
					alarmMetrics.WithLabelValues(
						alarm["deviceName"].(string),
						alarm["deviceAttributes"].(string),
						alarm["message"].(string),
						alarm["lastScanTimeStamp"].(string),
						event["EventSwitch"].(string),
						event["EventType"].(string),
						event["description"].(string),
						event["severity"].(string),
					).Set(1)
				}
			}
		}
		time.Sleep(interval)
	}
}

// getAllEtherInterfaceStats gets all the Ethernet interface stats from the DCNM server.
func getAllEtherInterfaceStats(serverIP string) ([]EtherInterfaceStat, error) {
	url := fmt.Sprintf("%s/fm/fmrest/statistics/LanEthernetStat?interval=Day&navId=-1", dcnmURL)

	tokenRefresher.mu.Lock()
	authToken := tokenRefresher.token
	tokenRefresher.mu.Unlock()

	headers := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Cache-Control": "no-cache",
		"Dcnm-Token":    authToken,
	}

	respBody, statusCode, err := apiCaller(url, http.MethodGet, nil, headers)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get Ethernet interface stats, status code: %d", statusCode)
	}

	var stats []EtherInterfaceStat
	err = json.Unmarshal(respBody, &stats)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// updateEtherInterfaceStats updates the Ethernet interface stats periodically.
func updateEtherInterfaceStats(serverIP string) {
	for {
		stats, err := getAllEtherInterfaceStats(serverIP)
		if err != nil {
			log.Printf("Error getting Ethernet interface stats: %v\n", err)
		} else {
			etherInterfaceStats.Reset()
			for _, stat := range stats {
				etherInterfaceStats.WithLabelValues(
					stat.EntityName,
					stat.SwIfName,
					stat.AvgDiscardStr,
					stat.MaxRxStr,
					stat.MaxTxStr,
					stat.SpeedStr,
					stat.AvgRxStr,
					stat.AvgTxStr,
					stat.ErrorStr,
				).Set(1)
			}
		}
		time.Sleep(10 * time.Minute) // Change the interval as needed
	}
}

func getServerStatus(serverIP, authToken string) error {
	url := fmt.Sprintf("%s/fm/fmrest/dbadmin/getServiceList/", serverIP)

	headers := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Cache-Control": "no-cache",
		"Dcnm-Token":    authToken,
	}

	respBody, statusCode, err := apiCaller(url, http.MethodGet, nil, headers)
	if err != nil {
		return err
	}

	if statusCode != http.StatusOK {
		return fmt.Errorf("failed to get server status, status code: %d", statusCode)
	}

	var services []map[string]string
	err = json.Unmarshal(respBody, &services)
	if err != nil {
		return err
	}

	for _, service := range services {
		status, _ := strconv.ParseFloat(service["Status"], 64)
		serverStatus.WithLabelValues(service["Service"]).Set(status)
	}

	return nil
}

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

	prometheus.MustRegister(ongoingAlarms)
	prometheus.MustRegister(alarmMetrics)
	prometheus.MustRegister(etherInterfaceStats)
	prometheus.MustRegister(serverStatus)

}

func main() {
	log.Println("Starting DCNM exporter...")

	//Sets up an insecure SSL connection
	setInsecureSSL()

	// This function refreshes the token, and returns an error if one occurs.
	// The tokenRefresher is a struct that implements the refreshToken() method.
	if err := tokenRefresher.refreshToken(); err != nil {
		log.Printf("Error logging in: %v\n", err)
		return
	}

	go tokenRefresher.autoRefresh()

	go printAlarmsPeriodically(10 * time.Minute) // Change the interval as needed

	go updateEtherInterfaceStats(dcnmURL)

	// Fetch the server status periodically
	go func() {
		for {
			serverIP := dcnmURL
			tokenRefresher.mu.Lock()
			authToken := tokenRefresher.token
			tokenRefresher.mu.Unlock()

			err := getServerStatus(serverIP, authToken)
			if err != nil {
				log.Printf("Error getting server status: %v\n", err)
			}
			time.Sleep(10 * time.Minute) // Change the interval as needed
		}
	}()

	// Initialize the HTTP server for Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(":9740", nil); err != nil {
			log.Printf("Error starting HTTP server: %v\n", err)
			os.Exit(1)
		}
	}()

	// To prevent the main function from exiting, you can add a blocking channel read or a select statement
	select {} // This will block indefinitely
}
