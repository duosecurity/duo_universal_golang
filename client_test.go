package duouniversal

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var clientId = "DIXXXXXXXXXXXXXXXXXX"
var shortClientId = "DIXXXXXXXXXXXXX"
var clientSecret = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
var shortClientSecret = "beefdeadbeefdeadbeefdeadbeef"
var apiHost = "api-deadbeef.duosecurity.com"
var redirectUri = "https://example.com"
var nilErrErrorMsg = "Did not recieve expected error in Health Check"
var nilResultErrorMsg = "Result should be nil but is not"

func TestRandomStateLength(t *testing.T) {
	client, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	output, err := client.generateStateWithLength(100)
	if err != nil {
		t.Error(err)
	}
	if len(output) != 100 {
		t.Errorf("Expected output of length 100, got '%d'", len(output))
	}
}

func TestRandomStateLengthZero(t *testing.T) {
	client, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	output, err := client.generateStateWithLength(0)
	if err != nil {
		t.Error(err)
	}
	if len(output) != 0 {
		t.Errorf("Expected output of length 0, got '%d'", len(output))
	}
}

func TestRandomStateLengthRandom(t *testing.T) {
	client, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	output1, err := client.generateStateWithLength(60)
	if err != nil {
		t.Error(err)
	}
	output2, err := client.generateStateWithLength(60)
	if err != nil {
		t.Error(err)
	}
	if output1 == output2 {
		t.Errorf("State generation output two identical strings, '%s'", output1)
	}
}

func TestRandomStateDefaultLength(t *testing.T) {
	client, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	output, err := client.generateState()
	if err != nil {
		t.Error(err)
	}
	if len(output) != defaultStateLength {
		t.Errorf("Expected output of length %d but got %d", defaultStateLength, len(output))
	}
}

func TestClientInitGood(t *testing.T) {
	client, err := NewClient(clientId, clientSecret, apiHost, redirectUri)
	if err != nil || client == nil {
		t.Error(err)
	}
}

func TestClientInitShortClientId(t *testing.T) {
	_, err := NewClient(shortClientId, clientSecret, apiHost, redirectUri)
	if err == nil {
		t.Error(err)
	}
}

func TestClientInitShortClientSecret(t *testing.T) {
	_, err := NewClient(clientId, shortClientSecret, apiHost, redirectUri)
	if err == nil {
		t.Error(err)
	}
}

func TestHealthCheckGood(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
        {
          "stat": "OK",
          "response": {
            "time": 1357020061
          }
        }`)
	}))
	defer ts.Close()

	duoHost := strings.Split(ts.URL, "//")[1]
	duoClient, err := NewClient(clientId, clientSecret, duoHost, redirectUri)
	duoClient.duoHttpClient = ts.Client()

	result, err := duoClient.healthCheck()
	if err != nil {
		t.Error("Unexpected error from Health Check" + err.Error())
	}
	if result.Stat != "OK" {
		t.Error("Expected OK, but got " + result.Stat)
	}
	if result.Response.Time != 1357020061 {
		t.Errorf("Expected 1357020061, but got %d", result.Response.Time)
	}
	if result.Message != "" {
		t.Error("Expected \"\", but got " + result.Message)
	}
	if result.MessageDetail != "" {
		t.Error("Expected \"\", but got " + result.MessageDetail)
	}
}

func TestHealthCheckFail(t *testing.T) {
	expectedErrorMsg := "invalid_client: The provided client_assertion was invalid"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
        {
          "stat": "FAIL",
          "code": 0,
          "message": "invalid_client",
          "message_detail": "The provided client_assertion was invalid",
          "response": {
            "time": 1357020061
          }
        }`)
	}))
	defer ts.Close()

	duoHost := strings.Split(ts.URL, "//")[1]
	duoClient, err := NewClient(clientId, clientSecret, duoHost, redirectUri)
	duoClient.duoHttpClient = ts.Client()

	result, err := duoClient.healthCheck()
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != expectedErrorMsg {
		t.Error("Expected \"" + expectedErrorMsg + "\" but got " + err.Error())
	}
}

func TestHealthCheckBadJSON(t *testing.T) {
	expectedErrorMsg := "invalid character '\"' after object key:value pair"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
        {
          "stat": "OK"
          "response": {
            "time": 1357020061
          }
        }`)
	}))
	defer ts.Close()

	duoHost := strings.Split(ts.URL, "//")[1]
	duoClient, err := NewClient(clientId, clientSecret, duoHost, redirectUri)
	duoClient.duoHttpClient = ts.Client()

	result, err := duoClient.healthCheck()
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != expectedErrorMsg {
		t.Error("Expected \"" + expectedErrorMsg + "\" but got " + err.Error())
	}
}

func TestHealthCheckNoResponse(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	duoHost := strings.Split(ts.URL, "//")[1]
	duoClient, err := NewClient(clientId, clientSecret, duoHost, redirectUri)
	duoClient.duoHttpClient = ts.Client()

	result, err := duoClient.healthCheck()
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != "unexpected end of JSON input" {
		t.Error("Expected \"unexpected end of JSON input\" but got " + err.Error())
	}
}

func TestHealthCheckError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer ts.Close()

	duoHost := strings.Split(ts.URL, "//")[1]
	duoClient, err := NewClient(clientId, clientSecret, duoHost, redirectUri)
	duoClient.duoHttpClient = ts.Client()

	result, err := duoClient.healthCheck()
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != "404 Not Found" {
		t.Error("Expected \"404 Not Found\" but got " + err.Error())
	}
}
