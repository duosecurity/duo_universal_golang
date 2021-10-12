package duouniversal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"
)

var clientId = "DIXXXXXXXXXXXXXXXXXX"
var shortClientId = "DIXXXXXXXXXXXXX"
var badClientId = "XXXXXXXXXXXXXXXXXXXX"
var clientSecret = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
var badClientSecret = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
var shortClientSecret = "beefdeadbeefdeadbeefdeadbeef"
var apiHost = "api-deadbeef.duosecurity.com"
var badApiHost = "deadbeef.com"
var redirectUri = "https://example.com"
var state = "deadbeefdeadbeefdeadbeefdeadbeefdead"
var username = "user1"
var nonce = "abcdefghijklmnopqrstuvwxyz"
var badNonce = "aaaaaaaaaaaaaaaaaaaaaaaaaa"

var tokenEndpointResponse = `
        {
            "expires_in": 12345678,
            "access_token": "1234",
            "id_token": "%s",
            "token_type": "type"
        }`

var goodClaims = MapClaims{
	"preferred_username": username,
	"auth_time":          time.Now().Unix(),
	"iss":                "",
	"aud":                clientId,
	"exp":                time.Now().Add(time.Second * time.Duration(expirationTime)).Unix(),
	"iat":                time.Now().Unix(),
	"nonce":              "",
}

const (
	correctSignatureAlgorithm string = "HS512"
	wrongSignatureAlgorithm   string = "HS256"
)

var nilErrErrorMsg = "Did not recieve expected error"
var nilResultErrorMsg = "Result should be nil but is not"
var sigIsInvalid = "failed to verify jws signature: failed to verify message: failed to match hmac signature"
var notSatisfiedError = "%s not satisfied"
var duoCode = "abcdefghijklmnopqrstuvwxyz"
var badUsername = "badUsername"

func TestRandomStateLength(t *testing.T) {
	client, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	output, err := client.GenerateStateWithLength(100)
	if err != nil {
		t.Error(err)
	}
	if len(output) != 100 {
		t.Errorf("Expected output of length 100, got '%d'", len(output))
	}
}

func TestRandomStateLengthZero(t *testing.T) {
	client, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	output, err := client.GenerateStateWithLength(0)
	if err.Error() != "Length needs to be at least 22" {
		t.Error("Did not receive expected error message")
	}

	if output != "" {
		t.Error("Expected result to be empty, got " + output)
	}
}

func TestRandomStateLengthRandom(t *testing.T) {
	client, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	output1, err := client.GenerateStateWithLength(60)
	if err != nil {
		t.Error(err)
	}
	output2, err := client.GenerateStateWithLength(60)
	if err != nil {
		t.Error(err)
	}
	if output1 == output2 {
		t.Errorf("State generation output two identical strings, '%s'", output1)
	}
}

func TestRandomStateDefaultLength(t *testing.T) {
	client, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	output, err := client.GenerateState()
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
	serverResponseMessage := `
        {
          "stat": "OK",
          "response": {
            "time": 1357020061
          }
        }`

	result, err := callHealthCheck(serverResponseMessage)
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
	serverResponseMessage := `
        {
          "stat": "FAIL",
          "code": 0,
          "message": "invalid_client",
          "message_detail": "The provided client_assertion was invalid",
          "response": {
            "time": 1357020061
          }
        }`

	result, err := callHealthCheck(serverResponseMessage)
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
	serverResponseMessage := `
        {
          "stat": "OK"
          "response": {
            "time": 1357020061
          }
        }`

	result, err := callHealthCheck(serverResponseMessage)
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
	result, err := callHealthCheck("")
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
	duoClient, _ := NewClient(clientId, clientSecret, duoHost, redirectUri)
	duoClient.duoHttpClient = ts.Client()

	result, err := duoClient.HealthCheck()
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

func TestCreateAuthURLSuccess(t *testing.T) {
	duoClient, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	result, err := duoClient.CreateAuthURL(username, state)
	if err != nil {
		t.Error("Unexpected error from createAuthUrl" + err.Error())
	}
	if !strings.HasPrefix(result, "https://api-deadbeef.duosecurity.com/oauth/v1/authorize?client_id=DIXXXXXXXXXXXXXXXXXX&request=") {
		t.Error("URL doesn't match expected prefix: " + result)
	}

	base, _ := url.Parse(result)
	requestString := base.Query().Get("request")

	token, err := jwtParseAndValidate(requestString, clientSecret, MapClaims{
		"aud": fmt.Sprintf("https://%s", apiHost),
		"iss": clientId,
	})
	if err != nil {
		t.Error("Expected token to be valid, got err: " + err.Error())
	}
	if token == nil {
		t.Error("Expected token to be valid, got nil")
	}
}

func TestCreateAuthURLMissingUsername(t *testing.T) {
	duoClient, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	result, err := duoClient.CreateAuthURL("", state)
	if result != "" {
		t.Error("Expected result to be empty but got " + result)
	}
	if err.Error() != "The username is invalid." {
		t.Error("Expected 'The username is invalid.' but got " + err.Error())
	}
}

func TestCreateAuthURLShortState(t *testing.T) {
	duoClient, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	result, err := duoClient.CreateAuthURL(username, "deadbeef")
	if result != "" {
		t.Error("Expected result to be empty but got " + result)
	}
	if err.Error() != "State must be at least 22 characters long and no longer than 1024 characters" {
		t.Error("Expected 'State must be at least 22 characters long and no longer than 1024 characters' but got " + err.Error())
	}
}

func TestCreateAuthURLLongState(t *testing.T) {
	duoClient, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	longState := strings.Repeat("a", 1025)
	result, err := duoClient.CreateAuthURL(username, longState)
	if result != "" {
		t.Error("Expected result to be empty but got " + result)
	}
	if err == nil {
		t.Error("Expected err to not be nil")
	}
	if err.Error() != "State must be at least 22 characters long and no longer than 1024 characters" {
		t.Error("Expected 'State must be at least 22 characters long and no longer than 1024 characters' but got " + err.Error())
	}
}

func TestCreateAuthURLDuoCodeAttribute(t *testing.T) {
	duoClientDuoCode, _ := NewClient(clientId, clientSecret, apiHost, redirectUri)
	duoClientNoDuoCode, _ := NewClientDuoCodeAttribute(clientId, clientSecret, apiHost, redirectUri, false)
	testCases := []struct {
		name      string
		duoClient *Client
		expected  bool
	}{
		{"With Duo Code", duoClientDuoCode, true},
		{"Without Duo Code", duoClientNoDuoCode, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, _ := tc.duoClient.CreateAuthURL(username, state)
			urlResult, _ := url.Parse(result)
			urlVals, _ := url.ParseQuery(urlResult.RawQuery)
			request := urlVals["request"][0]
			claims := jwtParseFields(request, clientSecret, []string{"use_duo_code_attribute"})
			v := claims["use_duo_code_attribute"]
			if v != tc.expected {
				errMsg := fmt.Sprintf("Expected result to be %v but got %v", tc.expected, v)
				t.Error(errMsg)
			}
		})
	}
}

func TestExchangeCodeFor2FAVerifyJWT(t *testing.T) {
	testCases := []struct {
		name        string
		key         string
		valueString string
		valueInt    int64
		nonce       string
		want        string
	}{
		{"badPreferredUsername", "preferred_username", badUsername, 0, "", fmt.Sprintf(notSatisfiedError, "preferred_username")},
		{"badAud", "aud", badClientId, 0, "", fmt.Sprintf(notSatisfiedError, "aud")},
		{"badIat", "iat", "", time.Now().Add(time.Second * time.Duration(expirationTime)).Unix(), "", fmt.Sprintf(notSatisfiedError, "iat")},
		{"badExp", "exp", "", time.Now().Unix() - expirationTime, "", fmt.Sprintf(notSatisfiedError, "exp")},
		{"badIss", "iss", fmt.Sprintf(tokenEndpoint, badApiHost), 0, "", fmt.Sprintf(notSatisfiedError, "iss")},
		{"noNonce", "", "", 0, nonce, fmt.Sprintf(notSatisfiedError, "nonce")},
		{"badNonce", "nonce", badNonce, 0, nonce, fmt.Sprintf(notSatisfiedError, "nonce")},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := copyGoodClaims()
			if tc.valueString != "" {
				claims[tc.key] = tc.valueString
			} else {
				claims[tc.key] = tc.valueInt
			}
			result, err := callExchangeAuthorization(tokenEndpointResponse, clientSecret, tc.nonce, claims)
			if result != nil {
				t.Error(nilResultErrorMsg)
			}
			if err == nil {
				t.Error(nilErrErrorMsg)
			}
			if err != nil && err.Error() != tc.want {
				t.Error("Expected \"" + tc.want + "\" but got " + err.Error())
			}
		})
	}
}

func TestExchangeCodeFor2FASuccess(t *testing.T) {
	result, err := callExchangeAuthorization(tokenEndpointResponse, clientSecret, "", goodClaims)
	if result == nil {
		t.Error(nilResultErrorMsg)
	}
	if err != nil {
		fmt.Println(err)
		t.Error(nilErrErrorMsg + err.Error())
	}
}

func TestExchangeCodeFor2FANoCode(t *testing.T) {
	ts := httptest.NewTLSServer(nil)
	duoHost := strings.Split(ts.URL, "//")[1]
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})
	defer ts.Close()
	duoClient, _ := NewClient(clientId, clientSecret, duoHost, redirectUri)
	duoClient.duoHttpClient = ts.Client()
	result, err := duoClient.ExchangeAuthorizationCodeFor2faResult("", username)

	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != duoCodeError {
		t.Error("Expected \"" + duoCodeError + "\" but got " + err.Error())
	}
}

func TestExchangeCodeFor2FANoAccessToken(t *testing.T) {
	responseNoAccessToken := `
        {
            "expires_in": 12345678,
            "id_token": "%s",
            "token_type": "type"
        }`
	result, err := callExchangeAuthorization(responseNoAccessToken, clientSecret, "", goodClaims)
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != parameterError {
		t.Error("Expected \"" + parameterError + "\" but got " + err.Error())
	}
}

func TestExchangeCodeFor2FANoIdToken(t *testing.T) {
	serverResponseMessage := `
        {
            "access_token": "1234",
            "expires_in": 12345678,
            "token_type": "type"
        }`

	result, err := callExchangeAuthorization(serverResponseMessage, clientSecret, "", goodClaims)
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != parameterError {
		t.Error("Expected \"" + parameterError + "\" but got " + err.Error())
	}
}

func TestExchangeCodeFor2FANoExpiresIn(t *testing.T) {
	responseNoExpiresIn := `
        {
            "access_token": "1234",
            "id_token": "%s",
            "token_type": "type"
        }`
	result, err := callExchangeAuthorization(responseNoExpiresIn, clientSecret, "", goodClaims)
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != parameterError {
		t.Error("Expected \"" + parameterError + "\" but got " + err.Error())
	}
}

func TestExchangeCodeFor2FANoTokenType(t *testing.T) {
	responseNoExpiresIn := `
        {
            "access_token": "1234",
            "id_token": "%s",
            "token_type": "type"
        }`

	result, err := callExchangeAuthorization(responseNoExpiresIn, clientSecret, "", goodClaims)
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != parameterError {
		t.Error("Expected \"" + parameterError + "\" but got " + err.Error())
	}
}

func TestExchangeCodeFor2FAGoodNance(t *testing.T) {
	claims := copyGoodClaims()
	claims["nonce"] = nonce
	result, err := callExchangeAuthorization(tokenEndpointResponse, clientSecret, nonce, claims)
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
}

func TestExchangeCodeFor2FABadSignature(t *testing.T) {
	result, err := callExchangeAuthorization(tokenEndpointResponse, badClientSecret, "", goodClaims)
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != sigIsInvalid {
		t.Error("Expected \"" + sigIsInvalid + "\" but got " + err.Error())
	}
}

func TestExchangeCodeFor2FABadSigningMethod(t *testing.T) {
	result, err := callExchangeAuthorizationWithCustomSignature(tokenEndpointResponse, clientSecret, "", goodClaims, wrongSignatureAlgorithm)
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != sigIsInvalid {
		t.Error("Expected \"" + sigIsInvalid + "\" but got " + err.Error())
	}
}

func TestBlockHttpRequests(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer ts.Close()

	expectedError := "Post \"" + ts.URL + "\": " + httpUseError
	duoClient, _ := NewClient(clientId, clientSecret, ts.URL, redirectUri)
	ts.Client().Transport = newStrictTLSTransport()
	duoClient.duoHttpClient = ts.Client()

	result, err := duoClient._makeHttpRequest(ts.URL, "", nil)

	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != expectedError {
		t.Error("Expected \"" + expectedError + "\" but got " + err.Error())
	}
}

func TestSendUserAgent(t *testing.T) {
	claims := copyGoodClaims()
	ts := httptest.NewTLSServer(nil)
	duoHost := strings.Split(ts.URL, "//")[1]
	claims["iss"] = fmt.Sprintf(tokenEndpoint, duoHost)
	m := createServerResponseMessage(tokenEndpointResponse, clientSecret, claims, correctSignatureAlgorithm)
	duoUserAgent := fmt.Sprintf("duo_universal_golang/%s Golang/%s %s/%s", duoVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["User-Agent"][0] == duoUserAgent {
			fmt.Fprintln(w, m)
		} else {
			w.WriteHeader(404)
		}
	})
	defer ts.Close()
	duoClient, _ := NewClient(clientId, clientSecret, duoHost, redirectUri)
	duoClient.duoHttpClient = ts.Client()
	result, err := duoClient.ExchangeAuthorizationCodeFor2faResult(duoCode, username)

	if result == nil {
		t.Error(nilResultErrorMsg)
	}
	if err != nil {
		t.Error(nilErrErrorMsg)
	}
}

func TestMarshalingFlagStatus(t *testing.T) {
	testCases := []struct {
		name      string
		enumValue FlagStatus
		jsonValue string
	}{
		{"Disabled marshaling", Disabled, "false"},
		{"Enabled marshaling", Enabled, "true"},
		{"Unknown marshaling", Unknown, "\"unknown\""},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := json.Marshal(tc.enumValue)
			if err != nil {
				t.Error(err)
			} else if string(result) != tc.jsonValue {
				t.Errorf("Value did not correctly marshal. Expected %s, got: %s", string(tc.jsonValue), string(result))
			}
		})
	}

	type testStruct struct {
		Flag FlagStatus `json:"flag"`
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var result testStruct
			data := fmt.Sprintf("{\"flag\": %s}", tc.jsonValue)
			err := json.Unmarshal([]byte(data), &result)
			if err != nil {
				t.Error(err)
			} else if result.Flag != tc.enumValue {
				t.Errorf("Value did not correctly unmarshal. Expected %d, got: %d", tc.enumValue, result.Flag)
			}
		})
	}
	t.Run("Error marshaling", func(t *testing.T) {
		marshalResult, marshalErr := json.Marshal(FlagStatus(12))
		if marshalErr == nil {
			t.Errorf("Did not produce error when marshaling invalid value. Instead got: %s", marshalResult)
		}
	})
	t.Run("Error unmarshaling", func(t *testing.T) {
		var result testStruct
		data := fmt.Sprintf("{\"flag\": %s}", "badvalue")
		unmarshalErr := json.Unmarshal([]byte(data), &result)
		if unmarshalErr == nil {
			t.Errorf("Did not produce error when unmarshaling invalid value. Instead got %d", result.Flag)
		}
	})
}

// Creates the return message for the test server
func createServerResponseMessage(response, secret string, claims MapClaims, signature string) string {

	signedJwt, err := jwtCreateSignedTokenWithSignature(claims, secret, signature)
	if err != nil {
		fmt.Println(err)
	}
	if strings.Contains(response, "id_token") {
		serverResponseMessage := fmt.Sprintf(response, signedJwt)
		return serverResponseMessage
	}
	return response
}

// Spin up a test server, create a Duo Client, and make a HealthCheck call
func callHealthCheck(m string) (*HealthCheckResponse, error) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, m)
	}))
	defer ts.Close()

	duoHost := strings.Split(ts.URL, "//")[1]
	duoClient, _ := NewClient(clientId, clientSecret, duoHost, redirectUri)
	duoClient.duoHttpClient = ts.Client()
	result, err := duoClient.HealthCheck()
	return result, err
}

// Spin up a test server, create a Duo Client, and make an ExchangeAuthorizationCodeFor2faResultWithNonce call
func callExchangeAuthorizationWithCustomSignature(response, secret, n string, claims MapClaims, signature string) (*TokenResponse, error) {
	ts := httptest.NewTLSServer(nil)
	duoHost := strings.Split(ts.URL, "//")[1]
	if claims["iss"] == "" {
		claims["iss"] = fmt.Sprintf(tokenEndpoint, duoHost)
	}
	m := createServerResponseMessage(response, secret, claims, signature)
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, m)
	})
	defer ts.Close()
	duoClient, _ := NewClient(clientId, clientSecret, duoHost, redirectUri)
	duoClient.duoHttpClient = ts.Client()
	result, err := duoClient.ExchangeAuthorizationCodeFor2faResultWithNonce(duoCode, username, n)
	return result, err
}

// Spin up a test server, create a Duo Client, and make an ExchangeAuthorizationCodeFor2faResultWithNonce call
func callExchangeAuthorization(response, secret, n string, claims MapClaims) (*TokenResponse, error) {
	return callExchangeAuthorizationWithCustomSignature(response, secret, n, claims, correctSignatureAlgorithm)
}

// Copy goodClaims into a new map
func copyGoodClaims() MapClaims {
	claims := make(MapClaims)
	for key, value := range goodClaims {
		claims[key] = value
	}
	return claims
}
