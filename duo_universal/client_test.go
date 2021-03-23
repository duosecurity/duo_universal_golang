package duouniversal

import (
	"fmt"
	"github.com/form3tech-oss/jwt-go"
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

var goodClaims = jwt.MapClaims{
	"preferred_username": username,
	"auth_time":          time.Now().Unix(),
	"iss":                "",
	"aud":                clientId,
	"exp":                time.Now().Add(time.Second * time.Duration(expirationTime)).Unix(),
	"iat":                time.Now().Unix(),
}
var nilErrErrorMsg = "Did not recieve expected error"
var nilResultErrorMsg = "Result should be nil but is not"
var sigIsInvalid = "signature is invalid"
var iatError = "Token used before issued"
var expError = "token is expired by 5m0s"
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
	duoClient, err := NewClient(clientId, clientSecret, duoHost, redirectUri)
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
	duoClient, err := NewClient(clientId, clientSecret, apiHost, redirectUri)
	result, err := duoClient.CreateAuthURL(username, state)
	if err != nil {
		t.Error("Unexpected error from createAuthUrl" + err.Error())
	}
	if !strings.HasPrefix(result, "https://api-deadbeef.duosecurity.com/oauth/v1/authorize?client_id=DIXXXXXXXXXXXXXXXXXX&request=") {
		t.Error("URL doesn't match expected prefix: " + result)
	}

	base, err := url.Parse(result)
	requestString := base.Query().Get("request")
	token, err := jwt.Parse(
		requestString,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(clientSecret), nil
		},
	)

	if !token.Valid {
		t.Error("Expected token to be valid")
	}
}

func TestCreateAuthURLMissingUsername(t *testing.T) {
	duoClient, err := NewClient(clientId, clientSecret, apiHost, redirectUri)
	result, err := duoClient.CreateAuthURL("", state)
	if result != "" {
		t.Error("Expected result to be empty but got " + result)
	}
	if err.Error() != "The username is invalid." {
		t.Error("Expected 'The username is invalid.' but got " + err.Error())
	}
}

func TestCreateAuthURLShortState(t *testing.T) {
	duoClient, err := NewClient(clientId, clientSecret, apiHost, redirectUri)
	result, err := duoClient.CreateAuthURL(username, "deadbeef")
	if result != "" {
		t.Error("Expected result to be empty but got " + result)
	}
	if err.Error() != "State must be at least 22 characters long and no longer than 1024 characters" {
		t.Error("Expected 'State must be at least 22 characters long and no longer than 1024 characters' but got " + err.Error())
	}
}

func TestCreateAuthURLLongState(t *testing.T) {
	duoClient, err := NewClient(clientId, clientSecret, apiHost, redirectUri)
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

func TestExchangeCodeFor2FAVerifyJWT(t *testing.T) {
	testCases := []struct {
		name        string
		key         string
		valueString string
		valueInt    int64
		nonce       string
		want        string
	}{
		{"badPreferredUsername", "preferred_username", badUsername, 0, "", usernameMismatchError},
		{"badAud", "aud", badClientId, 0, "", jwtResponseError},
		{"badIat", "iat", "", time.Now().Add(time.Second * time.Duration(expirationTime)).Unix(), "", iatError},
		{"badExp", "exp", "", time.Now().Unix() - expirationTime, "", expError},
		{"badIss", "iss", fmt.Sprintf(tokenEndpoint, badApiHost), 0, "", jwtResponseError},
		{"noNonce", "", "", 0, nonce, nonceError},
		{"badNonce", "nonce", badNonce, 0, nonce, nonceError},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := copyGoodClaims()
			if tc.valueString != "" {
				claims[tc.key] = tc.valueString
			} else {
				claims[tc.key] = tc.valueInt
			}
			result, err := callExchangeAuthorization(tokenEndpointResponse, clientSecret, tc.nonce, claims, jwt.SigningMethodHS512)
			if result != nil {
				t.Error(nilResultErrorMsg)
			}
			if err == nil {
				t.Error(nilErrErrorMsg)
			}
			if err.Error() != tc.want {
				t.Error("Expected \"" + tc.want + "\" but got " + err.Error())
			}
		})
	}
}

func TestExchangeCodeFor2FASuccess(t *testing.T) {
	result, err := callExchangeAuthorization(tokenEndpointResponse, clientSecret, "", goodClaims, jwt.SigningMethodHS512)
	if result == nil {
		t.Error(nilResultErrorMsg)
	}
	if err != nil {
		fmt.Println(err)
		t.Error(nilErrErrorMsg)
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
	result, err := callExchangeAuthorization(responseNoAccessToken, clientSecret, "", goodClaims, jwt.SigningMethodHS512)
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

	result, err := callExchangeAuthorization(serverResponseMessage, clientSecret, "", goodClaims, jwt.SigningMethodHS512)
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
	result, err := callExchangeAuthorization(responseNoExpiresIn, clientSecret, "", goodClaims, jwt.SigningMethodHS512)
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

	result, err := callExchangeAuthorization(responseNoExpiresIn, clientSecret, "", goodClaims, jwt.SigningMethodHS512)
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
	result, err := callExchangeAuthorization(tokenEndpointResponse, clientSecret, nonce, claims, jwt.SigningMethodHS512)
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
}

func TestExchangeCodeFor2FABadSignature(t *testing.T) {
	result, err := callExchangeAuthorization(tokenEndpointResponse, badClientSecret, "", goodClaims, jwt.SigningMethodHS512)
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
	result, err := callExchangeAuthorization(tokenEndpointResponse, clientSecret, "", goodClaims, jwt.SigningMethodHS256)
	if result != nil {
		t.Error(nilResultErrorMsg)
	}
	if err == nil {
		t.Error(nilErrErrorMsg)
	}
	if err.Error() != signatureError {
		t.Error("Expected \"" + signatureError + "\" but got " + err.Error())
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
	m := createServerResponseMessage(tokenEndpointResponse, clientSecret, claims, jwt.SigningMethodHS512)
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
	result, err := duoClient.exchangeAuthorizationCodeFor2faResult(duoCode, username)

	if result == nil {
		t.Error(nilResultErrorMsg)
	}
	if err != nil {
		t.Error(nilErrErrorMsg)
	}
}

// Creates the return message for the test server
func createServerResponseMessage(response, secret string, claims jwt.MapClaims, jwtSignature *jwt.SigningMethodHMAC) string {
	jwtWithClaims := jwt.NewWithClaims(jwtSignature, claims)
	signedJwt, err := jwtWithClaims.SignedString([]byte(secret))
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
func callExchangeAuthorization(response, secret, n string, claims jwt.MapClaims, jwtSignature *jwt.SigningMethodHMAC) (*TokenResponse, error) {
	ts := httptest.NewTLSServer(nil)
	duoHost := strings.Split(ts.URL, "//")[1]
	if claims["iss"] == "" {
		claims["iss"] = fmt.Sprintf(tokenEndpoint, duoHost)
	}
	m := createServerResponseMessage(response, secret, claims, jwtSignature)
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, m)
	})
	defer ts.Close()
	duoClient, _ := NewClient(clientId, clientSecret, duoHost, redirectUri)
	duoClient.duoHttpClient = ts.Client()
	result, err := duoClient.ExchangeAuthorizationCodeFor2faResultWithNonce(duoCode, username, n)
	return result, err
}

// Copy goodClaims into a new map
func copyGoodClaims() jwt.MapClaims {
	claims := make(jwt.MapClaims)
	for key, value := range goodClaims {
		claims[key] = value
	}
	return claims
}
