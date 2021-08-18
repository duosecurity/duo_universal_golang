package duouniversal

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

const defaultStateLength = 36
const minimumStateLength = 22
const maximumStateLength = 1024
const defaultJtiLength = 36
const clientIdLength = 20
const clientSecretLength = 40
const expirationTime = 300
const allowedSkew = time.Duration(60) * time.Second
const healthCheckEndpoint = "https://%s/oauth/v1/health_check"
const oauthV1AuthorizeEndpoint = "https://%s/oauth/v1/authorize"
const apiHostURIFormat = "https://%s"
const tokenEndpoint = "https://%s/oauth/v1/token"
const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// StateCharacters is the set of possible characters used in the random state
const stateCharacters = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
	"1234567890"
const clientIdError = "The Duo client id is invalid."
const clientSecretError = "The Duo client secret is invalid."
const usernameError = "The username is invalid."
const parameterError = "Did not recieve expected parameters."
const duoCodeError = "Missing authorization code"
const httpUseError = "This client does not allow use of http, please use https"
const duoVersion = "1.0.1"

var stateLengthError = fmt.Sprintf("State must be at least %d characters long and no longer than %d characters", minimumStateLength, maximumStateLength)
var generateStateLengthError = fmt.Sprintf("Length needs to be at least %d", minimumStateLength)

type HealthCheckTime struct {
	Time int `json:"time"`
}

type HealthCheckResponse struct {
	Stat          string          `json:"stat"`
	Message       string          `json:"message"`
	MessageDetail string          `json:"message_detail"`
	Response      HealthCheckTime `json:"response"`
	Code          int             `json:"code"`
}

type BodyToken struct {
	IdToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type AuthResultInfo struct {
	Result    string `json:"result"`
	Status    string `json:"status"`
	StatusMsg string `json:"status_msg"`
}

type LocationInfo struct {
	City    string `json:"city"`
	Country string `json:"country"`
	State   string `json:"state"`
}

type AccessDeviceInfo struct {
	Browser             string       `json:"browser"`
	BrowserVersion      string       `json:"browser_version"`
	FlashVersion        string       `json:"flash_version"`
	Hostname            string       `json:"host_name"`
	Ip                  string       `json:"ip"`
	IsEncryptionEnabled string       `json:"is_encryption_enabled"`
	IsFirewallEnabled   string       `json:"is_firewall_enabled"`
	IsPasswordSet       string       `json:"is_password_set"`
	JavaVersion         string       `json:"java_version"`
	Location            LocationInfo `json:"location"`
	Os                  string       `json:"os"`
	OsVersion           string       `json:"os_version"`
}

type AuthDeviceInfo struct {
	Ip       string       `json:"ip"`
	Location LocationInfo `json:"location"`
	Name     string       `json:"name"`
}

type ApplicationInfo struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type UserInfo struct {
	Groups []string `json:"groups"`
	Key    string   `json:"key"`
	Name   string   `json:"name"`
}

type AuthContextInfo struct {
	AccessDevice AccessDeviceInfo `json:"access_device"`
	Alias        string           `json:"alias"`
	Application  ApplicationInfo  `json:"application"`
	AuthDevice   AuthDeviceInfo   `json:"auth_device"`
	Email        string           `json:"email"`
	EventType    string           `json:"event_type"`
	Factor       string           `json:"factor"`
	Isotimestamp string           `json:"isotimestamp"`
	OodSoftware  string           `json:"ood_software"`
	Reason       string           `json:"reason"`
	Result       string           `json:"result"`
	Timestamp    int              `json:"timestamp"`
	Txid         string           `json:"txid"`
	User         UserInfo         `json:"user"`
}

type TokenResponse struct {
	PreferredUsername string          `json:"preferred_username"`
	AuthTime          int             `json:"auth_time"`
	Nonce             string          `json:"nonce"`
	AuthResult        AuthResultInfo  `json:"auth_result"`
	AuthContext       AuthContextInfo `json:"auth_context"`
	Audience          string          `json:"aud"`
	ExpiresAt         int64           `json:"exp"`
	Id                string          `json:"jti"`
	IssuedAt          int64           `json:"iat"`
	Issuer            string          `json:"iss"`
	Subject           string          `json:"sub"`
}

type Client struct {
	clientId            string
	clientSecret        string
	apiHost             string
	redirectUri         string
	useDuoCodeAttribute bool
	duoHttpClient       httpClient
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Blocks HTTP requests
func refuseHttpConnection(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, fmt.Errorf(httpUseError)
}

// Creates a http.Transport that pins certs to Duo and refuses HTTP connections
func newStrictTLSTransport() *http.Transport {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(duoPinnedCert))

	tlsDialer := &tls.Dialer{
		Config: &tls.Config{
			RootCAs: certPool,
		},
	}
	return &http.Transport{
		DialContext:    refuseHttpConnection,
		DialTLSContext: tlsDialer.DialContext,
	}
}

func NewClient(clientId, clientSecret, apiHost, redirectUri string) (*Client, error) {
	return NewClientDuoCodeAttribute(clientId, clientSecret, apiHost, redirectUri, true)
}

// Creates a new Client with the ability to turn off use_duo_code_attribute
func NewClientDuoCodeAttribute(clientId, clientSecret, apiHost, redirectUri string, useDuoCodeAttribute bool) (*Client, error) {
	if len(clientId) != clientIdLength {
		return nil, fmt.Errorf(clientIdError)
	} else if len(clientSecret) != clientSecretLength {
		return nil, fmt.Errorf(clientSecretError)
	}

	return &Client{
		clientId:            clientId,
		clientSecret:        clientSecret,
		apiHost:             apiHost,
		redirectUri:         redirectUri,
		useDuoCodeAttribute: useDuoCodeAttribute,
		duoHttpClient: &http.Client{
			Transport: newStrictTLSTransport(),
		},
	}, nil
}

// Return a cryptographically-secure string of random characters
// with the default length
func (client *Client) GenerateState() (string, error) {
	return client.GenerateStateWithLength(defaultStateLength)
}

// Return a cryptographically-secure string of random characters
// suitable for use in state values.
// length is the number of characters in the randomly generated string
func (client *Client) GenerateStateWithLength(length int) (string, error) {
	if length < minimumStateLength {
		return "", fmt.Errorf(generateStateLengthError)
	}

	result := make([]byte, length)
	possibleCharacters := int64(len(stateCharacters))
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(possibleCharacters))
		if err != nil {
			return "", err
		}
		result[i] = stateCharacters[n.Int64()]
	}
	return string(result), nil
}

// Creates a JWT token used for the "client_assertion" parameter in the health check
// and "requset" parameter in the token endpoint
func (client *Client) createJwtArgs(aud string) (string, error) {
	jti, err := client.GenerateStateWithLength(defaultJtiLength)
	if err != nil {
		return "", err
	}

	claims := MapClaims{
		"iss": client.clientId,
		"sub": client.clientId,
		"aud": aud,
		"exp": time.Now().Add(time.Second * time.Duration(expirationTime)).Unix(),
		"jti": jti,
	}

	token, err := client.createSignedToken(claims)
	if err != nil {
		return "", err
	}

	return token, nil
}

// Makes HTTP request to Duo
func (client *Client) _makeHttpRequest(e, userAgent string, p url.Values) ([]byte, error) {
	r, err := http.NewRequest(http.MethodPost, e, strings.NewReader(p.Encode()))
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if userAgent != "" {
		r.Header.Set("User-Agent", userAgent)
	}
	resp, err := client.duoHttpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// Checks whether or not Duo is available.
func (client *Client) HealthCheck() (*HealthCheckResponse, error) {
	postParams := url.Values{}
	healthCheckResponse := &HealthCheckResponse{}
	healthCheckUrl := fmt.Sprintf(healthCheckEndpoint, client.apiHost)

	token, err := client.createJwtArgs(healthCheckUrl)
	if err != nil {
		return nil, err
	}

	postParams.Add("client_assertion", token)
	postParams.Add("client_id", client.clientId)
	body, err := client._makeHttpRequest(healthCheckUrl, "", postParams)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, healthCheckResponse)
	if err != nil {
		return nil, err
	}
	if healthCheckResponse.Stat != "OK" {
		return nil, fmt.Errorf("%s: %s", healthCheckResponse.Message, healthCheckResponse.MessageDetail)
	}

	return healthCheckResponse, nil
}

func (client *Client) CreateAuthURL(username string, state string) (string, error) {

	err := validateClientCreateAuthURLInputs(username, state)
	if err != nil {
		return "", err
	}

	authorizeEndpoint := fmt.Sprintf(oauthV1AuthorizeEndpoint, client.apiHost)

	claims := MapClaims{
		"scope":                  "openid",
		"redirect_uri":           client.redirectUri,
		"client_id":              client.clientId,
		"iss":                    client.clientId,
		"aud":                    fmt.Sprintf(apiHostURIFormat, client.apiHost),
		"exp":                    time.Now().Add(time.Second * time.Duration(expirationTime)).Unix(),
		"state":                  state,
		"response_type":          "code",
		"duo_uname":              username,
		"use_duo_code_attribute": client.useDuoCodeAttribute,
	}

	requestJWTSigned, err := client.createSignedToken(claims)
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", client.clientId)
	params.Add("request", requestJWTSigned)

	base, err := url.Parse(authorizeEndpoint)
	if err != nil {
		return "", err
	}
	base.RawQuery = params.Encode()
	authorizationURI := base.String()

	return authorizationURI, nil
}

func (client *Client) createSignedToken(claims MapClaims) (string, error) {
	return jwtCreateSignedToken(claims, client.clientSecret)
}

func validateClientCreateAuthURLInputs(username string, state string) error {
	stateLength := len(state)
	if stateLength < minimumStateLength || stateLength > maximumStateLength {
		return fmt.Errorf(stateLengthError)
	}

	if username == "" {
		return fmt.Errorf(usernameError)
	}

	return nil
}

func (client *Client) ExchangeAuthorizationCodeFor2faResult(duoCode string, username string) (*TokenResponse, error) {
	return client.ExchangeAuthorizationCodeFor2faResultWithNonce(duoCode, username, "")
}

// Exchange the duo_code for a token with Duo to determine if the auth was successful.
func (client *Client) ExchangeAuthorizationCodeFor2faResultWithNonce(duoCode string, username string, nonce string) (*TokenResponse, error) {
	if duoCode == "" {
		return nil, fmt.Errorf(duoCodeError)
	}
	tokenUrl := fmt.Sprintf(tokenEndpoint, client.apiHost)
	postParams := url.Values{}
	bodyToken := &BodyToken{}
	jwtToken, err := client.createJwtArgs(tokenUrl)
	if err != nil {
		return nil, err
	}

	postParams.Add("redirect_uri", client.redirectUri)
	postParams.Add("grant_type", "authorization_code")
	postParams.Add("code", duoCode)
	postParams.Add("client_id", client.clientId)
	postParams.Add("client_assertion_type", clientAssertionType)
	postParams.Add("client_assertion", jwtToken)

	duoUserAgent := fmt.Sprintf("duo_universal_golang/%s Golang/%s %s/%s", duoVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)

	body, err := client._makeHttpRequest(tokenUrl, duoUserAgent, postParams)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, bodyToken)
	if err != nil {
		return nil, err
	}
	if bodyToken.AccessToken == "" || bodyToken.IdToken == "" ||
		bodyToken.ExpiresIn == 0 || bodyToken.TokenType == "" {
		return nil, fmt.Errorf(parameterError)
	}

	claimsToVerify := MapClaims{
		"aud":                client.clientId,
		"iss":                fmt.Sprintf(tokenEndpoint, client.apiHost),
		"preferred_username": username,
		"nonce":              nonce,
	}

	jwtResponse, err := jwtParseAndValidate(bodyToken.IdToken, client.clientSecret, claimsToVerify)

	if err != nil {
		return nil, err
	}

	return jwtResponse, nil
}

const duoPinnedCert string = `
subject= /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Assured ID Root CA
-----BEGIN CERTIFICATE-----
MIIDtzCCAp+gAwIBAgIQDOfg5RfYRv6P5WD8G/AwOTANBgkqhkiG9w0BAQUFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMzExMTEwMDAwMDAwWjBlMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
cnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtDhXO5EOAXLGH87dg+XESpa7c
JpSIqvTO9SA5KFhgDPiA2qkVlTJhPLWxKISKityfCgyDF3qPkKyK53lTXDGEKvYP
mDI2dsze3Tyoou9q+yHyUmHfnyDXH+Kx2f4YZNISW1/5WBg1vEfNoTb5a3/UsDg+
wRvDjDPZ2C8Y/igPs6eD1sNuRMBhNZYW/lmci3Zt1/GiSw0r/wty2p5g0I6QNcZ4
VYcgoc/lbQrISXwxmDNsIumH0DJaoroTghHtORedmTpyoeb6pNnVFzF1roV9Iq4/
AUaG9ih5yLHa5FcXxH4cDrC0kqZWs72yl+2qp/C3xag/lRbQ/6GW6whfGHdPAgMB
AAGjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBRF66Kv9JLLgjEtUYunpyGd823IDzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYun
pyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEAog683+Lt8ONyc3pklL/3cmbYMuRC
dWKuh+vy1dneVrOfzM4UKLkNl2BcEkxY5NM9g0lFWJc1aRqoR+pWxnmrEthngYTf
fwk8lOa4JiwgvT2zKIn3X/8i4peEH+ll74fg38FnSbNd67IJKusm7Xi+fT8r87cm
NW1fiQG2SVufAQWbqz0lwcy2f8Lxb4bG+mRo64EtlOtCt/qMHt1i8b5QZ7dsvfPx
H2sMNgcWfzd8qVttevESRmCD1ycEvkvOl77DZypoEd+A5wwzZr8TDRRu838fYxAe
+o0bJW1sj6W3YQGx0qMmoRBxna3iw/nDmVG3KwcIzi7mULKn+gpFL6Lw8g==
-----END CERTIFICATE-----
subject= /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----
subject= /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDEL
MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2Ug
RVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm
+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTW
PNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEM
xChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFB
Ik5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3
hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsg
EsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQF
MAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaA
FLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3Nec
nzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6z
eM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jF
hS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2
Yzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCe
vEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep
+OkuE6N36B9K
-----END CERTIFICATE-----
subject= /C=US/O=SecureTrust Corporation/CN=SecureTrust CA
-----BEGIN CERTIFICATE-----
MIIDuDCCAqCgAwIBAgIQDPCOXAgWpa1Cf/DrJxhZ0DANBgkqhkiG9w0BAQUFADBI
MQswCQYDVQQGEwJVUzEgMB4GA1UEChMXU2VjdXJlVHJ1c3QgQ29ycG9yYXRpb24x
FzAVBgNVBAMTDlNlY3VyZVRydXN0IENBMB4XDTA2MTEwNzE5MzExOFoXDTI5MTIz
MTE5NDA1NVowSDELMAkGA1UEBhMCVVMxIDAeBgNVBAoTF1NlY3VyZVRydXN0IENv
cnBvcmF0aW9uMRcwFQYDVQQDEw5TZWN1cmVUcnVzdCBDQTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKukgeWVzfX2FI7CT8rU4niVWJxB4Q2ZQCQXOZEz
Zum+4YOvYlyJ0fwkW2Gz4BERQRwdbvC4u/jep4G6pkjGnx29vo6pQT64lO0pGtSO
0gMdA+9tDWccV9cGrcrI9f4Or2YlSASWC12juhbDCE/RRvgUXPLIXgGZbf2IzIao
wW8xQmxSPmjL8xk037uHGFaAJsTQ3MBv396gwpEWoGQRS0S8Hvbn+mPeZqx2pHGj
7DaUaHp3pLHnDi+BeuK1cobvomuL8A/b01k/unK8RCSc43Oz969XL0Imnal0ugBS
8kvNU3xHCzaFDmapCJcWNFfBZveA4+1wVMeT4C4oFVmHursCAwEAAaOBnTCBmjAT
BgkrBgEEAYI3FAIEBh4EAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB
/zAdBgNVHQ4EFgQUQjK2FvoE/f5dS3rD/fdMQB1aQ68wNAYDVR0fBC0wKzApoCeg
JYYjaHR0cDovL2NybC5zZWN1cmV0cnVzdC5jb20vU1RDQS5jcmwwEAYJKwYBBAGC
NxUBBAMCAQAwDQYJKoZIhvcNAQEFBQADggEBADDtT0rhWDpSclu1pqNlGKa7UTt3
6Z3q059c4EVlew3KW+JwULKUBRSuSceNQQcSc5R+DCMh/bwQf2AQWnL1mA6s7Ll/
3XpvXdMc9P+IBWlCqQVxyLesJugutIxq/3HcuLHfmbx8IVQr5Fiiu1cprp6poxkm
D5kuCLDv/WnPmRoJjeOnnyvJNjR7JLN4TJUXpAYmHrZkUjZfYGfZnMUFdAvnZyPS
CPyI6a6Lf+Ew9Dd+/cYy2i2eRDAwbO4H3tI0/NL/QPZL9GZGBlSm8jIKYyYwa5vR
3ItHuuG51WLQoqD0ZwV4KWMabwTW+MZMo5qxN7SN5ShLHZ4swrhovO0C7jE=
-----END CERTIFICATE-----
subject= /C=US/O=SecureTrust Corporation/CN=Secure Global CA
-----BEGIN CERTIFICATE-----
MIIDvDCCAqSgAwIBAgIQB1YipOjUiolN9BPI8PjqpTANBgkqhkiG9w0BAQUFADBK
MQswCQYDVQQGEwJVUzEgMB4GA1UEChMXU2VjdXJlVHJ1c3QgQ29ycG9yYXRpb24x
GTAXBgNVBAMTEFNlY3VyZSBHbG9iYWwgQ0EwHhcNMDYxMTA3MTk0MjI4WhcNMjkx
MjMxMTk1MjA2WjBKMQswCQYDVQQGEwJVUzEgMB4GA1UEChMXU2VjdXJlVHJ1c3Qg
Q29ycG9yYXRpb24xGTAXBgNVBAMTEFNlY3VyZSBHbG9iYWwgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvNS7YrGxVaQZx5RNoJLNP2MwhR/jxYDiJ
iQPpvepeRlMJ3Fz1Wuj3RSoC6zFh1ykzTM7HfAo3fg+6MpjhHZevj8fcyTiW89sa
/FHtaMbQbqR8JNGuQsiWUGMu4P51/pinX0kuleM5M2SOHqRfkNJnPLLZ/kG5VacJ
jnIFHovdRIWCQtBJwB1g8NEXLJXr9qXBkqPFwqcIYA1gBBCWeZ4WNOaptvolRTnI
HmX5k/Wq8VLcmZg9pYYaDDUz+kulBAYVHDGA76oYa8J719rO+TMg1fW9ajMtgQT7
sFzUnKPiXB3jqUJ1XnvUd+85VLrJChgbEplJL4hL/VBi0XPnj3pDAgMBAAGjgZ0w
gZowEwYJKwYBBAGCNxQCBAYeBABDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQF
MAMBAf8wHQYDVR0OBBYEFK9EBMJBfkiD2045AuzshHrmzsmkMDQGA1UdHwQtMCsw
KaAnoCWGI2h0dHA6Ly9jcmwuc2VjdXJldHJ1c3QuY29tL1NHQ0EuY3JsMBAGCSsG
AQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBBQUAA4IBAQBjGghAfaReUw132HquHw0L
URYD7xh8yOOvaliTFGCRsoTciE6+OYo68+aCiV0BN7OrJKQVDpI1WkpEXk5X+nXO
H0jOZvQ8QCaSmGwb7iRGDBezUqXbpZGRzzfTb+cnCDpOGR86p1hcF895P4vkp9Mm
I50mD1hp/Ed+stCNi5O/KU9DaXR2Z0vPB4zmAve14bRDtUstFJ/53CYNv6ZHdAbY
iNE6KTCEztI5gGIbqMdXSbxqVVFnFUq+NQfk1XWYN3kwFNspnWzFacxHVaIw98xc
f8LDmBxrThaA63p4ZUWiABqvDA1VZDRIuJK58bRQKfJPIx/abKwfROHdI3hRW8cW
-----END CERTIFICATE-----`
