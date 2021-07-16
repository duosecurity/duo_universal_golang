package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/duosecurity/duo_universal_golang/duouniversal"
)

const duoUnavailable = "Duo unavailable"

type Session struct {
	duoState    string
	duoUsername string
	failmode    string
}

type Config struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	ApiHost      string `json:"apiHost"`
	RedirectUri  string `json:"redirectUri"`
	Failmode     string `json:"failmode"`
}

func main() {
	session := Session{}
	file, err := os.Open("duo_config.json")
	duoConfig := Config{}
	if err != nil {
		log.Fatal("can't open config file: ", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&duoConfig)
	if err != nil {
		log.Fatal("can't decode config JSON: ", err)
	}
	// Step 1: Create a Duo client
	duoClient, err := duouniversal.NewClient(duoConfig.ClientId, duoConfig.ClientSecret, duoConfig.ApiHost, duoConfig.RedirectUri)
	session.failmode = strings.ToUpper(duoConfig.Failmode)
	if err != nil {
		log.Fatal("Error parsing config: ", err)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session.login(w, r, duoClient)
	})
	http.HandleFunc("/duo-callback", func(w http.ResponseWriter, r *http.Request) {
		session.duoCallback(w, r, duoClient)
	})
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Running demo on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func (session *Session) login(w http.ResponseWriter, r *http.Request, c *duouniversal.Client) {
	if r.Method == "GET" {
		// Render the login template
		renderTemplate("login.html", "This is a demo.", w)
	} else if r.Method == "POST" {
		r.ParseForm()
		session.duoUsername = r.FormValue("username")
		password := r.FormValue("password")
		if password == "" {
			renderTemplate("login.html", "Password required", w)
			return
		}
		if session.duoUsername == "" {
			renderTemplate("login.html", "Username required", w)
			return
		}
		// Step 2: Call the healthCheck to make sure Duo is accessable
		_, err := c.HealthCheck()

		// Step 3: If Duo is not available to authenticate then either allow user
		// to bypass Duo (failopen) or prevent user from authenticating (failclosed)
		if err != nil {
			if session.failmode == "CLOSED" {
				renderTemplate("login.html", duoUnavailable, w)
			} else {
				renderTemplate("success.html", duoUnavailable, w)
			}
		}

		// Step 4: Generate and save a state variable
		session.duoState, err = c.GenerateState()
		if err != nil {
			log.Fatal("Error generating state: ", err)
		}

		// Step 5: Create a URL to redirect to inorder to reach the Duo prompt
		redirectToDuoUrl, err := c.CreateAuthURL(session.duoUsername, session.duoState)
		if err != nil {
			log.Fatal("Error creating the auth URL: ", err)
		}

		// Step 6: Redirect to that prompt
		http.Redirect(w, r, redirectToDuoUrl, 302)
	}
}

func (session *Session) duoCallback(w http.ResponseWriter, r *http.Request, c *duouniversal.Client) {
	// Step 7: Grab the state and duo_code variables from the URL parameters
	urlState := r.URL.Query().Get("state")
	duoCode := r.URL.Query().Get("duo_code")

	// Step 8: Verify that the state in the URL matches the state saved previously
	if urlState != session.duoState {
		renderTemplate("login.html", "Duo state does not match saved state", w)
		return
	}

	// Step 9: Exchange the duoCode from the URL parameters and the username of the user trying to authenticate
	// for an authentication token containing information about the auth
	authToken, err := c.ExchangeAuthorizationCodeFor2faResult(duoCode, session.duoUsername)
	if err != nil {
		log.Fatal("Error exchanging authToken: ", err)
	}
	message, _ := json.MarshalIndent(authToken, " ", "    ")
	renderTemplate("success.html", string(message), w)
}

// Renders HTML page with message
func renderTemplate(fileName, message string, w http.ResponseWriter) {
	fp := path.Join("templates", fileName)
	tmpl, _ := template.ParseFiles(fp)
	tmpl.Execute(w, map[string]interface{}{
		"Message": message,
	})
}
