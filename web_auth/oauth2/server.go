/*
OAuth2 example using Authorization Code Grant Flow.

Disclaimer

Code is not production ready. Many things would still have to be improved.
Current status served only for learning purposes.

*/
package main

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type githubResponse struct {
	Data struct {
		Viewer struct {
			Id    string `json:"id"`
			Login string `json:"login"`
		} `json:"viewer"`
	} `json:"data"`
}

var githubUsers map[string]string

var githubConfig *oauth2.Config

var loginExpirationMap = map[string]time.Time{}

func main() {

	// load oauth provider secrets form .env file in root
	// see .env.example for reference
	err := godotenv.Load()

	githubConfig = &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		Endpoint:     github.Endpoint,
		RedirectURL:  os.Getenv("GITHUB_CALLBACK_URL"),
		Scopes:       []string{"read:user"},
	}

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/gh", startGithubAuth)
	http.HandleFunc("/oauth/callback", githubCallback)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
	fmt.Fprintf(w, `<!doctype html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport"
			  content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>OAuth2 example</title>
	</head>
	<body>
	<b>%s</b>
	<form action="/oauth/gh">
		<input type="submit" value="Login with github" />
	</form>
	</body>
	</html>`, msg)
}

func startGithubAuth(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()
	loginExpirationMap[state] = time.Now().Add(1 * time.Hour)
	redirectUrl := githubConfig.AuthCodeURL(state)
	http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
}

func githubCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if loginExpires, ok := loginExpirationMap[state]; !ok || time.Now().After(loginExpires) {
		http.Error(w, "state is incorrect or login window expired", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")

	token, err := githubConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "couldn't login", http.StatusInternalServerError)
		return
	}

	ts := githubConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)
	requestBody := strings.NewReader(`{"query": "query {viewer {id login}}"}`)
	resp, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
	if err != nil {
		http.Error(w, "Couldn't get user information", http.StatusInternalServerError)
	}

	if err != nil {
		http.Error(w, "Couldn't read user information", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var ghResponse githubResponse
	err = json.NewDecoder(resp.Body).Decode(&ghResponse)
	if err != nil {
		http.Error(w, "invalid response", http.StatusInternalServerError)
	}

	// Here we have reached a good starting point to continue with things like session state-handling, JWT, user registration if more infos needed from user etc.
	// Below code is only to show message. Real work begins here :-)

	ghUser := ghResponse.Data.Viewer
	ghUserId := ghUser.Id
	ghUserLogin := ghUser.Login

	msg := url.QueryEscape(fmt.Sprintf("Logged in with github user  %v (%v)", ghUserId, ghUserLogin))
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)

}
