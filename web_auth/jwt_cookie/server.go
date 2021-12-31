package main

import (
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/url"
)

type userInfo struct {
	password []byte
	Email    string
}

var users = map[string]userInfo{}
var sessions = map[string]string{}

func main() {

	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func index(w http.ResponseWriter, req *http.Request) {
	var msg string
	var displayRegisterLoginLinks string
	var displayLogoutLink string

	c, err := req.Cookie("sessionId")
	if err != nil {
		displayLogoutLink = "none"
		displayRegisterLoginLinks = "block"
	} else {
		t, err := parseToken(c.Value)
		if err != nil {
			http.Error(w, "error verifying session", http.StatusInternalServerError)
			return
		}

		email := sessions[t]
		if user, ok := users[email]; ok {
			msg = fmt.Sprintf("Welcome %v", user.Email)
			displayRegisterLoginLinks = "none"
			displayLogoutLink = "block"
		}
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<title>Welcome</title>
	</head>
	<body>
		<b>%s</b>
		<div style="display: %s">
			<h1>Register or login</h1>
			<a href="/register">Register</a><br>
			<a href="/login">Login</a>
		</div>
		<div style="display: %s">
			<a href="/logout">Logout</a>
		</div>
	</body>
	</html>`, msg, displayRegisterLoginLinks, displayLogoutLink)
}

func login(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		msg := req.FormValue("msg")
		fmt.Fprintf(w, `<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<title>That's a title'</title>
		</head>
		<body>
			<b>%s</b>
			<h1>Login</h1>
			<form action="/login" method="post">
			<div>
				<label for="email">Email</>
				<input type="email" name="email"/>
			</div>
			<div>
				<label for="email">Password</>
				<input type="password" name="password"/>
			</div>
				<input type="submit"/>
			</form>
		</body>
		</html>`, msg)

		return
	}

	if req.Method != http.MethodPost {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	email := req.FormValue("email")
	pass := req.FormValue("password")
	if email == "" {
		msg := url.QueryEscape("email must not be empty")
		http.Redirect(w, req, "/login?msg="+msg, http.StatusSeeOther)
	}

	if pass == "" {
		msg := url.QueryEscape("password must not be empty")
		http.Redirect(w, req, "/login?msg="+msg, http.StatusSeeOther)
	}

	if user, exist := users[email]; exist {
		err := bcrypt.CompareHashAndPassword(user.password, []byte(pass))
		if err != nil {
			http.Error(w, "error logging in", http.StatusInternalServerError)
			return
		}

		sId := uuid.New().String()
		sessions[sId] = email
		token, err := createToken(sId)
		if err != nil {
			msg := url.QueryEscape("couldn't create token")
			http.Redirect(w, req, "/login?msg="+msg, http.StatusSeeOther)
			return
		}

		c := http.Cookie{
			Name:  "sessionId",
			Value: token,
		}
		http.SetCookie(w, &c)

		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("username or password wrong")
	http.Redirect(w, req, "/login?msg="+msg, http.StatusSeeOther)
}

func register(w http.ResponseWriter, req *http.Request) {

	if req.Method == http.MethodGet {
		msg := req.FormValue("msg")

		fmt.Fprintf(w, `<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<title>Please register</title>
		</head>
		<body>
			<b>%s</b>
			<h1>Register</h1>
			<form action="/register" method="post">
			<div>
				<label for="email">Email</>
				<input type="email" name="email"/>
			</div>
			<div>
				<label for="email">Password</>
				<input type="password" name="password"/>
			</div>
				<input type="submit"/>
			</form>
		</body>
		</html>`, msg)

		return
	}

	if req.Method != http.MethodPost {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	email := req.FormValue("email")
	pass := req.FormValue("password")
	if email == "" {
		msg := url.QueryEscape("email must not be empty")
		http.Redirect(w, req, "/?msg="+msg, http.StatusSeeOther)
	}

	if pass == "" {
		msg := url.QueryEscape("password must not be empty")
		http.Redirect(w, req, "/?msg="+msg, http.StatusSeeOther)
	}

	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		http.Error(w, "error registering new user", http.StatusInternalServerError)
		return
	}

	_, exists := users[email]
	if exists {
		msg := url.QueryEscape("email already registered")
		http.Redirect(w, req, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	users[email] = userInfo{
		password: h,
		Email:    email,
	}
	http.Redirect(w, req, "/login", http.StatusSeeOther)
}

func logout(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	c, _ := req.Cookie("sessionId")

	t, _ := parseToken(c.Value)

	delete(sessions, t)

	http.SetCookie(w, c)
	http.Redirect(w, req, "/", http.StatusSeeOther)
}
