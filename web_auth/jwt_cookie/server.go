package main

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"io"
	"net/http"
	"strings"
	"time"
)

type userClaims struct {
	jwt.StandardClaims
	Email string
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/submit", submit)
	http.ListenAndServe(":8080", nil)
}

func submit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

	jwt, err := createJwt(email)
	if err != nil {

		http.Error(w, "couldn't get JWT", http.StatusInternalServerError)

	}

	c := http.Cookie{
		Name:  "session",
		Value: jwt + "|" + email,
	}

	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)

}

func createJwt(msg string) (string, error) {
	key := key()

	claims := &userClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
		Email: msg,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	signedString, err := token.SignedString([]byte(key))
	if err != nil {
		return "", fmt.Errorf("unable to sign token")
	}

	return signedString, nil
}

func key() string {
	key := "secret"
	return key
}

func index(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}

	message := "Not logged in"

	xs := strings.SplitN(c.Value, "|", 2)
	if len(xs) == 2 {
		cCode := xs[0]
		//cEmail := xs[1]

		t, err := jwt.ParseWithClaims(cCode, &userClaims{}, func(token *jwt.Token) (interface{}, error) {

			if token.Method.Alg() != jwt.SigningMethodHS512.Alg() {
				return nil, fmt.Errorf("invalid signing method detected")
			}
			return []byte(key()), nil
		})

		if err != nil {
			http.Error(w, "error parsing jwt token", http.StatusInternalServerError)
		}

		if claims, ok := t.Claims.(*userClaims); ok && t.Valid {
			fmt.Printf("%v %v", claims.Email, claims.StandardClaims.ExpiresAt)
			message = "Logged in"
		}
	}

	html :=
		`<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<title>HMAC Example</title>
	</head>
	<body>
	<p>Cookie: ` + c.Value + `</p>
	<p>` + message + `</p>
		<form action="/submit" method="post">
			<input type="email" name="email"/>
			<input type="submit"/>
		</form>
	</body>
	</html>`

	io.WriteString(w, html)
}
