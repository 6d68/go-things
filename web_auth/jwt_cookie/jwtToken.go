/*
Basic abstraction over JWT token generation and validation specifically
for this example web app to maintain sessions using cookies.

Disclaimer

Code is not production ready. Many things would still have to be improved.
Current status served only for learning purposes.

*/
package main

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"time"
)

var key = []byte("secret")

type userClaims struct {
	jwt.StandardClaims
	SID string
}

func createToken(sid string) (string, error) {
	claims := &userClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
		SID: sid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	signedString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("unable to sign token")
	}

	return signedString, nil
}

func parseToken(tokenString string) (string, error) {
	t, err := jwt.ParseWithClaims(tokenString, &userClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, errors.New("wrong signing alg detected")
		}
		return key, nil
	})

	if claims, ok := t.Claims.(*userClaims); ok && t.Valid {
		return claims.SID, nil
	}

	return "", fmt.Errorf("token not valid %w", err)
}
