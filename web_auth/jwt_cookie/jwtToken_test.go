package main

import (
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCreateToken(t *testing.T) {

	sid := "session-id-1"
	tokenString, err := createToken(sid)
	assert.NoError(t, err)

	token, err := jwt.ParseWithClaims(tokenString, &userClaims{}, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})

	claims := token.Claims.(*userClaims)
	nowPlus5Min := time.Now().Add(5 * time.Minute).Unix()

	assert.Equal(t, sid, claims.SID)
	assert.LessOrEqual(t, claims.ExpiresAt, nowPlus5Min)
	assert.NoError(t, claims.Valid())

}

func TestParseTokenFailsWithInvalidSignature(t *testing.T) {

	tokenSignedWithInvalidKey := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJTSUQiOiJteS1zZXNzaW9uIn0.qbhWTzfZMu63DcWc3zNXM83KPXiWuUyR7eBySGM1Tj4IzScAPHuEDCwrwPxgzTT_sCOLMM8gHMlbyfoPf9oWqQ"
	token, err := parseToken(tokenSignedWithInvalidKey)

	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestParseTokenExtractsSessionIdFromCustomClaims(t *testing.T) {
	sid := "session-id-1"
	tokenString, err := createToken(sid)
	s, err := parseToken(tokenString)

	assert.NoError(t, err)
	assert.Equal(t, sid, s)
}

func TestParseTokenFailsIfSigningAlgoDiffersFromHS512(t *testing.T) {

	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJTSUQiOiJteS1zZXNzaW9uIn0.LiwqxtrIN8XFa-KQsIjjXMlQhXXMlTXDbSi1B6CqkJ0"
	s, err := parseToken(tokenString)

	assert.Error(t, err)
	assert.Empty(t, s)
}

func TestParseTokenFailsIfTokenIsExpired(t *testing.T) {

	tokenString := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJTSUQiOiJteS1zZXNzaW9uIiwiZXhwIjoxNjA4OTM3MjAwfQ.N-IlkWgLzJzdKS_3qwJb_vNV8P6O-r5DFQgd96xHl9KoeYxZJLm78v05ZWTz3TVjiTgj7h8Xccl4BLMrcyPzPw"
	s, err := parseToken(tokenString)

	assert.Error(t, err)
	assert.Empty(t, s)
}

func TestParseTokenFailsIfTokenUsesCorruptSignature(t *testing.T) {

	tokenString := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJTSUQiOiJteS1zZXNzaW9uIiwiZXhwIjoxNjA4OTM3MjAwfQ.N-IlkWgLzJzdKS_3qwJb_vNV8P6O-r5DFQgd96xHl9KoeYxZJLm78v05ZWTz3TVjiTgj7h8Xccl4BLMrcyPzPwCORRUPT"
	s, err := parseToken(tokenString)

	assert.Error(t, err)
	assert.Empty(t, s)
}
