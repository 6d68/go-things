package aes

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"testing"
)

var pass = "super-secret"
var msg = "My message to encrypt/de-crypt"

func TestEncryptDecryptWithWriter(t *testing.T) {

	key := newKeyWithPassword(pass)

	w := &bytes.Buffer{}
	encryptWriter, err := EncryptWriter(w, key)

	_, err = io.WriteString(encryptWriter, msg)
	encodedMsg := w.String()
	assert.NoError(t, err)
	assert.NotNil(t, encodedMsg)

	decodedMsg, err := EncodeOrDecode(key, encodedMsg)
	assert.NoError(t, err)
	assert.Equal(t, msg, string(decodedMsg))

}

func newKeyWithPassword(password string) []byte {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		log.Panic("couldn't bcrypt password")
	}

	key := b[:16]
	return key
}
