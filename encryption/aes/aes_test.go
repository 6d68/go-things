package aes

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strings"
	"testing"
)

var pass = "super-secret"
var msg = "My message to encrypt/de-crypt"

func TestEncryptDecryptWithWriterAndReader(t *testing.T) {

	var sb strings.Builder
	w, err := EncryptWriter(&sb, pass)
	_, err = w.Write([]byte(msg))
	encodedMsg := sb.String()
	assert.NoError(t, err)
	assert.NotNil(t, encodedMsg)

	r, err := EncryptReader(strings.NewReader(encodedMsg), pass)
	decrypted, err := ioutil.ReadAll(r)
	assert.NoError(t, err)
	assert.Equal(t, msg, string(decrypted))
}
