package base64

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var plainText = "Hallo123"
var encodedText = "SGFsbG8xMjM="

func TestUrlEncodeBase64(t *testing.T) {

	actual := UrlEncodeToString(plainText)
	assert.Equal(t, encodedText, actual, "they should be equal")
}

func TestUrlDecodeBase64(t *testing.T) {

	actual, err := UrlDecodeString(encodedText)

	assert.NoError(t, err)
	assert.Equal(t, plainText, actual, "they should be equal")
}

func TestUrlDecodeBase64WithNotEncodedString(t *testing.T) {
	actual, err := UrlDecodeString("not a base64 encoded string")
	assert.Error(t, err)
	assert.Equal(t, "", actual, "they should be equal")
}
