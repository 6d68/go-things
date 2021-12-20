package base64

import (
	"encoding/base64"
	"fmt"
)

func UrlEncodeToString(plain string) string {
	return base64.URLEncoding.EncodeToString([]byte(plain))
}

func UrlDecodeString(encoded string) (string, error) {
	b, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("couldn't decode string %w", err)
	}

	return string(b), err
}
