package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

func EncodeOrDecode(key []byte, input string) ([]byte, error) {
	w := &bytes.Buffer{}
	encryptWriter, err := EncryptWriter(w, key)
	if err != nil {
		return nil, err
	}

	_, err = io.WriteString(encryptWriter, input)
	if err != nil {
		return nil, fmt.Errorf("couldn't sw.Write to stream write %w", err)
	}

	return w.Bytes(), nil
}

func EncryptWriter(w io.Writer, key []byte) (io.Writer, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("couldn't NewCipher %w", err)
	}

	// initialization header
	iv := make([]byte, aes.BlockSize)
	s := cipher.NewCTR(b, iv)

	return cipher.StreamWriter{
		S: s,
		W: w,
	}, nil
}
