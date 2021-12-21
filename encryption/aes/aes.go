package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"io"
)

func EncryptWriter(w io.Writer, key string) (io.Writer, error) {

	// create randomized initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	_, err := w.Write(iv)
	if err != nil {
		return nil, errors.New("couldn't write initialization vector")
	}

	b, err := newCipherWithKey(key)
	if err != nil {
		return nil, err
	}

	s := cipher.NewCTR(b, iv)

	return cipher.StreamWriter{
		S: s,
		W: w,
	}, nil
}

func EncryptReader(r io.Reader, key string) (io.Reader, error) {
	iv := make([]byte, aes.BlockSize)
	n, err := r.Read(iv)
	if err != nil || n != len(iv) {
		return nil, errors.New("could not read initial value")
	}

	b, err := newCipherWithKey(key)
	if err != nil {
		return nil, err
	}

	s := cipher.NewCTR(b, iv)
	return &cipher.StreamReader{
		S: s,
		R: r,
	}, nil
}

func newCipherWithKey(key string) (cipher.Block, error) {
	hash := md5.Sum([]byte(key))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	return block, nil
}
