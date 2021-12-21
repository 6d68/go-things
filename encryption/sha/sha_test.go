package sha

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"testing"
)

func TestSha(t *testing.T) {

	f, err := os.Open("sample.txt")
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		log.Fatalln("couldn't io.copy")
	}

	xb := h.Sum(nil)

	fmt.Printf("%T\n", h)
	fmt.Printf("%x\n", xb)
}
