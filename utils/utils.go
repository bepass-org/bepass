// Package utils provides utility functions for the application.
package utils

import (
	"crypto/rand"
	"io"
)

var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-"

// ShortID generates a random short SessionID of the specified length.
func ShortID(length int) string {
	ll := len(chars)
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	} // generates len(b) random bytes
	for i := 0; i < length; i++ {
		b[i] = chars[int(b[i])%ll]
	}
	return string(b)
}

type BufferedReader struct {
	FirstPacketData []byte
	BufReader       io.Reader
	FirstTime       bool
}

func (r *BufferedReader) Read(p []byte) (int, error) {
	if r.FirstTime {
		r.FirstTime = false
		n := copy(p, r.FirstPacketData)
		return n, nil
	}
	return r.BufReader.Read(p)
}
