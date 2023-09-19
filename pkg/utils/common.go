// Package utils provides utility functions for the application.
package utils

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
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

// WSEndpointHelper generates a WebSocket endpoint URL based on the workerAddress, rawDestAddress, and network.
func WSEndpointHelper(workerAddress, rawDestAddress, network, sessionID string) (string, error) {
	u, err := url.Parse(workerAddress)
	if err != nil {
		return "", err
	}
	dh, dp, err := net.SplitHostPort(rawDestAddress)
	if strings.Contains(dh, ":") {
		// its ipv6
		dh = "[" + dh + "]"
	}
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("wss://%s/connect?host=%s&port=%s&net=%s&session=%s", u.Host, dh, dp, network, sessionID)
	return endpoint, nil
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
