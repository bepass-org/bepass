// Package sni provides functionality for parsing the first HTTP request on a connection
// and returning metadata for virtual host muxing.
package sni

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
)

// ParseHTTPHost parses the head of the first HTTP request on conn and returns
// a new, unread connection with metadata for virtual host muxing
func ParseHTTPHost(rd io.Reader) (string, []byte, error) {
	var request *http.Request
	var err error
	if request, err = http.ReadRequest(bufio.NewReader(rd)); err != nil {
		return "", nil, err
	}

	// You probably don't need access to the request body and this makes the API
	// simpler by allowing you to call Free() optionally
	defer func() {
		_ = request.Body.Close()
	}()

	if request.Host == "" {
		return "", nil, errors.New("host not found")
	}
	host := request.Host

	var buff bytes.Buffer
	request.Write(&buff)
	b := bytes.Replace(buff.Bytes(), []byte("Host:"), []byte("hOSt:"), -1)
	return host, b, nil
}
