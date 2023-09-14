// Package sni provides functionality for parsing the first HTTP request on a connection
package sni

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
)

// ParseHTTPHost parses the head of the first HTTP request on conn
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
	err = request.Write(&buff)
	if err != nil {
		return "", nil, err
	}
	b := bytes.Replace(buff.Bytes(), []byte("Host:"), []byte("hOSt:"), -1)
	return host, b, nil
}
