package server

import (
	"bufio"
	"io"
	"net/http"
)

// ParseHTTPHost parses the head of the first HTTP request on conn and returns
// a new, unread connection with metadata for virtual host muxing
func ParseHTTPHost(rd io.Reader) (string, error) {
	var request *http.Request
	var err error
	if request, err = http.ReadRequest(bufio.NewReader(rd)); err != nil {
		return "", err
	}

	// You probably don't need access to the request body and this makes the API
	// simpler by allowing you to call Free() optionally
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(request.Body)

	return request.Host, nil
}
