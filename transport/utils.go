package transport

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
)

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
