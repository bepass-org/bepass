// Package utils provides utility functions for the application.
package utils

import (
	"fmt"
	"github.com/bepass-org/bepass/config"
	"net"
	"net/url"
	"strings"
)

// WSEndpointHelper generates a WebSocket endpoint URL based on the workerAddress, rawDestAddress, and network.
func WSEndpointHelper(workerAddress, rawDestAddress, network string) (string, error) {
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
	endpoint := fmt.Sprintf("wss://%s/connect?host=%s&port=%s&net=%s&session=%s", u.Host, dh, dp, network, config.G.UserSession)
	return endpoint, nil
}
