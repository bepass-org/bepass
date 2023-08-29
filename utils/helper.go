package utils

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

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
	endpoint := fmt.Sprintf("wss://%s/connect?host=%s&port=%s&net=%s", u.Host, dh, dp, network)
	return endpoint, nil
}
