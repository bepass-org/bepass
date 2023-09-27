package config

import (
	"fmt"
	"github.com/uoosef/bepass/internal/logger"
	"net"
	"time"
)

var (
	availableFragmentModes = []string{
		// weak|strong|aggressive|adaptive|advanced
		"weak",
		"strong",
		"aggressive",
		"adaptive",
		"advanced",
	}
	availableTLSFingerPrints = []string{
		// chrome|edge|firefox|safari|ios|android|auto
		"chrome",
		"edge",
		"firefox",
		"safari",
		"ios",
		"android",
		"auto",
	}
	availableDNSStrategies = []string{
		// direct|proxy
		"direct",
		"proxy",
	}
	availableDNSPrefer = []string{
		// ipv4|ipv6|auto
		"ipv4",
		"ipv6",
		"auto",
	}
	availableDNSTypes = []string{
		// udp|tcp|dot|doh|crypt|system
		"udp",
		"tcp",
		"dot",
		"doh",
		"crypt",
		"system",
	}
	availableWorkerConnectionTypes = []string{
		"scanner",
		"random",
	}
)

// validateConfig validates the config that user provided it checks if user inputs are actually making any sense
// and if some parts of config doesn't exist it will fill it with default values
func validateConfig() {
	// Check if the provided address is available
	if isPortAvailable(Server.Bind) {
		logger.Infof("%s is free and available", Server.Bind)
	} else {
		// If not available, find an available port and bind to 0.0.0.0
		port, err := findAvailablePort()
		if err != nil {
			fmt.Println("Error finding available port:", err)
			return
		}
		bindAddress := fmt.Sprintf("0.0.0.0:%s", port)
		logger.Errorf("%s is not available. Listening on %s instead.", Server.Bind, bindAddress)
		Server.Bind = bindAddress
	}
	// check if tls padding is enabled and provided range is valid
	if Tls.Padding.Enabled && Tls.Padding.LengthRange[0] > Tls.Padding.LengthRange[1] {
		Tls.Padding.LengthRange[0], Tls.Padding.LengthRange[1] = Tls.Padding.LengthRange[1], Tls.Padding.LengthRange[0]
	}
	// check if provided tls fingerprint is valid
	if Tls.Fingerprint != "" && !checkTLSFingerPrint(Tls.Fingerprint) {
		Tls.Fingerprint = "auto"
		logger.Warn("invalid tls fingerprint, set to default tls fingerprint: `auto`")
	}
	// check if provided fragment delay is valid
	if Fragment.Enable && Fragment.Delay[0] > Fragment.Delay[1] {
		Fragment.Delay[0], Fragment.Delay[1] = Fragment.Delay[1], Fragment.Delay[0]
	}
	// check if provided fragment mode is valid
	if Fragment.Enable && !checkFragmentMode(Fragment.Mode) {
		// set it to default fragment mode
		Fragment.Mode = "weak"
		logger.Warn("invalid fragment mode, set to default fragment mode: `weak`")
	}
	if Fragment.Enable && Fragment.Mode == "advanced" {
		if Fragment.Advanced.Bsl[0] > Fragment.Advanced.Bsl[1] {
			Fragment.Advanced.Bsl[0], Fragment.Advanced.Bsl[1] = Fragment.Advanced.Bsl[1], Fragment.Advanced.Bsl[0]
		}
		if Fragment.Advanced.Sl[0] > Fragment.Advanced.Sl[1] {
			Fragment.Advanced.Sl[0], Fragment.Advanced.Sl[1] = Fragment.Advanced.Sl[1], Fragment.Advanced.Sl[0]
		}
		if Fragment.Advanced.Asl[0] > Fragment.Advanced.Asl[1] {
			Fragment.Advanced.Asl[0], Fragment.Advanced.Asl[1] = Fragment.Advanced.Asl[1], Fragment.Advanced.Asl[0]
		}
	}
	// check if provided dns strategy is valid
	if !checkDNSStrategy(Dns.Strategy) {
		// set it to default dns strategy
		Dns.Strategy = "direct"
		logger.Warn("invalid dns strategy, set to default dns strategy: `direct`")
	}
	if Dns.Strategy == "proxy" && !Worker.Enable {
		Dns.Strategy = "direct"
		logger.Warn("dns strategy `proxy` requires worker, set to default dns strategy: `direct`")
	}
	// check if provided dns prefer is valid
	if !checkDNSPrefer(Dns.Prefer) {
		// set it to default dns prefer
		Dns.Prefer = "auto"
		logger.Warn("invalid dns prefer, set to default dns prefer: `auto`")
	}
	// check if provided dns type is valid
	if !checkDNSType(Dns.Type) {
		// set it to default dns type
		Dns.Type = "system"
		logger.Warn("invalid dns type, set to default dns type: `system`")
	}
	// check if provided worker connection type is valid
	if Worker.Enable && !checkWorkerConnectionType(Worker.Connection.Type) {
		// set it to default worker connection type
		Worker.Connection.Type = "scanner"
		logger.Warn("invalid worker connection type, set to default worker connection type: `scanner`")
	}
}

func findAvailablePort() (string, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", err
	}
	defer listener.Close()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return "", err
	}

	return portStr, nil
}

func isPortAvailable(address string) bool {
	// Validate address format
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}

	conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err != nil {
		return true // Unable to connect, port is likely available
	}
	defer conn.Close()
	return false
}

// check fragment mode is valid
func checkFragmentMode(mode string) bool {
	for _, m := range availableFragmentModes {
		if m == mode {
			return true
		}
	}
	return false
}

// check tls fingerprint is valid
func checkTLSFingerPrint(fingerprint string) bool {
	for _, m := range availableTLSFingerPrints {
		if m == fingerprint {
			return true
		}
	}
	return false
}

// check dns strategy is valid
func checkDNSStrategy(strategy string) bool {
	for _, m := range availableDNSStrategies {
		if m == strategy {
			return true
		}
	}
	return false
}

// check dns prefer is valid
func checkDNSPrefer(dnsPrefer string) bool {
	for _, m := range availableDNSPrefer {
		if m == dnsPrefer {
			return true
		}
	}
	return false
}

// check dns type is valid
func checkDNSType(dnsType string) bool {
	for _, m := range availableDNSTypes {
		if m == dnsType {
			return true
		}
	}
	return false
}

// check worker connection type is valid
func checkWorkerConnectionType(connectionType string) bool {
	for _, m := range availableWorkerConnectionTypes {
		if m == connectionType {
			return true
		}
	}
	return false
}
