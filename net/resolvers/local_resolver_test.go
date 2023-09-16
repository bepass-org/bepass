// local_resolver_test.go

package resolvers

import (
	"testing"
)

func TestLocalResolver_Resolve_HostsFile(t *testing.T) {
	// Create a LocalResolver instance with mock host entries
	mockHosts := []Hosts{
		{Domain: "example.com", IP: "192.168.1.1"},
		{Domain: "test.com", IP: "10.0.0.1"},
	}
	localResolver := &LocalResolver{Hosts: mockHosts}

	// Test resolving a domain that exists in the local hosts file
	domain := "example.com"
	expectedIP := "192.168.1.1"
	result := localResolver.Resolve(domain)

	if result != expectedIP {
		t.Errorf("Expected IP: %s, Got: %s", expectedIP, result)
	}

	// Test resolving a domain that does not exist in the local hosts file
	domain = "nonexistent.com"
	result = localResolver.Resolve(domain)

	if result != "" {
		t.Errorf("Expected an empty string, Got: %s", result)
	}
}
