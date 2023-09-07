package dialer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMakeHTTPClient(t *testing.T) {
	// Create a test server to simulate HTTP requests
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Initialize the Dialer
	d := Dialer{
		EnableLowLevelSockets: false,        // Set your desired configuration
		TLSPaddingEnabled:     false,        // Set your desired configuration
		TLSPaddingSize:        [2]int{0, 0}, // Set your desired padding size
		ProxyAddress:          "",           // Set your proxy address if needed
	}

	// Create an HTTP client using the MakeHTTPClient method
	client := d.MakeHTTPClient(testServer.Listener.Addr().String(), false)

	// Make an HTTP request using the client
	resp, err := client.Get(testServer.URL)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
}
