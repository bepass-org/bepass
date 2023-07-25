package server

import (
	"testing"
)

func TestLengthFromData(t *testing.T) {
	server := Server{}

	tests := []struct {
		name     string
		data     []byte
		index    int
		expected int
	}{
		{
			name:     "ValidData",
			data:     []byte{0x00, 0x0A}, // Data with length 10
			index:    0,
			expected: 10,
		},
		{
			name:     "InvalidIndex",
			data:     []byte{0x00, 0x0A},
			index:    2, // Invalid index, should return 0
			expected: 0,
		},
		{
			name:     "MaxValue",
			data:     []byte{0xFF, 0xFF}, // Maximum value for two octets
			index:    0,
			expected: 65535,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := server.lengthFromData(test.data, test.index)
			if result != test.expected {
				t.Errorf("Expected %d, but got %d", test.expected, result)
			}
		})
	}
}
