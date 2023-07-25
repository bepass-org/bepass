package server

import (
	"fmt"
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

func TestGetSNBlock(t *testing.T) {
	server := Server{}

	tests := []struct {
		name          string
		data          []byte
		expectedBlock []byte
		expectedError error
	}{
		{
			name: "ValidSNBlock",
			data: []byte{
				0x00, 0x0D, // Extension length
				0x00, 0x04, // Block 1 length
				0x00, 0x00, // Block 1 type
				0x01, 0x02, // Block 1 data
				0x00, 0x05, // Block 2 length
				0x00, 0x00, // Block 2 type
				0x03, 0x04, // Block 2 data
			},
			expectedBlock: []byte{0x01, 0x02},
			expectedError: nil,
		},
		{
			name: "InvalidExtensionSize",
			data: []byte{
				0x00, 0x04, // Extension length (less than required)
				0x00, 0x02, // Block 1 length
				0x00, 0x00, // Block 1 type
				0x01, 0x02, // Block 1 data
			},
			expectedBlock: nil,
			expectedError: fmt.Errorf("finished parsing the Extension block without finding an SN block"),
		},
		{
			name: "SNBlockNotFound",
			data: []byte{
				0x00, 0x08, // Extension length
				0x00, 0x04, // Block 1 length
				0x00, 0x01, // Block 1 type
				0x01, 0x02, // Block 1 data
				0x00, 0x04, // Block 2 length
				0x00, 0x02, // Block 2 type
				0x03, 0x04, // Block 2 data
			},
			expectedBlock: nil,
			expectedError: fmt.Errorf("finished parsing the Extension block without finding an SN block"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := server.getSNBlock(test.data)
			if err != nil {
				if test.expectedError == nil {
					t.Errorf("Unexpected error: %v", err)
				} else if err.Error() != test.expectedError.Error() {
					t.Errorf("Expected error: %v, but got: %v", test.expectedError, err)
				}
			} else {
				if string(result) != string(test.expectedBlock) {
					t.Errorf("Expected block %v, but got %v", test.expectedBlock, result)
				}
			}
		})
	}
}
