package bufferpool

import (
	"testing"
)

func TestBufferPool(t *testing.T) {
	// Create a new buffer pool with a size of 128 bytes
	pool := NewPool(128)

	// Get a buffer from the pool
	buf := pool.Get()

	// Check if the buffer length matches the expected size
	if len(buf) != 128 {
		t.Errorf("Expected buffer size of 128, but got %d", len(buf))
	}

	// Put the buffer back into the pool
	pool.Put(buf)

	// Ensure the pool is empty
	buf2 := pool.Get()
	if len(buf2) != 128 {
		t.Errorf("Expected buffer size of 128, but got %d", len(buf2))
	}
}
