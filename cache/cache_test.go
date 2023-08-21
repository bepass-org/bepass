package cache

import (
	"testing"
	"time"
)

func TestCache_SetAndGet(t *testing.T) {
	testCases := []struct {
		name     string
		duration time.Duration
	}{
		{"DefaultDuration", 10 * time.Second},
		{"CustomDuration", 5 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cache := NewCache(tc.duration)

			cache.Set("key1", "value1")
			cache.Set("key2", "value2", 5*time.Second)

			value1, exists1 := cache.Get("key1")
			if !exists1 || value1 != "value1" {
				t.Errorf("Expected 'value1' to exist in cache with key 'key1', but got value: %v", value1)
			}

			value2, exists2 := cache.Get("key2")
			if !exists2 || value2 != "value2" {
				t.Errorf("Expected 'value2' to exist in cache with key 'key2', but got value: %v", value2)
			}

			value3, exists3 := cache.Get("nonexistent_key")
			if exists3 || value3 != nil {
				t.Errorf("Expected 'nonexistent_key' to not exist in cache, but got value: %v", value3)
			}

			// Wait for the shorter cache entry to expire
			time.Sleep(6 * time.Second)

			value2AfterExpiry, exists2AfterExpiry := cache.Get("key2")
			if exists2AfterExpiry || value2AfterExpiry != nil {
				t.Errorf("Expected 'key2' to have expired and not exist in cache, but got value: %v", value2AfterExpiry)
			}
		})
	}
}