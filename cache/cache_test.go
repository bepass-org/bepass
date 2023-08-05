package cache

import (
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	defaultDuration := time.Second * 2
	cache := NewCache(defaultDuration)

	// Test Set and Get
	cache.Set("key1", "value1")
	value, found := cache.Get("key1")
	if !found || value != "value1" {
		t.Errorf("Expected 'value1', found '%v'", value)
	}

	// Test expiration
	time.Sleep(defaultDuration + time.Millisecond*500) // Wait for item to expire
	value, found = cache.Get("key1")
	if found || value != nil {
		t.Errorf("Expected cache miss, found '%v'", value)
	}

	// Test custom duration
	cache.Set("key2", "value2", time.Second*3)
	value, found = cache.Get("key2")
	if !found || value != "value2" {
		t.Errorf("Expected 'value2', found '%v'", value)
	}

	// Test cache eviction due to expiration
	time.Sleep(time.Second * 3) // Wait for item to expire
	value, found = cache.Get("key2")
	if found || value != nil {
		t.Errorf("Expected cache miss, found '%v'", value)
	}
}

func TestCacheWithDefaultDuration(t *testing.T) {
	defaultDuration := time.Second * 2
	cache := NewCache(defaultDuration)

	cache.Set("key1", "value1")
	value, found := cache.Get("key1")
	if !found || value != "value1" {
		t.Errorf("Expected 'value1', found '%v'", value)
	}

	time.Sleep(defaultDuration + time.Millisecond*500) // Wait for item to expire
	value, found = cache.Get("key1")
	if found || value != nil {
		t.Errorf("Expected cache miss, found '%v'", value)
	}
}
