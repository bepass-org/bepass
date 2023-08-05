package cache

import (
	"sync"
	"time"
)

// Cache represents a simple in-memory cache.
type Cache struct {
	data     map[string]cacheItem
	duration time.Duration
	mutex    sync.RWMutex
}

type cacheItem struct {
	value      interface{}
	expiration time.Time
}

// NewCache creates a new Cache instance.
func NewCache(duration time.Duration) *Cache {
	return &Cache{
		data:     make(map[string]cacheItem),
		duration: duration,
	}
}

// Set adds or updates a value in the cache with an optional duration.
func (c *Cache) Set(key string, value interface{}, durations ...time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var duration time.Duration
	if len(durations) > 0 {
		duration = durations[0]
	} else {
		duration = c.duration
	}

	expiration := time.Now().Add(duration)
	c.data[key] = cacheItem{value: value, expiration: expiration}
}

// Get retrieves a value from the cache and returns its existence status.
func (c *Cache) Get(key string) (value interface{}, exists bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	item, found := c.data[key]
	if !found || item.expiration.Before(time.Now()) {
		return nil, false
	}
	return item.value, true
}
