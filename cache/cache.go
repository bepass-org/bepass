package cache

import (
	"sync"
	"time"
)

type cacheEntry struct {
	value     interface{}
	expiration time.Time
}

type Cache struct {
	data          map[string]cacheEntry
	defaultDuration time.Duration
	mutex         sync.RWMutex
}

func NewCache(defaultDuration time.Duration) *Cache {
	return &Cache{
		data:           make(map[string]cacheEntry),
		defaultDuration: defaultDuration,
	}
}

func (c *Cache) Set(key string, value interface{}, durations ...time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var duration time.Duration
	if len(durations) > 0 {
		duration = durations[0]
	} else {
		duration = c.defaultDuration
	}

	expiration := time.Now().Add(duration)
	c.data[key] = cacheEntry{
		value:     value,
		expiration: expiration,
	}
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, found := c.data[key]
	if !found {
		return nil, false
	}

	if entry.expiration.Before(time.Now()) {
		// Item has expired, remove it from cache
		c.mutex.Lock()
		delete(c.data, key)
		c.mutex.Unlock()
		return nil, false
	}

	return entry.value, true
}
