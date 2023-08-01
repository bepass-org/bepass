package cache

import (
	"sync"
	"time"
)

type Cache struct {
	data     map[string]interface{}
	duration time.Duration
	mutex    sync.RWMutex
}

func NewCache(duration time.Duration) *Cache {
	return &Cache{
		data:     make(map[string]interface{}),
		duration: duration,
	}
}

func (c *Cache) Set(key string, value interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.data[key] = value
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	val, found := c.data[key]
	return val, found
}
