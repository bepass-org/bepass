package cache

import (
	"github.com/uoosef/bepass/config"
	"time"
)

var c *Cache

func init() {
	if c == nil {
		c = NewCache(time.Duration(config.Dns.Ttl) * time.Second)
	}
}

func Set(key string, value interface{}) {
	c.Set(key, value)
}

func Get(key string) (interface{}, bool) {
	return c.Get(key)
}
