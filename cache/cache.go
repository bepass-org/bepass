// Package cache is a thread-safe in-memory cache implementation with expiration support.
// It allows you to store key-value pairs with optional expiration times.
//
// Usage:
//
//	// Create a new cache with a 10-minute default expiration time.
//	myCache := NewCache(10 * time.Minute)
//
//	// Store a value with a key and an optional expiration duration.
//	myCache.Set("myKey", myValue)
//
//	// Retrieve a value from the cache. Returns the value and true if found, or nil and false if not found.
//	value, found := myCache.Get("myKey")
//
//	// Check if a key exists in the cache.
//	if found {
//	    // Value exists in the cache.
//	    fmt.Println(value)
//	} else {
//	    // Value not found in the cache.
//	    fmt.Println("Key not found")
//	}
package cache

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Item represents an item in the cache.
type Item struct {
	Object     interface{}
	Expiration int64
}

// Expired returns true if the item has expired.
func (item Item) Expired() bool {
	if item.Expiration == 0 {
		return false
	}
	return time.Now().UnixNano() > item.Expiration
}

type Cache struct {
	*cache
}

type cache struct {
	expiration time.Duration
	items      map[string]Item
	mu         sync.RWMutex
	onExpired  func()
	janitor    *janitor
}

// Set add an item to the cache, replacing any existing item.
func (c *cache) Set(k string, x interface{}) {
	// "Inlining" of set
	var e = time.Now().Add(c.expiration).UnixNano()

	c.mu.Lock()
	c.items[k] = Item{
		Object:     x,
		Expiration: e,
	}
	// TODO: Calls to mu.Unlock are currently not deferred because defer
	// adds ~200 ns (as of go1.)
	c.mu.Unlock()
}

func (c *cache) set(k string, x interface{}) {
	var e = time.Now().Add(c.expiration).UnixNano()
	c.items[k] = Item{
		Object:     x,
		Expiration: e,
	}
}

// Replace set a new value for the cache key only if it already exists. Returns an error otherwise.
func (c *cache) Replace(k string, x interface{}) error {
	c.mu.Lock()
	_, found := c.get(k)
	if !found {
		c.mu.Unlock()
		return fmt.Errorf("item %s doesn't exist", k)
	}
	c.set(k, x)
	c.mu.Unlock()
	return nil
}

// Get an item from the cache. Returns the item or nil, and a bool indicating
// whether the key was found.
func (c *cache) Get(k string) (interface{}, bool) {
	c.mu.RLock()
	item, found := c.items[k]
	if !found {
		c.mu.RUnlock()
		return nil, false
	}
	c.mu.RUnlock()
	return item.Object, true
}

func (c *cache) get(k string) (interface{}, bool) {
	item, found := c.items[k]
	if !found {
		return nil, false
	}
	return item.Object, true
}

// GetAll returns all keys in the cache or empty map.
func (c *cache) GetAll() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var items map[string]interface{}

	if c.ItemCount() > 0 {
		items = make(map[string]interface{}, len(c.items))
		for k, v := range c.items {
			items[k] = v.Object
		}
	}

	return items
}

// Delete an item from the cache. Does nothing if the key is not in the cache.
func (c *cache) Delete(k string) {
	c.mu.Lock()
	delete(c.items, k)
	c.mu.Unlock()
}

// DeleteExpired Delete all expired items from the cache.
func (c *cache) DeleteExpired() {
	now := time.Now().UnixNano()
	c.mu.Lock()
	for k, v := range c.items {
		if v.Expiration > 0 && now > v.Expiration {
			delete(c.items, k)
		}
	}
	c.mu.Unlock()
}

type keyAndValue struct {
	key   string
	value interface{}
}

// OnExpired sets an (optional) function that is called when the cache expires
func (c *cache) OnExpired(f func()) {
	c.onExpired = f
}

// ItemCount Returns the number of items in the cache, including expired items.
func (c *cache) ItemCount() int {
	c.mu.RLock()
	n := len(c.items)
	c.mu.RUnlock()
	return n
}

// Flush Delete all items from the cache.
func (c *cache) Flush() {
	c.mu.Lock()
	c.items = map[string]Item{}
	c.mu.Unlock()
}

type janitor struct {
	Interval time.Duration
	stop     chan bool
}

// handleExpired is fired by the ticker and executes the onExpired function.
func (c *cache) handleExpired() {
	if c.onExpired != nil {
		c.onExpired()
	}
}

func (j *janitor) Run(c *cache) {
	ticker := time.NewTicker(j.Interval)
	for {
		select {
		case <-ticker.C:
			c.handleExpired()
		case <-j.stop:
			ticker.Stop()
			return
		}
	}
}

func stopJanitor(c *Cache) {
	c.janitor.stop <- true
}

func runJanitor(c *cache, ex time.Duration) {
	j := &janitor{
		Interval: ex,
		stop:     make(chan bool, 1),
	}
	c.janitor = j
	go j.Run(c)
}

func newCache(ex time.Duration, m map[string]Item) *cache {
	if ex <= 0 {
		ex = -1
	}
	c := &cache{
		expiration: ex,
		items:      m,
	}
	return c
}

func newCacheWithJanitor(ex time.Duration, m map[string]Item) *Cache {
	c := newCache(ex, m)
	// This trick ensures that the janitor goroutine (which--granted it
	// was enabled--is running DeleteExpired on c forever) does not keep
	// the returned C object from being garbage collected. When it is
	// garbage collected, the finalizer stops the janitor goroutine, after
	// which c can be collected.
	C := &Cache{c}
	if ex > 0 {
		runJanitor(c, ex)
		runtime.SetFinalizer(C, stopJanitor)
	}
	return C
}

// NewCache return a new cache with a given expiration duration. If the
// expiration duration is less than 1 (i.e. No Expiration),
// the items in the cache never expire (by default), and must be deleted
// manually. The OnExpired callback method is ignored, too.
func NewCache(expiration time.Duration) *Cache {
	items := make(map[string]Item)
	return newCacheWithJanitor(expiration, items)
}
