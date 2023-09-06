// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package lru contains a typed Least-Recently-Used cache.
package lru

// Cache is container type keyed by K, storing V, optionally evicting the least
// recently used items if a maximum size is exceeded.
//
// The zero value is valid to use.
//
// It is not safe for concurrent access.
//
// The current implementation is just the traditional LRU linked list; a future
// implementation may be more advanced to avoid pathological cases.
type Cache[K comparable, V any] struct {
	// MaxEntries is the maximum number of cache entries before
	// an item is evicted. Zero means no limit.
	MaxEntries int

	// l is a ring of LRU values. l points to the most recently used
	// element, l.prev is the least recently used.
	//
	// An LRU is technically a simple list rather than a ring, but
	// implementing it as a ring makes the list manipulation
	// operations more regular, because the first/last positions in
	// the list stop being special.
	l *entry[K, V]
	m map[K]*entry[K, V]
}

// entry is an entry of Cache.
type entry[K comparable, V any] struct {
	prev, next *entry[K, V]
	key        K
	value      V
}

// Set adds or replaces a value to the cache, set or updating its associated
// value.
//
// If MaxEntries is non-zero and the length of the cache is greater
// after any addition, the least recently used value is evicted.
func (c *Cache[K, V]) Set(key K, value V) {
	if c.m == nil {
		c.m = make(map[K]*entry[K, V])
	}
	if ent, ok := c.m[key]; ok {
		c.moveToFront(ent)
		ent.value = value
		return
	}
	ent := c.newAtFront(key, value)
	c.m[key] = ent
	if c.MaxEntries != 0 && c.Len() > c.MaxEntries {
		c.deleteOldest()
	}
}

// Get looks up a key's value from the cache, returning either
// the value or the zero value if it not present.
//
// If found, key is moved to the front of the LRU.
func (c *Cache[K, V]) Get(key K) V {
	v, _ := c.GetOk(key)
	return v
}

// Contains reports whether c contains key.
//
// If found, key is moved to the front of the LRU.
func (c *Cache[K, V]) Contains(key K) bool {
	_, ok := c.GetOk(key)
	return ok
}

// GetOk looks up a key's value from the cache, also reporting
// whether it was present.
//
// If found, key is moved to the front of the LRU.
func (c *Cache[K, V]) GetOk(key K) (value V, ok bool) {
	if ent, hit := c.m[key]; hit {
		c.moveToFront(ent)
		return ent.value, true
	}
	var zero V
	return zero, false
}

// PeekOk looks up the key's value from the cache, also reporting
// whether it was present.
//
// Unlike GetOk, PeekOk does not move key to the front of the
// LRU. This should mostly be used for non-intrusive debug inspection
// of the cache.
func (c *Cache[K, V]) PeekOk(key K) (value V, ok bool) {
	if ent, hit := c.m[key]; hit {
		return ent.value, true
	}
	var zero V
	return zero, false
}

// Delete removes the provided key from the cache if it was present.
func (c *Cache[K, V]) Delete(key K) {
	if ent, ok := c.m[key]; ok {
		c.deleteElement(ent)
	}
}

// DeleteOldest removes the item from the cache that was least recently
// accessed. It is a no-op if the cache is empty.
func (c *Cache[K, V]) DeleteOldest() {
	if c.l != nil {
		c.deleteOldest()
	}
}

// Len returns the number of items in the cache.
func (c *Cache[K, V]) Len() int { return len(c.m) }

// newAtFront creates a new LRU entry using key and value, and inserts
// it at the front of c.l.
func (c *Cache[K, V]) newAtFront(key K, value V) *entry[K, V] {
	ret := &entry[K, V]{key: key, value: value}
	if c.l == nil {
		ret.prev = ret
		ret.next = ret
	} else {
		ret.next = c.l
		ret.prev = c.l.prev
		c.l.prev.next = ret
		c.l.prev = ret
	}
	c.l = ret
	return ret
}

// moveToFront moves ent, which must be an element of c.l, to the
// front of c.l.
func (c *Cache[K, V]) moveToFront(ent *entry[K, V]) {
	if c.l == ent {
		return
	}
	ent.prev.next = ent.next
	ent.next.prev = ent.prev
	ent.prev = c.l.prev
	ent.next = c.l
	c.l.prev.next = ent
	c.l.prev = ent
	c.l = ent
}

// deleteOldest removes the oldest entry in the cache. Panics if there
// are no entries in the cache.
func (c *Cache[K, V]) deleteOldest() { c.deleteElement(c.l.prev) }

// deleteElement removes ent, which must be an element of c.l, from
// the cache.
func (c *Cache[K, V]) deleteElement(ent *entry[K, V]) {
	if ent.next == ent {
		c.l = nil
	} else {
		ent.next.prev = ent.prev
		ent.prev.next = ent.next
	}
	delete(c.m, ent.key)
}
