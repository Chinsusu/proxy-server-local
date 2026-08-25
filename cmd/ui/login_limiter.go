package main

import (
	"net/netip"
	"sync"
	"time"
)

const (
	defaultLoginLimitEntries  = 4096
	defaultLoginLimitAttempts = 10
	defaultLoginLimitWindow   = 5 * time.Minute
)

type loginLimitEntry struct {
	windowStart time.Time
	lastSeen    time.Time
	attempts    int
}

// loginRateLimiter is deliberately bounded. It tracks canonical network
// addresses, never credentials, and evicts the least-recently-seen entry once
// it reaches capacity so unauthenticated traffic cannot grow process memory.
type loginRateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]loginLimitEntry
	maximum int
	limit   int
	window  time.Duration
}

func newLoginRateLimiter(maximum, limit int, window time.Duration) *loginRateLimiter {
	return &loginRateLimiter{now: time.Now, entries: make(map[string]loginLimitEntry), maximum: maximum, limit: limit, window: window}
}

func (limiter *loginRateLimiter) allow(address netip.Addr) (bool, time.Duration) {
	canonical := address.Unmap().String()
	now := limiter.now()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	entry, exists := limiter.entries[canonical]
	if !exists {
		if len(limiter.entries) >= limiter.maximum {
			limiter.evictOldest()
		}
		entry = loginLimitEntry{windowStart: now}
	}
	if now.Sub(entry.windowStart) >= limiter.window || now.Before(entry.windowStart) {
		entry.windowStart, entry.attempts = now, 0
	}
	entry.lastSeen = now
	if entry.attempts >= limiter.limit {
		limiter.entries[canonical] = entry
		retry := limiter.window - now.Sub(entry.windowStart)
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	entry.attempts++
	limiter.entries[canonical] = entry
	return true, 0
}

func (limiter *loginRateLimiter) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range limiter.entries {
		if oldestKey == "" || entry.lastSeen.Before(oldest) {
			oldestKey, oldest = key, entry.lastSeen
		}
	}
	if oldestKey != "" {
		delete(limiter.entries, oldestKey)
	}
}
