package httpx

import (
	"sync"
	"time"
)

// LoginRateLimiter provides per-IP rate limiting for login attempts.
type LoginRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*attemptInfo
	reserved map[string]bool
	maxFails int
	window   time.Duration
}

type attemptInfo struct {
	count   int
	firstAt time.Time
}

// NewLoginRateLimiter creates a rate limiter that locks out after maxFails
// failed attempts within the given window duration.
func NewLoginRateLimiter(maxFails int, window time.Duration) *LoginRateLimiter {
	rl := &LoginRateLimiter{
		attempts: make(map[string]*attemptInfo),
		reserved: make(map[string]bool),
		maxFails: maxFails,
		window:   window,
	}
	// background cleanup every window duration
	go func() {
		t := time.NewTicker(window)
		defer t.Stop()
		for range t.C {
			rl.cleanup()
		}
	}()
	return rl
}

// Reserve atomically admits one in-flight password verification for an IP.
// The release closure is safe to defer. limited distinguishes lockout (429)
// from an in-flight per-IP reservation (deterministic overload response).
func (rl *LoginRateLimiter) Reserve(ip string) (release func(), admitted, limited bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if info, ok := rl.attempts[ip]; ok && time.Since(info.firstAt) <= rl.window && info.count >= rl.maxFails {
		return nil, false, true
	}
	if rl.reserved[ip] {
		return nil, false, false
	}
	rl.reserved[ip] = true
	return func() { rl.mu.Lock(); delete(rl.reserved, ip); rl.mu.Unlock() }, true, false
}

// Allow checks if the given IP is allowed to attempt login.
// Returns true if allowed, false if rate-limited.
func (rl *LoginRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	info, ok := rl.attempts[ip]
	if !ok {
		return true
	}
	// reset if window expired
	if time.Since(info.firstAt) > rl.window {
		delete(rl.attempts, ip)
		return true
	}
	return info.count < rl.maxFails
}

// RecordFailure records a failed login attempt for the given IP.
func (rl *LoginRateLimiter) RecordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	info, ok := rl.attempts[ip]
	if !ok || time.Since(info.firstAt) > rl.window {
		rl.attempts[ip] = &attemptInfo{count: 1, firstAt: time.Now()}
		return
	}
	info.count++
}

// Reset clears the failure count for an IP (on successful login).
func (rl *LoginRateLimiter) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ip)
}

func (rl *LoginRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, info := range rl.attempts {
		if now.Sub(info.firstAt) > rl.window {
			delete(rl.attempts, ip)
		}
	}
}
