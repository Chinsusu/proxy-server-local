package httpx

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginRateLimiterReserveIsAtomicPerClient(t *testing.T) {
	limiter := NewLoginRateLimiter(2, time.Minute)
	firstRelease, admitted, limited := limiter.Reserve("198.51.100.10")
	if !admitted || limited || firstRelease == nil {
		t.Fatalf("first reservation admitted=%v limited=%v", admitted, limited)
	}
	defer firstRelease()

	const contenders = 32
	var accepted atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if release, ok, isLimited := limiter.Reserve("198.51.100.10"); ok || isLimited || release != nil {
				if ok {
					release()
				}
				accepted.Add(1)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 0 {
		t.Fatalf("concurrent duplicate reservations=%d", accepted.Load())
	}
}

func TestLoginRateLimiterReservationReleasesAndLockoutWins(t *testing.T) {
	limiter := NewLoginRateLimiter(1, time.Minute)
	release, admitted, limited := limiter.Reserve("198.51.100.11")
	if !admitted || limited {
		t.Fatal("initial reservation refused")
	}
	release()
	release, admitted, limited = limiter.Reserve("198.51.100.11")
	if !admitted || limited {
		t.Fatal("released reservation was not available")
	}
	release()
	limiter.RecordFailure("198.51.100.11")
	if release, admitted, limited := limiter.Reserve("198.51.100.11"); admitted || !limited || release != nil {
		t.Fatalf("lockout reservation admitted=%v limited=%v release=%v", admitted, limited, release != nil)
	}
}
