package agent

import (
	"context"
	"fmt"
	"sync"
)

// GenerationQueue serializes reconciliation. Enqueue coalesces queued work to
// the greatest desired generation; no two Handler calls can overlap.
type GenerationQueue struct {
	mu        sync.Mutex
	pending   int64
	running   int64
	wake      chan struct{}
	handle    func(context.Context, int64) error
	onError   func(int64, error)
	telemetry *Telemetry
}

func NewGenerationQueue(handle func(context.Context, int64) error, onError func(int64, error), telemetry ...*Telemetry) *GenerationQueue {
	var observed *Telemetry
	if len(telemetry) > 0 {
		observed = telemetry[0]
	}
	return &GenerationQueue{pending: -1, running: -1, wake: make(chan struct{}, 1), handle: handle, onError: onError, telemetry: observed}
}

func (q *GenerationQueue) Enqueue(generation int64) error {
	if generation < 0 {
		return fmt.Errorf("generation must not be negative")
	}
	q.mu.Lock()
	if q.running >= 0 && generation <= q.running {
		if q.telemetry != nil {
			q.telemetry.Metrics.ObserveCoalesced()
		}
		q.mu.Unlock()
		return nil
	}
	if q.pending >= 0 {
		if q.telemetry != nil {
			q.telemetry.Metrics.ObserveCoalesced()
		}
	}
	if generation > q.pending {
		q.pending = generation
	}
	// Generation zero is the valid empty/bootstrap generation, so wake even
	// when max(pending) remains zero.
	shouldWake := q.running < 0
	q.mu.Unlock()
	if shouldWake {
		select {
		case q.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (q *GenerationQueue) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-q.wake:
		}
		for {
			q.mu.Lock()
			generation := q.pending
			q.pending = -1
			q.running = generation
			q.mu.Unlock()
			if q.telemetry != nil {
				q.telemetry.Log(ctx, "info", "queue_generation_started", map[string]any{"generation": generation, "state": "running"})
			}

			err := q.handle(ctx, generation)
			if q.telemetry != nil {
				outcome := "success"
				if err != nil {
					outcome = "failure"
				}
				q.telemetry.Log(ctx, map[bool]string{true: "error", false: "info"}[err != nil], "queue_generation_completed", map[string]any{"generation": generation, "outcome": outcome})
			}
			if err != nil && q.onError != nil {
				q.onError(generation, err)
			}

			q.mu.Lock()
			q.running = -1
			hasPending := q.pending >= 0
			q.mu.Unlock()
			if !hasPending {
				break
			}
		}
	}
}

func (q *GenerationQueue) State() (running, pending int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.running, q.pending
}
