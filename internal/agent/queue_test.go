package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGenerationQueueSerializesAndCoalescesPendingMax(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	done := make(chan struct{})
	var concurrent atomic.Int32
	var maximum atomic.Int32
	var mu sync.Mutex
	var generations []int64
	queue := NewGenerationQueue(func(_ context.Context, generation int64) error {
		current := concurrent.Add(1)
		defer concurrent.Add(-1)
		if current > maximum.Load() {
			maximum.Store(current)
		}
		mu.Lock()
		generations = append(generations, generation)
		mu.Unlock()
		if generation == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		if generation == 3 {
			close(done)
		}
		return nil
	}, nil)
	go queue.Run(ctx)
	if err := queue.Enqueue(1); err != nil {
		t.Fatal(err)
	}
	<-firstStarted
	for _, generation := range []int64{2, 3, 2, 1} {
		if err := queue.Enqueue(generation); err != nil {
			t.Fatal(err)
		}
	}
	close(releaseFirst)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("queue did not process coalesced generation")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(generations) != 2 || generations[0] != 1 || generations[1] != 3 {
		t.Fatalf("generations = %v, want [1 3]", generations)
	}
	if maximum.Load() != 1 {
		t.Fatalf("maximum concurrent handlers = %d", maximum.Load())
	}
}

func TestGenerationQueueRejectsNegativeGeneration(t *testing.T) {
	queue := NewGenerationQueue(func(context.Context, int64) error { return nil }, nil)
	if err := queue.Enqueue(-1); err == nil {
		t.Fatal("negative generation was accepted")
	}
}
