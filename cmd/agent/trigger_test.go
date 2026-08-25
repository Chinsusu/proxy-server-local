package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixedTriggerAuthorizer bool

func (a fixedTriggerAuthorizer) Authorized(header string) bool {
	return bool(a) && header == "Bearer scoped-token"
}

func TestAgentReconcileTriggerRequiresAuthorizedPOSTWithoutBody(t *testing.T) {
	t.Parallel()
	gate := newReconcileTriggerGate(time.Second)
	handler := newAgentHandler(fixedTriggerAuthorizer(true), gate)

	tests := []struct {
		name   string
		method string
		token  string
		body   string
		want   int
	}{
		{name: "get rejected", method: http.MethodGet, token: "Bearer scoped-token", want: http.StatusMethodNotAllowed},
		{name: "missing token", method: http.MethodPost, want: http.StatusUnauthorized},
		{name: "wrong token", method: http.MethodPost, token: "Bearer wrong", want: http.StatusUnauthorized},
		{name: "body rejected", method: http.MethodPost, token: "Bearer scoped-token", body: "x", want: http.StatusRequestEntityTooLarge},
		{name: "accepted", method: http.MethodPost, token: "Bearer scoped-token", want: http.StatusAccepted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/agent/reconcile", strings.NewReader(test.body))
			if test.token != "" {
				request.Header.Set("Authorization", test.token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestAgentReconcileTriggerFloodCoalescesBeforeFetchLatest(t *testing.T) {
	gate := newReconcileTriggerGate(0)
	handler := newAgentHandler(fixedTriggerAuthorizer(true), gate)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	go gate.Run(ctx, func(context.Context) error {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil
	}, nil)

	const requests = 64
	var workers sync.WaitGroup
	workers.Add(requests)
	for index := 0; index < requests; index++ {
		go func() {
			defer workers.Done()
			request := httptest.NewRequest(http.MethodPost, "/agent/reconcile", nil)
			request.Header.Set("Authorization", "Bearer scoped-token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusAccepted {
				t.Errorf("status = %d, want %d", response.Code, http.StatusAccepted)
			}
		}()
	}
	workers.Wait()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("FetchLatest was not started")
	}
	close(release)
	time.Sleep(50 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("FetchLatest calls = %d, want 1", got)
	}
}

func TestAgentHealthIsCheapAndMethodRestricted(t *testing.T) {
	t.Parallel()
	handler := newAgentHandler(fixedTriggerAuthorizer(false), newReconcileTriggerGate(time.Second))
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, "/agent/health", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d", method, response.Code)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/agent/health", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST health status = %d", response.Code)
	}
}

func TestAgentReconcileTriggerRateLimitsAuthorizedRequests(t *testing.T) {
	t.Parallel()
	handler := newAgentHandler(fixedTriggerAuthorizer(true), newReconcileTriggerGate(time.Minute))
	for attempt, want := range []int{http.StatusAccepted, http.StatusTooManyRequests} {
		request := httptest.NewRequest(http.MethodPost, "/agent/reconcile", nil)
		request.Header.Set("Authorization", "Bearer scoped-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("attempt %d status = %d, want %d", attempt+1, response.Code, want)
		}
	}
}
