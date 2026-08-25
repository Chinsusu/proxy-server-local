package forwarder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

type Server struct {
	runtime  RuntimeConfig
	upstream upstream
	notifier Notifier
	creds    *credentialStore
	observer *observability.Observer
	metrics  *forwarderMetrics

	listener        net.Listener
	metricsListener net.Listener
	metricsServer   *http.Server
	sem             chan struct{}
	stopping        atomic.Bool
	active          atomic.Int64

	mu      sync.Mutex
	clients map[net.Conn]net.Conn
	wg      sync.WaitGroup
	stopOne sync.Once
}

func NewServer(runtime RuntimeConfig, credentials Credentials, notifier Notifier) (*Server, error) {
	return NewServerWithObserver(runtime, credentials, notifier, nil)
}

// NewServerWithObserver allows the process entrypoint to provide a shared,
// fixed-schema JSON observer. A discard observer keeps unit tests silent.
func NewServerWithObserver(runtime RuntimeConfig, credentials Credentials, notifier Notifier, observer *observability.Observer) (*Server, error) {
	if err := runtime.Config.Validate(); err != nil {
		credentials.Wipe()
		return nil, err
	}
	if runtime.DialTimeout <= 0 || runtime.IdleTimeout <= 0 || runtime.DrainTimeout <= 0 || runtime.DrainTimeout > 30*time.Second {
		credentials.Wipe()
		return nil, errors.New("forwarder runtime timeouts are invalid")
	}
	if err := validateCredentials(runtime.ProxyType, credentials); err != nil {
		credentials.Wipe()
		return nil, err
	}
	if runtime.MaxConnections == 0 {
		runtime.MaxConnections = 8192
	}
	if notifier == nil {
		notifier = NewSystemdNotifier()
	}
	if observer == nil {
		observer = observability.NewDiscard("pgw-fwd")
	}
	store := newCredentialStore(credentials)
	return &Server{
		runtime:  runtime,
		upstream: upstream{typeName: runtime.ProxyType, host: runtime.ProxyHost, port: runtime.ProxyPort, creds: store, timeout: runtime.DialTimeout},
		notifier: notifier,
		creds:    store,
		observer: observer,
		metrics:  newForwarderMetrics(runtime.ProxyType),
		sem:      make(chan struct{}, runtime.MaxConnections),
		clients:  make(map[net.Conn]net.Conn),
	}, nil
}

// Start establishes all readiness preconditions in their fail-closed order:
// config and credentials were validated by the caller, the adapter is selected
// by NewServer, then the transparent listener is bound, then READY=1 is sent.
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.runtime.ListenAddress)
	if err != nil {
		s.metrics.observe("readiness", "failure", "listener_bind")
		s.log("error", "forwarder_startup", "failure", "listener_bind")
		return fmt.Errorf("bind transparent listener: %w", err)
	}
	metricsAddress, err := metricsAddress(s.runtime.ListenAddress)
	if err != nil {
		_ = listener.Close()
		s.metrics.observe("readiness", "failure", "metrics_bind")
		s.log("error", "forwarder_startup", "failure", "metrics_bind")
		return err
	}
	metricsListener, err := observability.ListenLoopback(metricsAddress)
	if err != nil {
		_ = listener.Close()
		s.metrics.observe("readiness", "failure", "metrics_bind")
		s.log("error", "forwarder_startup", "failure", "metrics_bind")
		return fmt.Errorf("bind metrics listener: %w", err)
	}
	s.listener = listener
	s.metricsListener = metricsListener
	s.metricsServer = newMetricsHTTPServer(s.metrics)
	go func() {
		err := s.metricsServer.Serve(metricsListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.metrics.observe("readiness", "failure", "metrics_bind")
			s.log("error", "forwarder_metrics", "failure", "metrics_bind")
		}
	}()
	if err := s.notifier.Ready("pgw forwarder ready"); err != nil {
		_ = s.metricsServer.Close()
		_ = metricsListener.Close()
		_ = listener.Close()
		s.metrics.observe("readiness", "failure", "notify_failed")
		s.log("error", "forwarder_startup", "failure", "notify_failed")
		return fmt.Errorf("notify systemd readiness: %w", err)
	}
	s.metrics.setReady(true)
	s.metrics.observe("readiness", "success", "ready")
	s.log("info", "forwarder_ready", "success", "ready")
	return nil
}

func (s *Server) Serve() error {
	if s.listener == nil {
		return errors.New("forwarder server has not been started")
	}
	for {
		client, err := s.listener.Accept()
		if err != nil {
			if s.stopping.Load() {
				return nil
			}
			if temporary, ok := err.(interface{ Temporary() bool }); ok && temporary.Temporary() {
				continue
			}
			return fmt.Errorf("accept transparent connection: %w", err)
		}
		if s.stopping.Load() {
			_ = client.Close()
			continue
		}
		select {
		case s.sem <- struct{}{}:
			s.track(client)
			s.metrics.observe("connection", "accepted", "none")
			s.wg.Add(1)
			go func() {
				defer func() {
					<-s.sem
					s.untrack(client)
					s.wg.Done()
				}()
				s.handle(client)
			}()
		default:
			client.Close()
			s.metrics.observe("connection", "failure", "connection_limit")
			s.log("warn", "forwarder_connection", "failure", "connection_limit")
		}
	}
}

// Shutdown stops accepts before draining. On expiry it closes every active
// client and upstream socket and returns immediately; it never waits past the
// supplied bound for an uncooperative proxy or copy goroutine.
func (s *Server) Shutdown(ctx context.Context) error {
	var shutdownErr error
	s.stopOne.Do(func() {
		s.stopping.Store(true)
		s.metrics.setReady(false)
		s.metrics.observe("drain", "started", "shutdown")
		s.log("info", "forwarder_drain", "started", "shutdown")
		_ = s.notifier.Stopping("pgw forwarder draining")
		s.creds.close()
		if s.listener != nil {
			shutdownErr = s.listener.Close()
		}
		if s.metricsServer != nil {
			_ = s.metricsServer.Close()
		}
		if s.metricsListener != nil {
			_ = s.metricsListener.Close()
		}
	})
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		s.metrics.observe("drain", "completed", "none")
		return shutdownErr
	case <-ctx.Done():
		s.closeActiveSockets()
		s.metrics.observe("forced_close", "success", "deadline")
		s.log("warn", "forwarder_forced_close", "success", "deadline")
		return ctx.Err()
	}
}

// CloseCredentials erases the owned credential buffers on all startup and
// runtime error paths. It is idempotent and does not alter listener state.
func (s *Server) CloseCredentials() {
	if s != nil && s.creds != nil {
		s.creds.close()
	}
}

func (s *Server) ActiveConnections() int64 { return s.active.Load() }

func (s *Server) track(conn net.Conn) {
	s.mu.Lock()
	s.clients[conn] = nil
	s.mu.Unlock()
	s.metrics.setActive(s.active.Add(1))
}

func (s *Server) trackUpstream(client, upstream net.Conn) bool {
	closeUpstream := false
	s.mu.Lock()
	if _, active := s.clients[client]; active && !s.stopping.Load() {
		s.clients[client] = upstream
	} else {
		closeUpstream = true
	}
	s.mu.Unlock()
	if closeUpstream {
		_ = upstream.Close()
		return false
	}
	return true
}

func (s *Server) untrack(conn net.Conn) {
	s.mu.Lock()
	delete(s.clients, conn)
	s.mu.Unlock()
	s.metrics.setActive(s.active.Add(-1))
}

func (s *Server) closeActiveSockets() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for client, upstream := range s.clients {
		_ = client.Close()
		if upstream != nil {
			_ = upstream.Close()
		}
	}
}

func (s *Server) handle(client net.Conn) {
	defer client.Close()
	tcpClient, ok := client.(*net.TCPConn)
	if !ok {
		s.connectionFailure("original_destination")
		return
	}
	destination, err := OriginalDestination(tcpClient)
	if err != nil {
		s.connectionFailure("original_destination")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.runtime.DialTimeout)
	proxyConn, err := s.upstream.dial(ctx, destination)
	cancel()
	if err != nil {
		s.connectionFailure(reasonCode(err))
		return
	}
	defer proxyConn.Close()
	if !s.trackUpstream(client, proxyConn) {
		s.connectionFailure("credential_unavailable")
		return
	}

	clientResult, proxyResult := relayWithIdleTimeout(client, proxyConn, s.runtime.IdleTimeout)
	s.metrics.addBytes(clientResult.bytes + proxyResult.bytes)
	if clientResult.err != nil || proxyResult.err != nil {
		s.connectionFailure("copy_failed")
		return
	}
	s.metrics.observe("connection", "success", "none")
	s.log("info", "forwarder_connection", "success", "none")
}

type copyResult struct {
	bytes int64
	err   error
}

// relayWithIdleTimeout forwards both directions with one shared idle window.
// Every successful read and every successful (including partial) write extends
// both connection deadlines. A one-way transfer therefore keeps the reverse
// read alive only while either side continues to make progress.
func relayWithIdleTimeout(client, proxy net.Conn, idleTimeout time.Duration) (copyResult, copyResult) {
	activity := newActivityDeadline(client, proxy, idleTimeout)
	if err := activity.touch(); err != nil {
		return copyResult{err: err}, copyResult{}
	}

	done := make(chan copyResult, 2)
	go func() { done <- copyWithActivityDeadline(client, proxy, activity) }()
	go func() { done <- copyWithActivityDeadline(proxy, client, activity) }()
	return <-done, <-done
}

type activityDeadline struct {
	client net.Conn
	proxy  net.Conn
	idle   time.Duration
	mu     sync.Mutex
}

func newActivityDeadline(client, proxy net.Conn, idle time.Duration) *activityDeadline {
	return &activityDeadline{client: client, proxy: proxy, idle: idle}
}

func (d *activityDeadline) touch() error {
	deadline := time.Now().Add(d.idle)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.client.SetDeadline(deadline); err != nil {
		return err
	}
	if err := d.proxy.SetDeadline(deadline); err != nil {
		return err
	}
	return nil
}

func copyWithActivityDeadline(source, destination net.Conn, activity *activityDeadline) copyResult {
	buffer := make([]byte, 32<<10)
	var copied int64
	for {
		read, readErr := source.Read(buffer)
		if read > 0 {
			if err := activity.touch(); err != nil {
				return copyResult{bytes: copied, err: err}
			}
			written, err := writeAllWithActivity(destination, buffer[:read], activity)
			copied += written
			if err != nil {
				return copyResult{bytes: copied, err: err}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return copyResult{bytes: copied}
			}
			return copyResult{bytes: copied, err: readErr}
		}
		if read == 0 {
			return copyResult{bytes: copied, err: io.ErrNoProgress}
		}
	}
}

func writeAllWithActivity(conn net.Conn, payload []byte, activity *activityDeadline) (int64, error) {
	var writtenTotal int64
	for len(payload) > 0 {
		written, err := conn.Write(payload)
		if written < 0 || written > len(payload) {
			return writtenTotal, errors.New("forwarder write returned invalid byte count")
		}
		if written > 0 {
			writtenTotal += int64(written)
			if touchErr := activity.touch(); touchErr != nil {
				return writtenTotal, touchErr
			}
		}
		if err != nil {
			return writtenTotal, err
		}
		if written == 0 {
			return writtenTotal, io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return writtenTotal, nil
}

func (s *Server) connectionFailure(reason string) {
	reason = metricReason(reason)
	s.metrics.observe("connection", "failure", reason)
	if reason == "dial_timeout" || reason == "dial_failed" {
		s.metrics.observe("dial", "failure", reason)
	}
	if reason == "handshake_timeout" || reason == "handshake_failed" || reason == "proxy_rejected" {
		s.metrics.observe("handshake", "failure", reason)
	}
	s.log("warn", "forwarder_connection", "failure", reason)
}

func (s *Server) log(level, event, outcome, reason string) {
	if s.observer == nil || s.observer.Logger == nil {
		return
	}
	s.observer.Logger.Log(context.Background(), level, event, map[string]any{
		"mapping_id":  s.runtime.MappingID,
		"outcome":     outcome,
		"reason_code": metricReason(reason),
		"state":       metricProxyType(s.runtime.ProxyType),
	})
}

func validateCredentials(proxyType string, credentials Credentials) error {
	if !credentials.Configured {
		return nil
	}
	if len(credentials.Username) > maxCredentialBytes || len(credentials.Password) > maxCredentialBytes {
		return errors.New("proxy credential exceeds forwarder limit")
	}
	if proxyType == "socks5" && (len(credentials.Username) > 255 || len(credentials.Password) > 255) {
		return errors.New("SOCKS5 credential exceeds protocol limit")
	}
	return nil
}

type credentialStore struct {
	mu          sync.Mutex
	credentials Credentials
	closed      bool
}

func newCredentialStore(credentials Credentials) *credentialStore {
	return &credentialStore{credentials: credentials}
}

// acquire makes a bounded per-session mutable copy. The caller owns and must
// wipe it after constructing its HTTP/SOCKS authentication material.
func (s *credentialStore) acquire() (Credentials, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Credentials{}, errors.New("forwarder credentials are unavailable")
	}
	return Credentials{
		Username:   append([]byte(nil), s.credentials.Username...),
		Password:   append([]byte(nil), s.credentials.Password...),
		Configured: s.credentials.Configured,
	}, nil
}

func (s *credentialStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.credentials.Wipe()
	s.closed = true
}
