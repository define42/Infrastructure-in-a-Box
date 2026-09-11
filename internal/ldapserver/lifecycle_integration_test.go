//go:build integration

package ldapserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

type lifecycleAccept struct {
	conn net.Conn
	err  error
}

// lifecycleListener controls accept order without opening a host interface.
type lifecycleListener struct {
	accepts chan lifecycleAccept
	closed  chan struct{}
	once    sync.Once
}

func (l *lifecycleListener) Accept() (net.Conn, error) {
	select {
	case next := <-l.accepts:
		return next.conn, next.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *lifecycleListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *lifecycleListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

type lifecycleConn struct {
	net.Conn
	readStarted chan struct{}
	readFailed  chan struct{}
	closed      chan struct{}
	releaseRead <-chan struct{}
	readOnce    sync.Once
	failOnce    sync.Once
	closeOnce   sync.Once
}

func (c *lifecycleConn) Read(data []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	n, err := c.Conn.Read(data)
	if err != nil {
		c.failOnce.Do(func() { close(c.readFailed) })
		if c.releaseRead != nil {
			<-c.releaseRead
		}
	}
	return n, err
}

func (c *lifecycleConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

func lifecyclePipe(t *testing.T) (*lifecycleConn, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	return &lifecycleConn{
		Conn: server, readStarted: make(chan struct{}), readFailed: make(chan struct{}), closed: make(chan struct{}),
	}, client
}

func lifecycleStart(t *testing.T) ([2]*lifecycleListener, context.CancelFunc, <-chan error) {
	t.Helper()
	server, err := New(config.LDAPConfig{
		Listen: "127.0.0.1:0", TLSListen: "127.0.0.1:0", BaseDN: "dc=home,dc=arpa",
	}, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return nil, errors.New("lifecycle tests never complete a TLS handshake")
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	listeners := [2]*lifecycleListener{
		{accepts: make(chan lifecycleAccept), closed: make(chan struct{})},
		{accepts: make(chan lifecycleAccept), closed: make(chan struct{})},
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, listeners[0], listeners[1]) }()
	return listeners, cancel, done
}

func TestLDAPLifecycleListenerErrorWaitsForConnections(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		listeners, _, done := lifecycleStart(t)
		conn, client := lifecyclePipe(t)
		release := make(chan struct{})
		var releaseOnce sync.Once
		releaseRead := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(releaseRead)
		conn.releaseRead = release
		listeners[0].accepts <- lifecycleAccept{conn: conn}
		<-conn.readStarted
		secure, _ := lifecyclePipe(t)
		listeners[1].accepts <- lifecycleAccept{conn: secure}
		<-secure.readStarted

		failure := errors.New("listener failed")
		listeners[1].accepts <- lifecycleAccept{err: failure}
		<-listeners[0].closed
		<-listeners[1].closed
		<-conn.readFailed
		<-secure.readFailed
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("serve returned before its connection worker exited: %v", err)
		default:
		}
		// The peer is already closed, but serve must also join its worker before
		// returning the listener error to the process-wide service lifecycle.
		if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("peer after listener failure: %v, want EOF", err)
		}
		releaseRead()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, failure) {
				t.Fatalf("serve error = %v, want listener failure", err)
			}
		default:
			t.Fatal("serve did not finish after its worker exited")
		}
	})
}

func TestLDAPLifecycleConnectionLimitAndRecovery(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		listeners, cancel, done := lifecycleStart(t)
		const limit = 64
		connections := make([]*lifecycleConn, 0, limit+1)
		clients := make([]net.Conn, 0, limit)
		for i := range limit {
			conn, client := lifecyclePipe(t)
			listeners[i%len(listeners)].accepts <- lifecycleAccept{conn: conn}
			<-conn.readStarted
			connections = append(connections, conn)
			clients = append(clients, client)
		}
		for _, listener := range listeners {
			overflow, overflowClient := lifecyclePipe(t)
			listener.accepts <- lifecycleAccept{conn: overflow}
			synctest.Wait()
			select {
			case <-overflow.closed:
			default:
				t.Fatal("server admitted a connection beyond its shared limit of 64")
			}
			if _, err := overflowClient.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("overflow connection: %v, want EOF", err)
			}
		}
		for _, conn := range connections {
			select {
			case <-conn.closed:
				t.Fatal("connection overflow displaced an admitted client")
			default:
			}
		}

		if err := clients[0].Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		replacement, _ := lifecyclePipe(t)
		// A slot released by LDAP is available to LDAPS too.
		listeners[1].accepts <- lifecycleAccept{conn: replacement}
		<-replacement.readStarted
		connections = append(connections, replacement)

		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("cancelled server: %v", err)
			}
		default:
			t.Fatal("cancelled server did not stop its idle connection workers")
		}
		for _, conn := range connections {
			select {
			case <-conn.closed:
			default:
				t.Fatal("cancelled server left an admitted connection open")
			}
		}
	})
}
