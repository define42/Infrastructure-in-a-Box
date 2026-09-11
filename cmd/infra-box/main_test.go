package main

import (
	"context"
	"errors"
	"testing"
)

func TestServeStopsSiblingAndWaits(t *testing.T) {
	t.Parallel()
	failure := errors.New("listener unavailable")
	stopped := make(chan struct{})
	err := serve(t.Context(),
		func(context.Context) error { return failure },
		func(ctx context.Context) error {
			<-ctx.Done()
			close(stopped)
			return nil
		},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("serve error = %v, want listener error", err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("serve returned before sibling stopped")
	}
}

func TestServeCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	runner := func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}
	if err := serve(ctx, runner, runner); err != nil {
		t.Fatal(err)
	}
}
