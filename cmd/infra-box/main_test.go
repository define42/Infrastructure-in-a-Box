package main

import (
	"context"
	"errors"
	"testing"
)

func TestServeStopsSiblingAndWaits(t *testing.T) {
	t.Parallel()
	failure := errors.New("listener unavailable")
	stopped := make(chan struct{}, 2)
	runner := func(ctx context.Context) error {
		<-ctx.Done()
		stopped <- struct{}{}
		return nil
	}
	err := serve(t.Context(),
		func(context.Context) error { return failure },
		runner,
		runner,
	)
	if !errors.Is(err, failure) {
		t.Fatalf("serve error = %v, want listener error", err)
	}
	if len(stopped) != 2 {
		t.Fatal("serve returned before both other services stopped")
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
	if err := serve(ctx, runner, runner, runner); err != nil {
		t.Fatal(err)
	}
}
