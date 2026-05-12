// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package clock provides a minimal Clock interface for time-dependent code.
// Production code uses Real (which delegates to the standard library), while
// tests use Mock to advance time programmatically without sleeping.
package clock

import "time"

// Clock abstracts time operations so that tests can control time progression
// without sleeping.
type Clock interface {
	// NewTicker returns a ticker that fires at the given interval.
	NewTicker(d time.Duration) Ticker
}

// Ticker abstracts *time.Ticker so both real and mock implementations
// can be used interchangeably.
type Ticker interface {
	// C returns the ticker's channel.
	C() <-chan time.Time

	// Stop stops the ticker.
	Stop()

	// Reset changes the ticker's interval.
	Reset(d time.Duration)
}

// Real is a Clock backed by the standard library's time package.
type Real struct{}

// NewTicker creates a real time.Ticker.
func (Real) NewTicker(d time.Duration) Ticker {
	return &realTicker{t: time.NewTicker(d)}
}

type realTicker struct {
	t *time.Ticker
}

func (r *realTicker) C() <-chan time.Time   { return r.t.C }
func (r *realTicker) Stop()                 { r.t.Stop() }
func (r *realTicker) Reset(d time.Duration) { r.t.Reset(d) }
