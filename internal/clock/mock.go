// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package clock

import "time"

// Mock is a test Clock whose tickers fire immediately without sleeping.
type Mock struct{}

// NewTicker returns a mock ticker whose channel is pre-filled so reads
// never block. This is suitable for unit tests that need deterministic
// polling without real delays.
func (Mock) NewTicker(_ time.Duration) Ticker {
	const bufSize = 64
	ch := make(chan time.Time, bufSize)
	now := time.Now()
	for range bufSize {
		ch <- now
	}
	return &mockTicker{ch: ch}
}

type mockTicker struct {
	ch chan time.Time
}

func (m *mockTicker) C() <-chan time.Time { return m.ch }
func (m *mockTicker) Stop()               {}
func (m *mockTicker) Reset(_ time.Duration) {
	now := time.Now()
	for {
		select {
		case m.ch <- now:
		default:
			return
		}
	}
}
