package clock

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRealNewTicker(t *testing.T) {
	r := Real{}
	ticker := r.NewTicker(50 * time.Millisecond)
	require.NotNil(t, ticker)
	defer ticker.Stop()

	select {
	case ts := <-ticker.C():
		assert.False(t, ts.IsZero())
	case <-time.After(1 * time.Second):
		t.Fatal("ticker did not fire within 1s")
	}
}

func TestRealTickerReset(t *testing.T) {
	r := Real{}
	ticker := r.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	ticker.Reset(50 * time.Millisecond)

	select {
	case ts := <-ticker.C():
		assert.False(t, ts.IsZero())
	case <-time.After(1 * time.Second):
		t.Fatal("ticker did not fire after reset")
	}
}

func TestMockNewTicker(t *testing.T) {
	m := Mock{}
	ticker := m.NewTicker(time.Second)
	require.NotNil(t, ticker)

	select {
	case ts := <-ticker.C():
		assert.False(t, ts.IsZero())
	default:
		t.Fatal("mock ticker channel should have data")
	}
}

func TestMockTickerStop(_ *testing.T) {
	m := Mock{}
	ticker := m.NewTicker(time.Second)
	ticker.Stop()
}

func TestMockTickerReset(t *testing.T) {
	m := Mock{}
	ticker := m.NewTicker(time.Second)

	for {
		select {
		case <-ticker.C():
		default:
			goto drained
		}
	}
drained:

	ticker.Reset(time.Second)

	select {
	case ts := <-ticker.C():
		assert.False(t, ts.IsZero())
	default:
		t.Fatal("mock ticker channel should have data after reset")
	}
}

func TestRealSleep(t *testing.T) {
	r := Real{}

	require.NoError(t, r.Sleep(context.Background(), 0))
	require.NoError(t, r.Sleep(context.Background(), 10*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Sleep(ctx, time.Hour)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestMockSleep(t *testing.T) {
	m := Mock{}
	require.NoError(t, m.Sleep(context.Background(), time.Minute))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, m.Sleep(ctx, time.Minute), context.Canceled)

	var got time.Duration
	custom := Mock{
		SleepFunc: func(_ context.Context, d time.Duration) error {
			got = d
			return nil
		},
	}
	require.NoError(t, custom.Sleep(context.Background(), 6*time.Second))
	assert.Equal(t, 6*time.Second, got)
}
