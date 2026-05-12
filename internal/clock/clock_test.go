package clock

import (
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
