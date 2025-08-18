package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockMonitor is a mock implementation of the Monitor interface.
type MockMonitor struct {
	mock.Mock // Embed mock.Mock
}

func (m *MockMonitor) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockMonitor) Run(ctx context.Context) {
	m.Called(ctx)
}

func TestScheduler_RegisterMonitor(t *testing.T) {
	cfg := &config.Config{}
	sched := NewScheduler(cfg)

	monitor := new(MockMonitor)
	monitor.On("Name").Return("test_monitor")

	sched.RegisterMonitor(monitor)

	assert.Len(t, sched.monitors, 1)
	assert.Equal(t, monitor, sched.monitors[0])
	monitor.AssertExpectations(t)
}

func TestScheduler_Start(t *testing.T) {
	// Setup config for the test
	cfg := &config.Config{
		Monitors: []config.MonitorConfig{
			{Name: "monitor_enabled", Enabled: true, Interval: "100ms"},
			{Name: "monitor_disabled", Enabled: false, Interval: "100ms"},
			{Name: "monitor_invalid_interval", Enabled: true, Interval: "invalid"},
		},
	}

	// Create a context that will be cancelled after a short duration
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	sched := NewScheduler(cfg)

	// Mock enabled monitor
	enabledMonitor := new(MockMonitor)
	enabledMonitor.On("Name").Return("monitor_enabled")

	var wg sync.WaitGroup
	// We expect at least 3 calls within 500ms for a 100ms interval (1 initial + 4 ticks)
	// Set a higher expectation to be safe, and use a WaitGroup to track actual calls.
	expectedCalls := 5
	wg.Add(expectedCalls)
	enabledMonitor.On("Run", mock.Anything).Run(func(args mock.Arguments) {
		wg.Done()
	}).Return().Times(expectedCalls)
	sched.RegisterMonitor(enabledMonitor)

	// Mock disabled monitor
	disabledMonitor := new(MockMonitor)
	disabledMonitor.On("Name").Return("monitor_disabled")
	disabledMonitor.AssertNotCalled(t, "Run", mock.Anything)
	sched.RegisterMonitor(disabledMonitor)

	// Mock monitor with invalid interval
	invalidIntervalMonitor := new(MockMonitor)
	invalidIntervalMonitor.On("Name").Return("monitor_invalid_interval")
	invalidIntervalMonitor.AssertNotCalled(t, "Run", mock.Anything)
	sched.RegisterMonitor(invalidIntervalMonitor)

	// Start the scheduler
	sched.Start(ctx)

	// Wait for the expected number of calls or context cancellation
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All expected calls happened
	case <-ctx.Done():
		// Context cancelled, some calls might not have happened, but that's expected for timeout
	}

	// Assert that the enabled monitor's Run method was called as expected
	enabledMonitor.AssertExpectations(t)
	disabledMonitor.AssertExpectations(t)
	invalidIntervalMonitor.AssertExpectations(t)
}

func TestScheduler_Shutdown(t *testing.T) {
	cfg := &config.Config{
		Monitors: []config.MonitorConfig{
			{Name: "shutdown_monitor", Enabled: true, Interval: "100ms"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	sched := NewScheduler(cfg)

	monitor := new(MockMonitor)
	monitor.On("Name").Return("shutdown_monitor")
	// Use a WaitGroup to ensure the Run method is called at least once before shutdown
	var wg sync.WaitGroup
	wg.Add(1)
	monitor.On("Run", mock.Anything).Run(func(args mock.Arguments) { wg.Done() }).Return()
	sched.RegisterMonitor(monitor)

	sched.Start(ctx)

	// Wait for the monitor to run at least once
	wg.Wait()

	// Cancel the context to signal shutdown
	cancel()

	// Give some time for the goroutines to shut down
	time.Sleep(200 * time.Millisecond)

	// Assert that Run was called at least once and then stopped
	monitor.AssertExpectations(t)
}
