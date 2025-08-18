package base

import (
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// BaseMonitor provides a common foundation for all monitor types. It implements
// shared functionality for configuration, logging, and status tracking, reducing
// boilerplate code in individual monitor implementations.
type BaseMonitor struct {
	name      string
	enabled   bool
	interval  time.Duration
	lastRun   time.Time
	lastError error
	metrics   map[string]interface{}
	logger    zerolog.Logger
	mu        sync.Mutex // Mutex to protect access to the metrics map
}

// NewBaseMonitor creates and initializes a new BaseMonitor with a given name and logger.
// It returns a pointer to the created BaseMonitor.
func NewBaseMonitor(name string, logger zerolog.Logger) *BaseMonitor {
	return &BaseMonitor{
		name:    name,
		enabled: true, // Default to enabled
		logger:  logger.With().Str("monitor", name).Logger(),
		metrics: make(map[string]interface{}),
	}
}

// Name returns the monitor's name.
func (b *BaseMonitor) Name() string {
	return b.name
}

// IsEnabled returns whether the monitor is enabled.
func (b *BaseMonitor) IsEnabled() bool {
	return b.enabled
}

// GetInterval returns the monitor's execution interval.
func (b *BaseMonitor) GetInterval() time.Duration {
	return b.interval
}

// SetInterval sets the monitor's execution interval.
func (b *BaseMonitor) SetInterval(d time.Duration) {
	b.interval = d
}

// GetLastError returns the last error that occurred during execution.
func (b *BaseMonitor) GetLastError() error {
	return b.lastError
}

// GetLastExecutionTime returns the last time the monitor was executed.
func (b *BaseMonitor) GetLastExecutionTime() time.Time {
	return b.lastRun
}

// GetMetrics returns the monitor's collected metrics.
func (b *BaseMonitor) GetMetrics() map[string]interface{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Return a copy to prevent external modification of the map
	dest := make(map[string]interface{}, len(b.metrics))
	for k, v := range b.metrics {
		dest[k] = v
	}
	return dest
}

// LogEvent is a helper to log events with the monitor's context.
func (b *BaseMonitor) LogEvent(level zerolog.Level, message string) {
	b.logger.WithLevel(level).Msg(message)
}

// UpdateMetrics is a helper to update a metric value.
func (b *BaseMonitor) UpdateMetrics(key string, value interface{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.metrics[key] = value
}
