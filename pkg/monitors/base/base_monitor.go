package base

import (
	"context"
	"sync"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/actions"
	"github.com/rs/zerolog"
)

// BaseMonitor provides a common foundation for all monitor types
type BaseMonitor struct {
	name              string
	enabled           bool
	interval          time.Duration
	lastRun           time.Time
	lastError         error
	metrics           map[string]interface{}
	logger            zerolog.Logger
	mu                sync.Mutex
	dispatcher        *actions.ActionDispatcher
	configuredActions []string
}

// NewBaseMonitor creates and initializes a new BaseMonitor
func NewBaseMonitor(name string, logger zerolog.Logger) *BaseMonitor {
	return &BaseMonitor{
		name:    name,
		enabled: true,
		logger:  logger.With().Str("monitor", name).Logger(),
		metrics: make(map[string]interface{}),
	}
}

// SetActionDispatcher sets the action dispatcher for this monitor
func (b *BaseMonitor) SetActionDispatcher(dispatcher *actions.ActionDispatcher) {
	b.dispatcher = dispatcher
}

// SetConfiguredActions sets the actions this monitor should trigger
func (b *BaseMonitor) SetConfiguredActions(actions []string) {
	b.configuredActions = actions
}

// TriggerAction executes a single action with the given data
func (b *BaseMonitor) TriggerAction(ctx context.Context, actionName string, data map[string]interface{}) {
	if b.dispatcher == nil {
		b.logger.Warn().Msg("No action dispatcher configured, cannot execute actions.")
		return
	}

	if err := b.dispatcher.Execute(ctx, actionName, data); err != nil {
		b.logger.Error().Err(err).Str("action", actionName).Msg("Failed to execute action.")
	}
}

// TriggerConfiguredActions executes all configured actions for this monitor
func (b *BaseMonitor) TriggerConfiguredActions(ctx context.Context, data map[string]interface{}) {
	if b.dispatcher == nil || len(b.configuredActions) == 0 {
		return
	}

	b.logger.Info().Strs("actions", b.configuredActions).Msg("Triggering configured actions.")
	b.dispatcher.ExecuteActions(ctx, b.configuredActions, data)
}

// Name returns the monitor's name
func (b *BaseMonitor) Name() string {
	return b.name
}

// IsEnabled returns whether the monitor is enabled
func (b *BaseMonitor) IsEnabled() bool {
	return b.enabled
}

// GetInterval returns the monitor's execution interval
func (b *BaseMonitor) GetInterval() time.Duration {
	return b.interval
}

// SetInterval sets the monitor's execution interval
func (b *BaseMonitor) SetInterval(d time.Duration) {
	b.interval = d
}

// GetLastError returns the last error that occurred during execution
func (b *BaseMonitor) GetLastError() error {
	return b.lastError
}

// GetLastExecutionTime returns the last time the monitor was executed
func (b *BaseMonitor) GetLastExecutionTime() time.Time {
	return b.lastRun
}

// GetMetrics returns the monitor's collected metrics
func (b *BaseMonitor) GetMetrics() map[string]interface{} {
	b.mu.Lock()
	defer b.mu.Unlock()

	dest := make(map[string]interface{}, len(b.metrics))
	for k, v := range b.metrics {
		dest[k] = v
	}
	return dest
}

// LogEvent is a helper to log events with the monitor's context
func (b *BaseMonitor) LogEvent(level zerolog.Level, message string) *zerolog.Event {
	return b.logger.WithLevel(level).Str("event", message)
}

// UpdateMetrics is a helper to update a metric value
func (b *BaseMonitor) UpdateMetrics(key string, value interface{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.metrics[key] = value
}

// RecordExecution updates the last run time and error status
func (b *BaseMonitor) RecordExecution(err error) {
	b.lastRun = time.Now()
	b.lastError = err
}
