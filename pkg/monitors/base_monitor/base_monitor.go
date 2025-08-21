// pkg/monitors/base_monitor/base_monitor.go
package base_monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/actions"
	"github.com/lucid-vigil/sentinel/pkg/errors"
	"github.com/lucid-vigil/sentinel/pkg/events"
	"github.com/rs/zerolog"
)

// MonitorClass defines the category of a monitor.
type MonitorClass string

const (
	ClassSentry   MonitorClass = "sentry"
	ClassSentinel MonitorClass = "sentinel"
	ClassDetector MonitorClass = "detector"
	ClassAnalyzer MonitorClass = "analyzer"
	ClassScribe   MonitorClass = "scribe"
)

// Capability defines a specific capability of a monitor.
type Capability string

const (
	CapabilityRealTime          Capability = "real_time"
	CapabilityMachineLearning   Capability = "machine_learning"
	CapabilityForensics         Capability = "forensics"
	CapabilityThreatIntel       Capability = "threat_intelligence"
	CapabilityAutomatedResponse Capability = "automated_response"
	CapabilityBehaviorAnalysis  Capability = "behavior_analysis"
	CapabilityCorrelation       Capability = "correlation"
)

// MonitorState represents the operational state of a monitor.
type MonitorState struct {
	LastEvent     time.Time              `json:"last_event"`
	EventsRaised  int64                  `json:"events_raised"`
	ActionsHanded int64                  `json:"actions_handled"`
	Status        string                 `json:"status"`
	Details       map[string]interface{} `json:"details"`
}

// BaseMonitor provides a common foundation for all monitor types,
// combining basic execution management with enhanced event-driven capabilities.
type BaseMonitor struct {
	// Core attributes
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
	errorHandler      *errors.ErrorHandler

	// Enhanced attributes
	EventBus     *events.EventBus
	class        MonitorClass
	capabilities []Capability
	state        MonitorState
}

// NewBaseMonitor creates and initializes a new enhanced BaseMonitor.
func NewBaseMonitor(name string, class MonitorClass, logger zerolog.Logger, eventBus *events.EventBus) *BaseMonitor {
	return &BaseMonitor{
		// Core initialization
		name:    name,
		enabled: true,
		logger:  logger.With().Str("monitor", name).Logger(),
		metrics: make(map[string]interface{}),

		// Enhanced initialization
		EventBus:     eventBus,
		class:        class,
		capabilities: []Capability{},
		state: MonitorState{
			Status:  "initialized",
			Details: make(map[string]interface{}),
		},
	}
}

// SetActionDispatcher sets the action dispatcher for this monitor.
func (b *BaseMonitor) SetActionDispatcher(dispatcher *actions.ActionDispatcher) {
	b.dispatcher = dispatcher
}

// SetConfiguredActions sets the actions this monitor should trigger.
func (b *BaseMonitor) SetConfiguredActions(actions []string) {
	b.configuredActions = actions
}

// TriggerAction executes a single action with the given data.
func (b *BaseMonitor) TriggerAction(ctx context.Context, actionName string, data map[string]interface{}) {
	if b.dispatcher == nil {
		b.logger.Warn().Msg("No action dispatcher configured, cannot execute actions.")
		return
	}

	if err := b.dispatcher.Execute(ctx, actionName, data); err != nil {
		b.logger.Error().Err(err).Str("action", actionName).Msg("Failed to execute action.")
	}
}

// TriggerConfiguredActions executes all configured actions for this monitor.
func (b *BaseMonitor) TriggerConfiguredActions(ctx context.Context, data map[string]interface{}) {
	if b.dispatcher == nil || len(b.configuredActions) == 0 {
		return
	}

	b.logger.Info().Strs("actions", b.configuredActions).Msg("Triggering configured actions.")
	b.dispatcher.ExecuteActions(ctx, b.configuredActions, data)
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

	dest := make(map[string]interface{}, len(b.metrics))
	for k, v := range b.metrics {
		dest[k] = v
	}
	return dest
}

// LogEvent is a helper to log events with the monitor's context.
func (b *BaseMonitor) LogEvent(level zerolog.Level, message string) *zerolog.Event {
	return b.logger.WithLevel(level).Str("event", message)
}

// UpdateMetrics is a helper to update a metric value.
func (b *BaseMonitor) UpdateMetrics(key string, value interface{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.metrics[key] = value
}

// RecordExecution updates the last run time and error status.
func (b *BaseMonitor) RecordExecution(err error) {
	b.lastRun = time.Now()
	b.lastError = err
}

// HandleError creates a structured error and passes it to the configured error handler.
func (b *BaseMonitor) HandleError(ctx context.Context, errorType string, message string, cause error, recoverable bool) {
	monitorError := &errors.MonitorError{
		MonitorName: b.name,
		ErrorType:   errorType,
		Message:     message,
		Timestamp:   time.Now(),
		Severity:    errors.SeverityMedium, // Default, monitors can override
		Recoverable: recoverable,
		Cause:       cause,
	}

	if b.errorHandler != nil {
		b.errorHandler.HandleError(ctx, monitorError)
	} else {
		b.logger.Error().
			Str("error_type", errorType).
			Str("message", message).
			Bool("recoverable", recoverable).
			AnErr("cause", cause).
			Msg("Monitor error (no error handler configured)")
	}

	b.RecordExecution(monitorError)
}

// AddCapability adds a capability to the monitor.
func (b *BaseMonitor) AddCapability(cap Capability) {
	b.capabilities = append(b.capabilities, cap)
	b.LogEvent(zerolog.InfoLevel, fmt.Sprintf("Added capability: %s", cap))
}

// HasCapability checks if the monitor has a specific capability.
func (b *BaseMonitor) HasCapability(cap Capability) bool {
	for _, c := range b.capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// PublishEvent publishes a security event to the event bus.
func (b *BaseMonitor) PublishEvent(ctx context.Context, eventType events.EventType, target, description string, severity string, data map[string]interface{}) error {
	if b.EventBus == nil {
		b.LogEvent(zerolog.WarnLevel, "No event bus configured, cannot publish event")
		return fmt.Errorf("no event bus configured")
	}

	event := events.SecurityEvent{
		Type:        eventType,
		Source:      b.Name(),
		Target:      target,
		Severity:    severity,
		Description: description,
		Data:        data,
		Tags:        []string{string(b.class)},
	}

	if err := b.EventBus.Publish(ctx, event); err != nil {
		b.LogEvent(zerolog.ErrorLevel, "Failed to publish event").Err(err)
		return err
	}

	b.state.EventsRaised++
	b.state.LastEvent = time.Now()
	b.LogEvent(zerolog.DebugLevel, "Event published successfully").
		Str("event_type", string(eventType)).
		Str("target", target).
		Str("severity", severity)

	return nil
}

// GetClass returns the monitor's class.
func (b *BaseMonitor) GetClass() MonitorClass {
	return b.class
}

// GetCapabilities returns the monitor's capabilities.
func (b *BaseMonitor) GetCapabilities() []Capability {
	return b.capabilities
}

// GetState returns the current monitor state.
func (b *BaseMonitor) GetState() MonitorState {
	return b.state
}

// UpdateState updates the monitor's state details.
func (b *BaseMonitor) UpdateState(key string, value interface{}) {
	b.state.Details[key] = value
}

// SetEventBus sets the event bus for the monitor.
func (b *BaseMonitor) SetEventBus(eventBus *events.EventBus) {
	b.EventBus = eventBus
}
