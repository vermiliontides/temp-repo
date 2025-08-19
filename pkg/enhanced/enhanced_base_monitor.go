// pkg/monitors/enhanced/enhanced_base_monitor.go
package enhanced

import (
	"context"
	"fmt"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/events"
	"github.com/lucid-vigil/sentinel/pkg/monitors/base"
	"github.com/rs/zerolog"
)

// EnhancedMonitor extends the base monitor with event bus integration
type EnhancedMonitor struct {
	*base.BaseMonitor
	eventBus     *events.EventBus
	class        MonitorClass
	capabilities []Capability
	state        MonitorState
}

type MonitorClass string

const (
	ClassSentry   MonitorClass = "sentry"
	ClassSentinel MonitorClass = "sentinel"
	ClassDetector MonitorClass = "detector"
	ClassAnalyzer MonitorClass = "analyzer"
	ClassScribe   MonitorClass = "scribe"
)

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

type MonitorState struct {
	LastEvent     time.Time              `json:"last_event"`
	EventsRaised  int64                  `json:"events_raised"`
	ActionsHanded int64                  `json:"actions_handled"`
	Status        string                 `json:"status"`
	Details       map[string]interface{} `json:"details"`
}

// NewEnhancedMonitor creates an enhanced monitor
func NewEnhancedMonitor(name string, class MonitorClass, logger zerolog.Logger, eventBus *events.EventBus) *EnhancedMonitor {
	return &EnhancedMonitor{
		BaseMonitor:  base.NewBaseMonitor(name, logger),
		eventBus:     eventBus,
		class:        class,
		capabilities: []Capability{},
		state: MonitorState{
			Status:  "initialized",
			Details: make(map[string]interface{}),
		},
	}
}

// AddCapability adds a capability to the monitor
func (em *EnhancedMonitor) AddCapability(cap Capability) {
	em.capabilities = append(em.capabilities, cap)
	em.LogEvent(zerolog.InfoLevel, fmt.Sprintf("Added capability: %s", cap))
}

// HasCapability checks if monitor has a specific capability
func (em *EnhancedMonitor) HasCapability(cap Capability) bool {
	for _, c := range em.capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// PublishEvent publishes a security event to the event bus
func (em *EnhancedMonitor) PublishEvent(ctx context.Context, eventType events.EventType, target, description string, severity string, data map[string]interface{}) error {
	if em.eventBus == nil {
		em.LogEvent(zerolog.WarnLevel, "No event bus configured, cannot publish event")
		return fmt.Errorf("no event bus configured")
	}

	event := events.SecurityEvent{
		Type:        eventType,
		Source:      em.Name(),
		Target:      target,
		Severity:    severity,
		Description: description,
		Data:        data,
		Tags:        []string{string(em.class)},
	}

	if err := em.eventBus.Publish(ctx, event); err != nil {
		em.LogEvent(zerolog.ErrorLevel, "Failed to publish event").Err(err)
		return err
	}

	em.state.EventsRaised++
	em.state.LastEvent = time.Now()
	em.LogEvent(zerolog.DebugLevel, "Event published successfully").
		Str("event_type", string(eventType)).
		Str("target", target).
		Str("severity", severity)

	return nil
}

// GetClass returns the monitor's class
func (em *EnhancedMonitor) GetClass() MonitorClass {
	return em.class
}

// GetCapabilities returns the monitor's capabilities
func (em *EnhancedMonitor) GetCapabilities() []Capability {
	return em.capabilities
}

// GetState returns the current monitor state
func (em *EnhancedMonitor) GetState() MonitorState {
	return em.state
}

// UpdateState updates the monitor state
func (em *EnhancedMonitor) UpdateState(key string, value interface{}) {
	em.state.Details[key] = value
}

// SetEventBus sets the event bus for the monitor
func (em *EnhancedMonitor) SetEventBus(eventBus *events.EventBus) {
	em.eventBus = eventBus
}
