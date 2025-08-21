// pkg/events/event_bus.go
package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// EventType defines the type of security event
type EventType string

const (
	EventThreatDetected          EventType = "threat_detected"
	EventHighValueAccess         EventType = "high_value_access"
	EventDataExfiltration        EventType = "data_exfiltration"
	EventProcessAnomaly          EventType = "process_anomaly"
	EventNetworkIntrusion        EventType = "network_intrusion"
	EventFileSystemChange        EventType = "filesystem_change"
	EventBehaviorAnomaly         EventType = "behavior_anomaly"
	EventIncidentCreated         EventType = "incident_created"
	EventActionTriggered         EventType = "action_triggered"
	EventForensicComplete        EventType = "forensic_complete"
	EventIntegrityViolation      EventType = "integrity_violation"
	EventUnauthorizedChange      EventType = "unauthorized_change"
	EventSystemStateChange       EventType = "system_state_change"
	EventConfigurationChange     EventType = "configuration_change"
	EventSecurityPolicyViolation EventType = "security_policy_violation"
	// /pkg/monitors/analyzer.go
	EventPrivilegeEscalation EventType = "privilege_escalation"
	EventSuspiciousNetwork   EventType = "suspicious_network"
	EventMalwareDetected     EventType = "malware_detected"
	EventRootkitDetected     EventType = "rootkit_detected"
	EventSystemAnomaly       EventType = "system_anomaly"
	// /pkg/monitors/scheduler.go
	EventSystemStatus EventType = "system_status"
	EventSystemError  EventType = "system_error"
	// /pkg/monitors/scribe.go
	EventComplianceStatus EventType = "compliance_status"
	EventCorrelation      EventType = "correlation"
	// pkg/monitors/sentinel.go
	EventAutomatedResponse EventType = "automated_response"
	EventCertificateChange EventType = "certificate_change"
	EventCertificateExpiry EventType = "certificate_expiry"
	EventSystemReport      EventType = "system_report"
	// /pkg/monitors/sentry.go
	EventFirmwareChange EventType = "firmware_change"
)

// SecurityEvent represents a security event in the system
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Type        EventType              `json:"type"`
	Source      string                 `json:"source"`   // Which monitor generated this
	Target      string                 `json:"target"`   // What was affected
	Severity    string                 `json:"severity"` // critical, high, medium, low
	Timestamp   time.Time              `json:"timestamp"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
	Tags        []string               `json:"tags"`
	TTL         time.Duration          `json:"ttl"` // How long event is valid
}

// EventHandler defines the interface for event handlers
type EventHandler interface {
	Handle(ctx context.Context, event SecurityEvent) error
	GetEventTypes() []EventType
}

// EventBus manages event distribution between monitor classes
type EventBus struct {
	handlers    map[EventType][]EventHandler
	buffer      chan SecurityEvent
	logger      zerolog.Logger
	mu          sync.RWMutex
	metrics     EventMetrics
	running     bool
	stopChannel chan struct{}
	wg          sync.WaitGroup
}

type EventMetrics struct {
	EventsPublished   int64            `json:"events_published"`
	EventsProcessed   int64            `json:"events_processed"`
	EventsByType      map[string]int64 `json:"events_by_type"`
	EventsBySeverity  map[string]int64 `json:"events_by_severity"`
	HandlerErrors     int64            `json:"handler_errors"`
	AverageProcessing time.Duration    `json:"average_processing_time"`
}

// NewEventBus creates a new event bus
func NewEventBus(logger zerolog.Logger, bufferSize int) *EventBus {
	if bufferSize <= 0 {
		bufferSize = 1000
	}

	return &EventBus{
		handlers:    make(map[EventType][]EventHandler),
		buffer:      make(chan SecurityEvent, bufferSize),
		logger:      logger.With().Str("component", "event_bus").Logger(),
		stopChannel: make(chan struct{}),
		metrics: EventMetrics{
			EventsByType:     make(map[string]int64),
			EventsBySeverity: make(map[string]int64),
		},
	}
}

// Subscribe registers an event handler for specific event types
func (eb *EventBus) Subscribe(handler EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	eventTypes := handler.GetEventTypes()
	for _, eventType := range eventTypes {
		eb.handlers[eventType] = append(eb.handlers[eventType], handler)
		eb.logger.Info().
			Str("event_type", string(eventType)).
			Msg("Handler subscribed to event type")
	}
}

// Publish sends an event to all registered handlers
func (eb *EventBus) Publish(ctx context.Context, event SecurityEvent) error {
	if event.ID == "" {
		event.ID = generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	select {
	case eb.buffer <- event:
		eb.updateMetrics(event, true)
		eb.logger.Debug().
			Str("event_id", event.ID).
			Str("type", string(event.Type)).
			Str("source", event.Source).
			Msg("Event published to bus")
		return nil
	default:
		eb.logger.Error().
			Str("event_id", event.ID).
			Str("type", string(event.Type)).
			Msg("Event bus buffer full, dropping event")
		return ErrEventBusBufferFull
	}
}

// Start begins processing events from the buffer
func (eb *EventBus) Start(ctx context.Context) {
	eb.mu.Lock()
	if eb.running {
		eb.mu.Unlock()
		return
	}
	eb.running = true
	eb.mu.Unlock()

	eb.logger.Info().Msg("Event bus starting...")

	eb.wg.Add(1)
	go func() {
		defer eb.wg.Done()
		for {
			select {
			case event := <-eb.buffer:
				eb.processEvent(ctx, event)
			case <-ctx.Done():
				eb.logger.Info().Msg("Event bus shutting down due to context cancellation...")
				return
			case <-eb.stopChannel:
				eb.logger.Info().Msg("Event bus shutting down...")
				return
			}
		}
	}()
}

// Stop gracefully shuts down the event bus
func (eb *EventBus) Stop() {
	eb.mu.Lock()
	if !eb.running {
		eb.mu.Unlock()
		return
	}
	eb.running = false
	eb.mu.Unlock()

	close(eb.stopChannel)
	eb.wg.Wait()
	eb.logger.Info().Msg("Event bus stopped")
}

// processEvent handles distribution of events to handlers
func (eb *EventBus) processEvent(ctx context.Context, event SecurityEvent) {
	start := time.Now()

	eb.mu.RLock()
	handlers, exists := eb.handlers[event.Type]
	eb.mu.RUnlock()

	if !exists || len(handlers) == 0 {
		eb.logger.Debug().
			Str("event_type", string(event.Type)).
			Msg("No handlers registered for event type")
		return
	}

	// Process handlers concurrently
	var wg sync.WaitGroup
	errorChan := make(chan error, len(handlers))

	for _, handler := range handlers {
		wg.Add(1)
		go func(h EventHandler) {
			defer wg.Done()
			if err := h.Handle(ctx, event); err != nil {
				errorChan <- err
				eb.logger.Error().
					Err(err).
					Str("event_id", event.ID).
					Str("event_type", string(event.Type)).
					Msg("Handler error processing event")
			}
		}(handler)
	}

	wg.Wait()
	close(errorChan)

	// Count errors
	errorCount := 0
	for range errorChan {
		errorCount++
	}

	eb.mu.Lock()
	eb.metrics.HandlerErrors += int64(errorCount)
	eb.mu.Unlock()

	eb.updateMetrics(event, false)
	eb.metrics.AverageProcessing = time.Since(start)

	eb.logger.Debug().
		Str("event_id", event.ID).
		Dur("processing_time", time.Since(start)).
		Int("handlers", len(handlers)).
		Int("errors", errorCount).
		Msg("Event processed by all handlers")
}

// updateMetrics updates internal metrics
func (eb *EventBus) updateMetrics(event SecurityEvent, published bool) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if published {
		eb.metrics.EventsPublished++
	} else {
		eb.metrics.EventsProcessed++
	}

	eb.metrics.EventsByType[string(event.Type)]++
	eb.metrics.EventsBySeverity[event.Severity]++
}

// GetMetrics returns current event bus metrics
func (eb *EventBus) GetMetrics() EventMetrics {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	// Create a copy to avoid race conditions
	metricsCopy := EventMetrics{
		EventsPublished:   eb.metrics.EventsPublished,
		EventsProcessed:   eb.metrics.EventsProcessed,
		HandlerErrors:     eb.metrics.HandlerErrors,
		AverageProcessing: eb.metrics.AverageProcessing,
		EventsByType:      make(map[string]int64),
		EventsBySeverity:  make(map[string]int64),
	}

	for k, v := range eb.metrics.EventsByType {
		metricsCopy.EventsByType[k] = v
	}
	for k, v := range eb.metrics.EventsBySeverity {
		metricsCopy.EventsBySeverity[k] = v
	}

	return metricsCopy
}

// generateEventID creates a unique event ID
func generateEventID() string {
	timestamp := time.Now().Format("20060102_150405")
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to time-based if crypto/rand fails
		return fmt.Sprintf("evt_%s_%d", timestamp, time.Now().UnixNano()%10000)
	}
	return fmt.Sprintf("evt_%s_%s", timestamp, hex.EncodeToString(randomBytes))
}

// Errors
var (
	ErrEventBusBufferFull = fmt.Errorf("event bus buffer is full")
)
