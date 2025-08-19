// pkg/events/correlation_engine.go
package events

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// CorrelationEngine identifies patterns and relationships between events
type CorrelationEngine struct {
	eventWindow      time.Duration
	recentEvents     []SecurityEvent
	correlationRules []CorrelationRule
	mutex            sync.RWMutex
	logger           zerolog.Logger
	eventBus         *EventBus
}

type CorrelationRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	EventTypes  []EventType   `json:"event_types"`
	TimeWindow  time.Duration `json:"time_window"`
	Threshold   int           `json:"threshold"`
	Severity    string        `json:"severity"`
	Action      string        `json:"action"`
	Description string        `json:"description"`
}

// NewCorrelationEngine creates a new correlation engine
func NewCorrelationEngine(logger zerolog.Logger, eventWindow time.Duration, eventBus *EventBus) *CorrelationEngine {
	engine := &CorrelationEngine{
		eventWindow:      eventWindow,
		recentEvents:     make([]SecurityEvent, 0),
		correlationRules: getDefaultCorrelationRules(),
		logger:           logger.With().Str("component", "correlation_engine").Logger(),
		eventBus:         eventBus,
	}

	// Subscribe to events
	if eventBus != nil {
		eventBus.Subscribe(engine)
	}

	return engine
}

// Handle processes events for correlation analysis
func (ce *CorrelationEngine) Handle(ctx context.Context, event SecurityEvent) error {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	// Add event to recent events
	ce.recentEvents = append(ce.recentEvents, event)

	// Clean old events outside the window
	cutoff := time.Now().Add(-ce.eventWindow)
	ce.recentEvents = ce.filterEventsByTime(ce.recentEvents, cutoff)

	// Check correlation rules
	for _, rule := range ce.correlationRules {
		if ce.checkRule(rule) {
			ce.triggerCorrelation(ctx, rule, event)
		}
	}

	return nil
}

// GetEventTypes returns event types this engine handles
func (ce *CorrelationEngine) GetEventTypes() []EventType {
	return []EventType{
		EventThreatDetected,
		EventHighValueAccess,
		EventDataExfiltration,
		EventProcessAnomaly,
		EventNetworkIntrusion,
		EventFileSystemChange,
		EventBehaviorAnomaly,
		EventIntegrityViolation,
		EventUnauthorizedChange,
	}
}

// checkRule evaluates if a correlation rule is triggered
func (ce *CorrelationEngine) checkRule(rule CorrelationRule) bool {
	matchingEvents := 0
	cutoff := time.Now().Add(-rule.TimeWindow)

	for _, event := range ce.recentEvents {
		if event.Timestamp.After(cutoff) {
			for _, ruleType := range rule.EventTypes {
				if event.Type == ruleType {
					matchingEvents++
					break
				}
			}
		}
	}

	return matchingEvents >= rule.Threshold
}

// triggerCorrelation handles when a correlation rule is triggered
func (ce *CorrelationEngine) triggerCorrelation(ctx context.Context, rule CorrelationRule, triggeringEvent SecurityEvent) {
	ce.logger.Warn().
		Str("rule_id", rule.ID).
		Str("rule_name", rule.Name).
		Str("triggering_event", triggeringEvent.ID).
		Msg("Correlation rule triggered")

	// Create a correlation event
	correlationEvent := SecurityEvent{
		Type:        EventThreatDetected,
		Source:      "correlation_engine",
		Target:      "system",
		Severity:    rule.Severity,
		Description: fmt.Sprintf("Correlation rule triggered: %s", rule.Description),
		Data: map[string]interface{}{
			"rule_id":            rule.ID,
			"rule_name":          rule.Name,
			"triggering_event":   triggeringEvent.ID,
			"matching_events":    ce.getMatchingEvents(rule),
			"recommended_action": rule.Action,
		},
		Tags: []string{"correlation", "multi-event"},
	}

	// Publish the correlation event
	if ce.eventBus != nil {
		if err := ce.eventBus.Publish(ctx, correlationEvent); err != nil {
			ce.logger.Error().Err(err).Msg("Failed to publish correlation event")
		}
	}
}

// getMatchingEvents returns events that match the correlation rule
func (ce *CorrelationEngine) getMatchingEvents(rule CorrelationRule) []string {
	var matchingEventIDs []string
	cutoff := time.Now().Add(-rule.TimeWindow)

	for _, event := range ce.recentEvents {
		if event.Timestamp.After(cutoff) {
			for _, ruleType := range rule.EventTypes {
				if event.Type == ruleType {
					matchingEventIDs = append(matchingEventIDs, event.ID)
					break
				}
			}
		}
	}

	return matchingEventIDs
}

// filterEventsByTime removes events older than the cutoff time
func (ce *CorrelationEngine) filterEventsByTime(events []SecurityEvent, cutoff time.Time) []SecurityEvent {
	filtered := make([]SecurityEvent, 0, len(events))
	for _, event := range events {
		if event.Timestamp.After(cutoff) {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// AddRule adds a custom correlation rule
func (ce *CorrelationEngine) AddRule(rule CorrelationRule) {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	ce.correlationRules = append(ce.correlationRules, rule)
	ce.logger.Info().
		Str("rule_id", rule.ID).
		Str("rule_name", rule.Name).
		Msg("Correlation rule added")
}

// RemoveRule removes a correlation rule by ID
func (ce *CorrelationEngine) RemoveRule(ruleID string) bool {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	for i, rule := range ce.correlationRules {
		if rule.ID == ruleID {
			ce.correlationRules = append(ce.correlationRules[:i], ce.correlationRules[i+1:]...)
			ce.logger.Info().
				Str("rule_id", ruleID).
				Msg("Correlation rule removed")
			return true
		}
	}
	return false
}

// GetRules returns all correlation rules
func (ce *CorrelationEngine) GetRules() []CorrelationRule {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()

	rules := make([]CorrelationRule, len(ce.correlationRules))
	copy(rules, ce.correlationRules)
	return rules
}

// GetStats returns correlation engine statistics
func (ce *CorrelationEngine) GetStats() map[string]interface{} {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()

	return map[string]interface{}{
		"total_rules":   len(ce.correlationRules),
		"recent_events": len(ce.recentEvents),
		"event_window":  ce.eventWindow.String(),
	}
}

func getDefaultCorrelationRules() []CorrelationRule {
	return []CorrelationRule{
		{
			ID:          "multi_stage_attack",
			Name:        "Multi-stage Attack Pattern",
			EventTypes:  []EventType{EventThreatDetected, EventNetworkIntrusion, EventDataExfiltration},
			TimeWindow:  30 * time.Minute,
			Threshold:   3,
			Severity:    "critical",
			Action:      "immediate_response",
			Description: "Multiple attack indicators within 30 minutes suggesting coordinated attack",
		},
		{
			ID:          "privilege_escalation",
			Name:        "Privilege Escalation Attempt",
			EventTypes:  []EventType{EventProcessAnomaly, EventFileSystemChange, EventHighValueAccess},
			TimeWindow:  15 * time.Minute,
			Threshold:   2,
			Severity:    "high",
			Action:      "investigate",
			Description: "Potential privilege escalation sequence detected",
		},
		{
			ID:          "data_exfiltration_pattern",
			Name:        "Data Exfiltration Pattern",
			EventTypes:  []EventType{EventHighValueAccess, EventDataExfiltration, EventNetworkIntrusion},
			TimeWindow:  20 * time.Minute,
			Threshold:   2,
			Severity:    "critical",
			Action:      "isolate_system",
			Description: "Pattern suggesting data exfiltration attempt",
		},
		{
			ID:          "reconnaissance_pattern",
			Name:        "System Reconnaissance",
			EventTypes:  []EventType{EventNetworkIntrusion, EventProcessAnomaly, EventBehaviorAnomaly},
			TimeWindow:  45 * time.Minute,
			Threshold:   4,
			Severity:    "medium",
			Action:      "monitor",
			Description: "Pattern suggesting system reconnaissance activity",
		},
		{
			ID:          "integrity_compromise",
			Name:        "System Integrity Compromise",
			EventTypes:  []EventType{EventIntegrityViolation, EventUnauthorizedChange, EventFileSystemChange},
			TimeWindow:  10 * time.Minute,
			Threshold:   2,
			Severity:    "high",
			Action:      "investigate",
			Description: "Multiple integrity violations suggesting system compromise",
		},
	}
}
