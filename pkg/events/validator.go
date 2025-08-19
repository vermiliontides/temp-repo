// pkg/events/validator.go
package events

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// EventValidator validates and sanitizes security events
type EventValidator struct {
	rateLimiters map[string]*rate.Limiter // source -> rate limiter
	maxDataSize  int
}

// NewEventValidator creates a new event validator
func NewEventValidator(maxDataSize int) *EventValidator {
	return &EventValidator{
		rateLimiters: make(map[string]*rate.Limiter),
		maxDataSize:  maxDataSize,
	}
}

// ValidateEvent validates a security event
func (ev *EventValidator) ValidateEvent(event *SecurityEvent) error {
	// Check required fields
	if event.Source == "" {
		return fmt.Errorf("event source is required")
	}
	if event.Target == "" {
		return fmt.Errorf("event target is required")
	}
	if event.Type == "" {
		return fmt.Errorf("event type is required")
	}
	if event.Severity == "" {
		return fmt.Errorf("event severity is required")
	}

	// Validate severity
	validSeverities := []string{"critical", "high", "medium", "low", "info"}
	if !contains(validSeverities, event.Severity) {
		return fmt.Errorf("invalid severity: %s", event.Severity)
	}

	// Sanitize description
	event.Description = sanitizeString(event.Description)

	// Limit data size
	if event.Data != nil && len(fmt.Sprintf("%v", event.Data)) > ev.maxDataSize {
		return fmt.Errorf("event data too large (max %d bytes)", ev.maxDataSize)
	}

	// Rate limiting check
	if !ev.checkRateLimit(event.Source) {
		return fmt.Errorf("rate limit exceeded for source: %s", event.Source)
	}

	return nil
}

// checkRateLimit checks if the event source is within rate limits
func (ev *EventValidator) checkRateLimit(source string) bool {
	limiter, exists := ev.rateLimiters[source]
	if !exists {
		// Create new rate limiter: 100 events per minute
		limiter = rate.NewLimiter(rate.Every(time.Minute/100), 10)
		ev.rateLimiters[source] = limiter
	}

	return limiter.Allow()
}

// sanitizeString removes potentially dangerous characters
func sanitizeString(s string) string {
	// Remove control characters and normalize whitespace
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")

	// Limit length
	if len(s) > 1000 {
		s = s[:1000] + "..."
	}

	return strings.TrimSpace(s)
}

// contains checks if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
