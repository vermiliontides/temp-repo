// pkg/errors/monitor_errors.go
package errors

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
)

// MonitorError represents a structured error from a monitor
type MonitorError struct {
	MonitorName string                 `json:"monitor_name"`
	ErrorType   string                 `json:"error_type"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    Severity               `json:"severity"`
	Recoverable bool                   `json:"recoverable"`
	Cause       error                  `json:"-"`
}

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Error implements the error interface
func (me *MonitorError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", me.MonitorName, me.ErrorType, me.Message)
}

// Unwrap returns the underlying cause
func (me *MonitorError) Unwrap() error {
	return me.Cause
}

// ErrorHandler manages monitor errors
type ErrorHandler struct {
	logger    zerolog.Logger
	collector ErrorCollector
}

// ErrorCollector defines how errors are collected and reported
type ErrorCollector interface {
	CollectError(ctx context.Context, err *MonitorError) error
	GetErrorStats() ErrorStats
}

type ErrorStats struct {
	TotalErrors      int              `json:"total_errors"`
	ErrorsByType     map[string]int   `json:"errors_by_type"`
	ErrorsByMonitor  map[string]int   `json:"errors_by_monitor"`
	ErrorsBySeverity map[Severity]int `json:"errors_by_severity"`
	LastError        *MonitorError    `json:"last_error,omitempty"`
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger zerolog.Logger, collector ErrorCollector) *ErrorHandler {
	return &ErrorHandler{
		logger:    logger,
		collector: collector,
	}
}

// HandleError processes and reports a monitor error
func (eh *ErrorHandler) HandleError(ctx context.Context, err *MonitorError) error {
	// Log the error with appropriate level
	logEvent := eh.getLogEvent(err.Severity).
		Str("monitor", err.MonitorName).
		Str("error_type", err.ErrorType).
		Str("message", err.Message).
		Bool("recoverable", err.Recoverable)

	if err.Details != nil {
		logEvent = logEvent.Interface("details", err.Details)
	}

	if err.Cause != nil {
		logEvent = logEvent.AnErr("cause", err.Cause)
	}

	logEvent.Msg("Monitor error occurred")

	// Collect error for statistics and alerting
	if eh.collector != nil {
		return eh.collector.CollectError(ctx, err)
	}

	return nil
}

// getLogEvent returns the appropriate zerolog event for severity
func (eh *ErrorHandler) getLogEvent(severity Severity) *zerolog.Event {
	switch severity {
	case SeverityCritical:
		return eh.logger.Fatal()
	case SeverityHigh:
		return eh.logger.Error()
	case SeverityMedium:
		return eh.logger.Warn()
	case SeverityLow:
		return eh.logger.Info()
	case SeverityInfo:
		return eh.logger.Debug()
	default:
		return eh.logger.Info()
	}
}

// Helper functions for creating common error types

func NewConfigError(monitorName string, cause error, details map[string]interface{}) *MonitorError {
	return &MonitorError{
		MonitorName: monitorName,
		ErrorType:   "configuration",
		Message:     "Configuration error occurred",
		Details:     details,
		Timestamp:   time.Now(),
		Severity:    SeverityHigh,
		Recoverable: true,
		Cause:       cause,
	}
}

func NewPermissionError(monitorName string, operation string, cause error) *MonitorError {
	return &MonitorError{
		MonitorName: monitorName,
		ErrorType:   "permission",
		Message:     fmt.Sprintf("Permission denied for operation: %s", operation),
		Details: map[string]interface{}{
			"operation": operation,
		},
		Timestamp:   time.Now(),
		Severity:    SeverityHigh,
		Recoverable: false,
		Cause:       cause,
	}
}

func NewResourceError(monitorName string, resource string, cause error) *MonitorError {
	return &MonitorError{
		MonitorName: monitorName,
		ErrorType:   "resource",
		Message:     fmt.Sprintf("Resource unavailable: %s", resource),
		Details: map[string]interface{}{
			"resource": resource,
		},
		Timestamp:   time.Now(),
		Severity:    SeverityMedium,
		Recoverable: true,
		Cause:       cause,
	}
}

func NewDetectionError(monitorName string, detectionType string, cause error) *MonitorError {
	return &MonitorError{
		MonitorName: monitorName,
		ErrorType:   "detection",
		Message:     fmt.Sprintf("Detection failed: %s", detectionType),
		Details: map[string]interface{}{
			"detection_type": detectionType,
		},
		Timestamp:   time.Now(),
		Severity:    SeverityMedium,
		Recoverable: true,
		Cause:       cause,
	}
}
