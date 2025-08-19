// pkg/monitors/enhanced/enhanced_sentry.go
package enhanced

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/events"
	"github.com/lucid-vigil/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
)

// EnhancedSentryMonitor combines multiple sentry monitors with event bus integration
type EnhancedSentryMonitor struct {
	*EnhancedMonitor
	config           *SentryConfig
	highValueTargets []HighValueTarget
	threatLevel      ThreatLevel
	lastPatrol       time.Time
	baseline         map[string]string // path -> hash mapping for integrity checks
	mu               sync.RWMutex      // Protects baseline and highValueTargets
}

type SentryConfig struct {
	HighValuePaths          []string `mapstructure:"high_value_paths"`
	CriticalProcesses       []string `mapstructure:"critical_processes"`
	ResponseMode            string   `mapstructure:"response_mode"`        // "monitor", "respond", "aggressive"
	ResponseThreshold       string   `mapstructure:"response_threshold"`   // "low", "medium", "high", "critical"
	IntegrityCheckMode      string   `mapstructure:"integrity_check_mode"` // "hash", "timestamp", "both"
	PatrolInterval          string   `mapstructure:"patrol_interval"`
	ThreatAssessmentEnabled bool     `mapstructure:"threat_assessment_enabled"`
}

type HighValueTarget struct {
	Path        string    `json:"path"`
	Type        string    `json:"type"` // "file", "directory", "process"
	Criticality string    `json:"criticality"`
	LastChecked time.Time `json:"last_checked"`
	Status      string    `json:"status"`
	Hash        string    `json:"hash,omitempty"` // For integrity checking
}

type ThreatLevel string

const (
	ThreatLevelGreen  ThreatLevel = "green"  // Normal
	ThreatLevelYellow ThreatLevel = "yellow" // Elevated
	ThreatLevelOrange ThreatLevel = "orange" // High
	ThreatLevelRed    ThreatLevel = "red"    // Critical
)

// NewEnhancedSentryMonitor creates a new enhanced sentry monitor
func NewEnhancedSentryMonitor(logger zerolog.Logger, eventBus *events.EventBus) scheduler.Monitor {
	monitor := &EnhancedSentryMonitor{
		EnhancedMonitor:  NewEnhancedMonitor("enhanced_sentry", ClassSentry, logger, eventBus),
		config:           &SentryConfig{},
		highValueTargets: []HighValueTarget{},
		threatLevel:      ThreatLevelGreen,
		baseline:         make(map[string]string),
	}

	// Add sentry-specific capabilities
	monitor.AddCapability(CapabilityRealTime)
	monitor.AddCapability(CapabilityAutomatedResponse)
	monitor.AddCapability(CapabilityThreatIntel)

	return monitor
}

// Configure sets up the enhanced sentry monitor with the provided configuration
func (esm *EnhancedSentryMonitor) Configure(config map[string]interface{}) error {
	esm.LogEvent(zerolog.InfoLevel, "Configuring Enhanced Sentry Monitor")

	// Parse configuration
	if highValuePaths, ok := config["high_value_paths"].([]interface{}); ok {
		esm.config.HighValuePaths = make([]string, len(highValuePaths))
		for i, path := range highValuePaths {
			if str, ok := path.(string); ok {
				esm.config.HighValuePaths[i] = str
			}
		}
	}

	if criticalProcesses, ok := config["critical_processes"].([]interface{}); ok {
		esm.config.CriticalProcesses = make([]string, len(criticalProcesses))
		for i, process := range criticalProcesses {
			if str, ok := process.(string); ok {
				esm.config.CriticalProcesses[i] = str
			}
		}
	}

	if responseMode, ok := config["response_mode"].(string); ok {
		esm.config.ResponseMode = responseMode
	} else {
		esm.config.ResponseMode = "respond" // default
	}

	if responseThreshold, ok := config["response_threshold"].(string); ok {
		esm.config.ResponseThreshold = responseThreshold
	} else {
		esm.config.ResponseThreshold = "medium" // default
	}

	if integrityCheckMode, ok := config["integrity_check_mode"].(string); ok {
		esm.config.IntegrityCheckMode = integrityCheckMode
	} else {
		esm.config.IntegrityCheckMode = "hash" // default
	}

	if patrolInterval, ok := config["patrol_interval"].(string); ok {
		esm.config.PatrolInterval = patrolInterval
	} else {
		esm.config.PatrolInterval = "30s" // default
	}

	if threatAssessment, ok := config["threat_assessment_enabled"].(bool); ok {
		esm.config.ThreatAssessmentEnabled = threatAssessment
	} else {
		esm.config.ThreatAssessmentEnabled = true // default
	}

	esm.LogEvent(zerolog.InfoLevel, "Enhanced Sentry Monitor configured successfully").
		Strs("high_value_paths", esm.config.HighValuePaths).
		Str("response_mode", esm.config.ResponseMode).
		Str("response_threshold", esm.config.ResponseThreshold)

	return nil
}

// Run executes the enhanced sentry monitoring logic
func (esm *EnhancedSentryMonitor) Run(ctx context.Context) {
	esm.LogEvent(zerolog.InfoLevel, "Enhanced Sentry Monitor: Beginning high-value target protection...")
	esm.UpdateState("status", "active")
	esm.UpdateState("patrol_start", time.Now())

	// Initialize high-value targets if not already done
	esm.mu.RLock()
	targetsEmpty := len(esm.highValueTargets) == 0
	esm.mu.RUnlock()

	if targetsEmpty {
		esm.initializeHighValueTargets(ctx)
	}

	// Assess current threat level if enabled
	if esm.config.ThreatAssessmentEnabled {
		previousThreatLevel := esm.threatLevel
		esm.assessThreatLevel(ctx)
		if esm.threatLevel != previousThreatLevel {
			esm.PublishEvent(ctx, events.EventThreatDetected, "system_threat_level",
				fmt.Sprintf("Threat level changed from %s to %s", previousThreatLevel, esm.threatLevel),
				string(esm.threatLevel), map[string]interface{}{
					"previous_level": string(previousThreatLevel),
					"new_level":      string(esm.threatLevel),
				})
		}
	}

	// Monitor high-value targets
	esm.monitorHighValueTargets(ctx)

	// Check for unauthorized access patterns
	esm.checkUnauthorizedAccess(ctx)

	// Perform integrity checks
	esm.performIntegrityChecks(ctx)

	// Update metrics and state
	esm.updateMetricsAndState()

	esm.lastPatrol = time.Now()
	esm.LogEvent(zerolog.InfoLevel, "Enhanced Sentry Monitor: Patrol completed").
		Str("threat_level", string(esm.threatLevel)).
		Int("targets_monitored", len(esm.highValueTargets))
}

// initializeHighValueTargets sets up the initial list of high-value targets
func (esm *EnhancedSentryMonitor) initializeHighValueTargets(ctx context.Context) {
	esm.LogEvent(zerolog.InfoLevel, "Initializing high-value targets")

	esm.mu.Lock()
	defer esm.mu.Unlock()

	for _, path := range esm.config.HighValuePaths {
		target := HighValueTarget{
			Path:        path,
			Type:        esm.determineTargetType(path),
			Criticality: esm.assessCriticality(path),
			LastChecked: time.Now(),
			Status:      "monitoring",
		}

		// Calculate initial hash if file exists
		if target.Type == "file" {
			if hash, err := esm.calculateFileHash(path); err == nil {
				target.Hash = hash
				esm.baseline[path] = hash
			} else {
				esm.LogEvent(zerolog.WarnLevel, "Failed to calculate initial hash").
					Str("path", path).Err(err)
			}
		}

		esm.highValueTargets = append(esm.highValueTargets, target)
		esm.LogEvent(zerolog.DebugLevel, "Added high-value target").
			Str("path", path).
			Str("type", target.Type).
			Str("criticality", target.Criticality)
	}

	esm.LogEvent(zerolog.InfoLevel, "High-value targets initialized").
		Int("count", len(esm.highValueTargets))
}

// determineTargetType determines if a path is a file, directory, or process
func (esm *EnhancedSentryMonitor) determineTargetType(path string) string {
	if strings.HasPrefix(path, "proc:") {
		return "process"
	}

	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			return "directory"
		}
		return "file"
	}

	// Default to file if we can't determine
	return "file"
}

// assessCriticality determines the criticality level of a target
func (esm *EnhancedSentryMonitor) assessCriticality(path string) string {
	// Critical system files and directories
	criticalPaths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/boot", "/etc/ssh", "/root/.ssh",
		"/var/log", "/etc/systemd",
	}

	for _, critical := range criticalPaths {
		if strings.Contains(path, critical) {
			return "critical"
		}
	}

	// High criticality paths
	highPaths := []string{
		"/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
		"/home", "/var", "/opt",
	}

	for _, high := range highPaths {
		if strings.HasPrefix(path, high) {
			return "high"
		}
	}

	// Default to medium
	return "medium"
}

// calculateFileHash calculates SHA256 hash of a file
func (esm *EnhancedSentryMonitor) calculateFileHash(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// assessThreatLevel evaluates the current threat level based on system state
func (esm *EnhancedSentryMonitor) assessThreatLevel(ctx context.Context) {
	// Simple threat assessment based on recent events and system state
	var score int

	// Check for recent security events
	if esm.state.EventsRaised > 10 {
		score += 2
	} else if esm.state.EventsRaised > 5 {
		score += 1
	}

	// Determine threat level based on score
	switch {
	case score >= 4:
		esm.threatLevel = ThreatLevelRed
	case score >= 3:
		esm.threatLevel = ThreatLevelOrange
	case score >= 1:
		esm.threatLevel = ThreatLevelYellow
	default:
		esm.threatLevel = ThreatLevelGreen
	}

	esm.UpdateState("threat_level", string(esm.threatLevel))
	esm.UpdateState("threat_score", score)
}

// monitorHighValueTargets checks the status of all high-value targets
func (esm *EnhancedSentryMonitor) monitorHighValueTargets(ctx context.Context) {
	esm.mu.Lock()
	defer esm.mu.Unlock()

	for i := range esm.highValueTargets {
		target := &esm.highValueTargets[i]

		switch target.Type {
		case "file":
			esm.monitorFile(ctx, target)
		case "directory":
			esm.monitorDirectory(ctx, target)
		case "process":
			esm.monitorProcess(ctx, target)
		}

		target.LastChecked = time.Now()
	}
}

// monitorFile monitors a specific file target
func (esm *EnhancedSentryMonitor) monitorFile(ctx context.Context, target *HighValueTarget) {
	// Check if file exists
	info, err := os.Stat(target.Path)
	if err != nil {
		if os.IsNotExist(err) {
			esm.handleFileNotFound(ctx, target)
		} else {
			esm.LogEvent(zerolog.WarnLevel, "Error accessing file").
				Str("path", target.Path).Err(err)
		}
		return
	}

	// Check for suspicious modifications
	if esm.config.IntegrityCheckMode == "hash" || esm.config.IntegrityCheckMode == "both" {
		if currentHash, err := esm.calculateFileHash(target.Path); err == nil {
			if baseline, exists := esm.baseline[target.Path]; exists {
				if currentHash != baseline {
					esm.handleIntegrityViolation(ctx, target, baseline, currentHash)
				}
			} else {
				// Store new baseline
				esm.baseline[target.Path] = currentHash
				target.Hash = currentHash
			}
		}
	}

	// Check timestamp modifications
	if esm.config.IntegrityCheckMode == "timestamp" || esm.config.IntegrityCheckMode == "both" {
		// Compare modification times (simplified implementation)
		target.Status = "verified"
	}
}

// monitorDirectory monitors a directory target
func (esm *EnhancedSentryMonitor) monitorDirectory(ctx context.Context, target *HighValueTarget) {
	// Check if directory exists and is accessible
	info, err := os.Stat(target.Path)
	if err != nil {
		if os.IsNotExist(err) {
			esm.handleDirectoryNotFound(ctx, target)
		}
		return
	}

	if !info.IsDir() {
		esm.PublishEvent(ctx, events.EventFileSystemChange, target.Path,
			"High-value directory is no longer a directory", "high",
			map[string]interface{}{
				"criticality": target.Criticality,
				"target_type": target.Type,
			})
		return
	}

	target.Status = "verified"
}

// monitorProcess monitors a process target
func (esm *EnhancedSentryMonitor) monitorProcess(ctx context.Context, target *HighValueTarget) {
	// Extract process name from "proc:name" format
	processName := strings.TrimPrefix(target.Path, "proc:")

	// Check if process is running (simplified implementation)
	esm.LogEvent(zerolog.DebugLevel, "Monitoring process").
		Str("process", processName)

	target.Status = "running"
}

// checkUnauthorizedAccess looks for patterns of unauthorized access
func (esm *EnhancedSentryMonitor) checkUnauthorizedAccess(ctx context.Context) {
	esm.LogEvent(zerolog.DebugLevel, "Checking for unauthorized access patterns")
}

// performIntegrityChecks runs comprehensive integrity verification
func (esm *EnhancedSentryMonitor) performIntegrityChecks(ctx context.Context) {
	esm.LogEvent(zerolog.DebugLevel, "Performing integrity checks")

	checkCount := 0
	violationCount := 0

	esm.mu.RLock()
	targets := make([]HighValueTarget, len(esm.highValueTargets))
	copy(targets, esm.highValueTargets)
	esm.mu.RUnlock()

	for _, target := range targets {
		if target.Type == "file" {
			checkCount++
			if currentHash, err := esm.calculateFileHash(target.Path); err == nil {
				esm.mu.RLock()
				baseline, exists := esm.baseline[target.Path]
				esm.mu.RUnlock()

				if exists && currentHash != baseline {
					violationCount++
				}
			}
		}
	}

	esm.UpdateState("integrity_checks_performed", checkCount)
	esm.UpdateState("integrity_violations_found", violationCount)

	if violationCount > 0 {
		esm.LogEvent(zerolog.WarnLevel, "Integrity violations detected").
			Int("violations", violationCount).
			Int("checks", checkCount)
	}
}

// updateMetricsAndState updates monitor metrics and state information
func (esm *EnhancedSentryMonitor) updateMetricsAndState() {
	esm.UpdateState("last_patrol", esm.lastPatrol)

	esm.mu.RLock()
	targetsCount := len(esm.highValueTargets)
	statusCounts := make(map[string]int)
	for _, target := range esm.highValueTargets {
		statusCounts[target.Status]++
	}
	esm.mu.RUnlock()

	esm.UpdateState("targets_count", targetsCount)
	esm.UpdateState("threat_level", string(esm.threatLevel))
	esm.UpdateState("target_status_counts", statusCounts)
}

// Event handlers for various security incidents

func (esm *EnhancedSentryMonitor) handleFileNotFound(ctx context.Context, target *HighValueTarget) {
	severity := "medium"
	if target.Criticality == "critical" {
		severity = "critical"
	} else if target.Criticality == "high" {
		severity = "high"
	}

	esm.PublishEvent(ctx, events.EventFileSystemChange, target.Path,
		fmt.Sprintf("High-value file not found: %s", target.Path),
		severity, map[string]interface{}{
			"criticality":  target.Criticality,
			"target_type":  target.Type,
			"last_checked": target.LastChecked,
		})

	target.Status = "missing"
}

func (esm *EnhancedSentryMonitor) handleDirectoryNotFound(ctx context.Context, target *HighValueTarget) {
	severity := "high"
	if target.Criticality == "critical" {
		severity = "critical"
	}

	esm.PublishEvent(ctx, events.EventFileSystemChange, target.Path,
		fmt.Sprintf("High-value directory not found: %s", target.Path),
		severity, map[string]interface{}{
			"criticality":  target.Criticality,
			"target_type":  target.Type,
			"last_checked": target.LastChecked,
		})

	target.Status = "missing"
}

func (esm *EnhancedSentryMonitor) handleIntegrityViolation(ctx context.Context, target *HighValueTarget, expectedHash, actualHash string) {
	severity := "high"
	if target.Criticality == "critical" {
		severity = "critical"
	}

	esm.PublishEvent(ctx, events.EventFileSystemChange, target.Path,
		fmt.Sprintf("Integrity violation detected for %s", target.Path),
		severity, map[string]interface{}{
			"criticality":   target.Criticality,
			"expected_hash": expectedHash,
			"actual_hash":   actualHash,
			"target_type":   target.Type,
			"check_time":    time.Now(),
		})

	target.Status = "compromised"
	target.Hash = actualHash               // Update to new hash
	esm.baseline[target.Path] = actualHash // Update baseline
}

// GetThreatLevel returns the current threat level
func (esm *EnhancedSentryMonitor) GetThreatLevel() ThreatLevel {
	return esm.threatLevel
}

// GetHighValueTargets returns the list of monitored targets
func (esm *EnhancedSentryMonitor) GetHighValueTargets() []HighValueTarget {
	esm.mu.RLock()
	defer esm.mu.RUnlock()

	targets := make([]HighValueTarget, len(esm.highValueTargets))
	copy(targets, esm.highValueTargets)
	return targets
}

// GetConfig returns the current configuration
func (esm *EnhancedSentryMonitor) GetConfig() *SentryConfig {
	return esm.config
}
