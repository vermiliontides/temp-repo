// pkg/config/config.go
package config

import (
	"fmt"
	"time"
)

// Config represents the unified enterprise configuration structure
type Config struct {
	// Core System Configuration
	LogLevel string `mapstructure:"log_level"`
	APIPort  string `mapstructure:"api_port"`
	
	// Component Configurations
	Actions         ActionsConfig         `mapstructure:"actions"`
	Monitors        MonitorConfigs        `mapstructure:"monitors"`
	Scheduler       SchedulerConfig       `mapstructure:"scheduler"`
	EventBus        EventBusConfig        `mapstructure:"event_bus"`
	Correlation     CorrelationConfig     `mapstructure:"correlation"`
	MachineLearning MachineLearningConfig `mapstructure:"machine_learning"`
	ThreatIntel     ThreatIntelConfig     `mapstructure:"threat_intelligence"`
	Forensics       ForensicsConfig       `mapstructure:"forensics"`
	Performance     PerformanceConfig     `mapstructure:"performance"`
	ErrorHandling   ErrorHandlingConfig   `mapstructure:"error_handling"`
}

// SchedulerConfig for the enhanced scheduler
type SchedulerConfig struct {
	Enabled                      bool          `mapstructure:"enabled"`
	StartupTimeout               time.Duration `mapstructure:"startup_timeout"`
	ShutdownTimeout              time.Duration `mapstructure:"shutdown_timeout"`
	MonitorRestartDelay          time.Duration `mapstructure:"monitor_restart_delay"`
	MaxRestartAttempts           int           `mapstructure:"max_restart_attempts"`
	HealthCheckEnabled           bool          `mapstructure:"health_check_enabled"`
	HealthCheckInterval          time.Duration `mapstructure:"health_check_interval"`
	UnhealthyThreshold           int           `mapstructure:"unhealthy_threshold"`
	EventPublishingEnabled       bool          `mapstructure:"event_publishing_enabled"`
	EventBufferSize              int           `mapstructure:"event_buffer_size"`
	PerformanceMonitoringEnabled bool          `mapstructure:"performance_monitoring_enabled"`
	MetricsCollectionInterval    time.Duration `mapstructure:"metrics_collection_interval"`
	SlowExecutionThreshold       time.Duration `mapstructure:"slow_execution_threshold"`
	ConcurrentMonitors           int           `mapstructure:"concurrent_monitors"`
	ResourceMonitoringEnabled    bool          `mapstructure:"resource_monitoring_enabled"`
	DebugMode                    bool          `mapstructure:"debug_mode"`
	DefaultMonitorSettings       MonitorDefaults `mapstructure:"default_monitor_settings"`
}

// MonitorDefaults provides default settings for all monitors
type MonitorDefaults struct {
	Timeout       time.Duration `mapstructure:"timeout"`
	MaxMemoryMB   int           `mapstructure:"max_memory_mb"`
	RetryAttempts int           `mapstructure:"retry_attempts"`
}

// MonitorConfigs holds all monitor-specific configurations
type MonitorConfigs struct {
	Sentry   SentryConfig   `mapstructure:"sentry"`
	Sentinel SentinelConfig `mapstructure:"sentinel"`
	Detector DetectorConfig `mapstructure:"detector"`
	Analyzer AnalyzerConfig `mapstructure:"analyzer"`
	Scribe   ScribeConfig   `mapstructure:"scribe"`
	
	// Enhanced unified monitors
	EnhancedSentry   EnhancedSentryConfig   `mapstructure:"enhanced_sentry"`
	EnhancedSentinel EnhancedSentinelConfig `mapstructure:"enhanced_sentinel"`
	EnhancedDetector EnhancedDetectorConfig `mapstructure:"enhanced_detector"`
	EnhancedAnalyzer EnhancedAnalyzerConfig `mapstructure:"enhanced_analyzer"`
	EnhancedScribe   EnhancedScribeConfig   `mapstructure:"enhanced_scribe"`
}

// Enhanced monitor configurations with full BaseMonitor integration
type EnhancedSentryConfig struct {
	BaseMonitorConfig     `mapstructure:",squash"`
	HighValuePaths        []string `mapstructure:"high_value_paths"`
	CriticalProcesses     []string `mapstructure:"critical_processes"`
	ResponseMode          string   `mapstructure:"response_mode"` // monitor, respond, aggressive
	ResponseThreshold     string   `mapstructure:"response_threshold"` // low, medium, high, critical
	IntegrityCheckMode    string   `mapstructure:"integrity_check_mode"` // hash, timestamp, both
	PatrolInterval        string   `mapstructure:"patrol_interval"`
	ThreatAssessment      bool     `mapstructure:"threat_assessment_enabled"`
	NetworkMonitoring     bool     `mapstructure:"network_monitoring_enabled"`
	UploadThresholdMB     int      `mapstructure:"upload_threshold_mb"`
	FileSharingDomains    []string `mapstructure:"file_sharing_domains"`
	RealtimeWatching      bool     `mapstructure:"realtime_watching_enabled"`
	CriticalPaths         string   `mapstructure:"critical_paths"`
	ExcludePaths          string   `mapstructure:"exclude_paths"`
	MonitorHiddenFiles    bool     `mapstructure:"monitor_hidden_files"`
	AlertOnSUIDChanges    bool     `mapstructure:"alert_on_suid_changes"`
	SUIDCheckInterval     int      `mapstructure:"suid_check_interval"`
	SUIDBaselineFile      string   `mapstructure:"suid_baseline_file"`
	ConfigBaselineDir     string   `mapstructure:"config_baseline_dir"`
	RootkitDetection      bool     `mapstructure:"rootkit_detection_enabled"`
	ManualChecks          bool     `mapstructure:"manual_checks_enabled"`
	ChkrootkitEnabled     bool     `mapstructure:"chkrootkit_enabled"`
	RkhunterEnabled       bool     `mapstructure:"rkhunter_enabled"`
	FirmwareMonitoring    bool     `mapstructure:"firmware_monitoring_enabled"`
}

type EnhancedSentinelConfig struct {
	BaseMonitorConfig  `mapstructure:",squash"`
	SystemHealth       bool    `mapstructure:"system_health"`
	ResourceMonitoring bool    `mapstructure:"resource_monitoring"`
	NetworkMonitoring  bool    `mapstructure:"network_monitoring"`
	ProcessMonitoring  bool    `mapstructure:"process_monitoring"`
	CPUThreshold       float64 `mapstructure:"cpu_threshold"`
	MemoryThreshold    float64 `mapstructure:"memory_threshold"`
	DiskThreshold      float64 `mapstructure:"disk_threshold"`
}

type EnhancedDetectorConfig struct {
	BaseMonitorConfig   `mapstructure:",squash"`
	MachineLearning     bool          `mapstructure:"machine_learning"`
	BehaviorAnalysis    bool          `mapstructure:"behavior_analysis"`
	AnomalyThreshold    float64       `mapstructure:"anomaly_threshold"`
	LearningPeriod      time.Duration `mapstructure:"learning_period"`
	ModelUpdateInterval time.Duration `mapstructure:"model_update_interval"`
	FeatureEngineering  bool          `mapstructure:"feature_engineering"`
}

type EnhancedAnalyzerConfig struct {
	BaseMonitorConfig              `mapstructure:",squash"`
	AnalysisInterval               string   `mapstructure:"analysis_interval"`
	EventAnalysisWindow            string   `mapstructure:"event_analysis_window"`
	ThreatScoreThreshold           float64  `mapstructure:"threat_score_threshold"`
	MaxAnalysisDepth               int      `mapstructure:"max_analysis_depth"`
	ThreatCorrelationEnabled       bool     `mapstructure:"threat_correlation_enabled"`
	CorrelationTimeWindow          string   `mapstructure:"correlation_time_window"`
	PatternLearningEnabled         bool     `mapstructure:"pattern_learning_enabled"`
	MinPatternOccurrence           int      `mapstructure:"min_pattern_occurrence"`
	PatternSignificanceScore       float64  `mapstructure:"pattern_significance_score"`
	PatternCategories              []string `mapstructure:"pattern_categories"`
	AnomalyDetectionEnabled        bool     `mapstructure:"anomaly_detection_enabled"`
	AnomalyThreshold               float64  `mapstructure:"anomaly_threshold"`
	BaselineLearningPeriod         string   `mapstructure:"baseline_learning_period"`
	ModelUpdateInterval            string   `mapstructure:"model_update_interval"`
	ContainmentEnabled             bool     `mapstructure:"containment_enabled"`
	AutoContainmentEnabled         bool     `mapstructure:"auto_containment_enabled"`
	ContainmentApprovalRequired    bool     `mapstructure:"containment_approval_required"`
	MaxContainmentActions          int      `mapstructure:"max_containment_actions"`
	HistoricalAnalysisEnabled      bool     `mapstructure:"historical_analysis_enabled"`
	ExternalAIEnabled              bool     `mapstructure:"external_ai_enabled"`
	AIAnalysisEndpoint             string   `mapstructure:"ai_analysis_endpoint"`
	ForensicsIntegration           bool     `mapstructure:"forensics_integration"`
	CorrelationEngine              bool     `mapstructure:"correlation_engine"`
	ThreatIntelligence             bool     `mapstructure:"threat_intelligence"`
	ContainmentStrategies          []string `mapstructure:"containment_strategies"`
	ResponseAutomation             bool     `mapstructure:"response_automation"`
}

type EnhancedScribeConfig struct {
	BaseMonitorConfig `mapstructure:",squash"`
	EvidenceStorage   string   `mapstructure:"evidence_storage"`
	ReportFormats     []string `mapstructure:"report_formats"`
	ChainOfCustody    bool     `mapstructure:"chain_of_custody"`
	DigitalSigning    bool     `mapstructure:"digital_signing"`
	LegalCompliance   []string `mapstructure:"legal_compliance"`
	RetentionDays     int      `mapstructure:"retention_days"`
}

// Legacy monitor configurations for backward compatibility
type SentryConfig struct {
	BaseMonitorConfig `mapstructure:",squash"`
	HighValuePaths    []string `mapstructure:"high_value_paths"`
	CriticalProcesses []string `mapstructure:"critical_processes"`
	ResponseMode      string   `mapstructure:"response_mode"` // monitor, respond, aggressive
}

type SentinelConfig struct {
	BaseMonitorConfig  `mapstructure:",squash"`
	SystemHealth       bool    `mapstructure:"system_health"`
	ResourceMonitoring bool    `mapstructure:"resource_monitoring"`
	NetworkMonitoring  bool    `mapstructure:"network_monitoring"`
	ProcessMonitoring  bool    `mapstructure:"process_monitoring"`
	CPUThreshold       float64 `mapstructure:"cpu_threshold"`
	MemoryThreshold    float64 `mapstructure:"memory_threshold"`
	DiskThreshold      float64 `mapstructure:"disk_threshold"`
}

type DetectorConfig struct {
	BaseMonitorConfig   `mapstructure:",squash"`
	MachineLearning     bool          `mapstructure:"machine_learning"`
	BehaviorAnalysis    bool          `mapstructure:"behavior_analysis"`
	AnomalyThreshold    float64       `mapstructure:"anomaly_threshold"`
	LearningPeriod      time.Duration `mapstructure:"learning_period"`
	ModelUpdateInterval time.Duration `mapstructure:"model_update_interval"`
	FeatureEngineering  bool          `mapstructure:"feature_engineering"`
}

type AnalyzerConfig struct {
	BaseMonitorConfig     `mapstructure:",squash"`
	CorrelationEngine     bool     `mapstructure:"correlation_engine"`
	ThreatIntelligence    bool     `mapstructure:"threat_intelligence"`
	ContainmentStrategies []string `mapstructure:"containment_strategies"`
	ResponseAutomation    bool     `mapstructure:"response_automation"`
}

type ScribeConfig struct {
	BaseMonitorConfig `mapstructure:",squash"`
	EvidenceStorage   string   `mapstructure:"evidence_storage"`
	ReportFormats     []string `mapstructure:"report_formats"`
	ChainOfCustody    bool     `mapstructure:"chain_of_custody"`
	DigitalSigning    bool     `mapstructure:"digital_signing"`
	LegalCompliance   []string `mapstructure:"legal_compliance"`
	RetentionDays     int      `mapstructure:"retention_days"`
}

// BaseMonitorConfig contains common configuration for all monitors
type BaseMonitorConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	Interval       time.Duration `mapstructure:"interval"`
	Actions        []string      `mapstructure:"actions"`
	Priority       int           `mapstructure:"priority"`
	Dependencies   []string      `mapstructure:"dependencies"`
	RestartPolicy  string        `mapstructure:"restart_policy"` // always, on_failure, never
	MaxMemoryMB    int           `mapstructure:"max_memory_mb"`
	Timeout        time.Duration `mapstructure:"timeout"`
	RunInterval    int           `mapstructure:"run_interval"` // Legacy support
}

// MonitorConfig provides legacy support during transition
type MonitorConfig struct {
	Name     string                 `mapstructure:"name"`
	Enabled  bool                   `mapstructure:"enabled"`
	Interval string                 `mapstructure:"interval"`
	Actions  []string               `mapstructure:"actions"`
	Config   map[string]interface{} `mapstructure:"config"`
}

type EventBusConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	BufferSize    int           `mapstructure:"buffer_size"`
	Workers       int           `mapstructure:"workers"`
	PersistEvents bool          `mapstructure:"persist_events"`
	EventTTL      time.Duration `mapstructure:"event_ttl"`
}

type CorrelationConfig struct {
	Enabled     bool              `mapstructure:"enabled"`
	WindowSize  time.Duration     `mapstructure:"window_size"`
	MaxEvents   int               `mapstructure:"max_events"`
	RulesPath   string            `mapstructure:"rules_path"`
	CustomRules []CorrelationRule `mapstructure:"custom_rules"`
}

type CorrelationRule struct {
	ID          string        `mapstructure:"id"`
	Name        string        `mapstructure:"name"`
	EventTypes  []string      `mapstructure:"event_types"`
	TimeWindow  time.Duration `mapstructure:"time_window"`
	Threshold   int           `mapstructure:"threshold"`
	Severity    string        `mapstructure:"severity"`
	Action      string        `mapstructure:"action"`
	Description string        `mapstructure:"description"`
}

type MachineLearningConfig struct {
	Enabled          bool          `mapstructure:"enabled"`
	ModelPath        string        `mapstructure:"model_path"`
	TrainingData     string        `mapstructure:"training_data"`
	UpdateInterval   time.Duration `mapstructure:"update_interval"`
	Algorithms       []string      `mapstructure:"algorithms"`
	AnomalyThreshold float64       `mapstructure:"anomaly_threshold"`
}

type ThreatIntelConfig struct {
	Enabled        bool                `mapstructure:"enabled"`
	Sources        []ThreatIntelSource `mapstructure:"sources"`
	UpdateInterval time.Duration       `mapstructure:"update_interval"`
	CachePath      string              `mapstructure:"cache_path"`
}

type ThreatIntelSource struct {
	Name    string            `mapstructure:"name"`
	URL     string            `mapstructure:"url"`
	Type    string            `mapstructure:"type"` // "json", "csv", "xml"
	Headers map[string]string `mapstructure:"headers"`
	Enabled bool              `mapstructure:"enabled"`
}

type ForensicsConfig struct {
	Enabled         bool     `mapstructure:"enabled"`
	EvidenceStorage string   `mapstructure:"evidence_storage"`
	ChainOfCustody  bool     `mapstructure:"chain_of_custody"`
	DigitalSigning  bool     `mapstructure:"digital_signing"`
	RetentionDays   int      `mapstructure:"retention_days"`
	AutoCapture     bool     `mapstructure:"auto_capture"`
	CaptureFormats  []string `mapstructure:"capture_formats"`
}

type PerformanceConfig struct {
	MaxMemoryMB     int           `mapstructure:"max_memory_mb"`
	MaxCPUPercent   float64       `mapstructure:"max_cpu_percent"`
	MonitorInterval time.Duration `mapstructure:"monitor_interval"`
	OptimizeFor     string        `mapstructure:"optimize_for"` // "speed", "memory", "balanced"
}

type ErrorHandlingConfig struct {
	Enabled              bool          `mapstructure:"enabled"`
	MaxRetries           int           `mapstructure:"max_retries"`
	RetryDelay           time.Duration `mapstructure:"retry_delay"`
	EscalationThreshold  int           `mapstructure:"escalation_threshold"`
	NotificationChannels []string      `mapstructure:"notification_channels"`
	PersistErrors        bool          `mapstructure:"persist_errors"`
	ErrorTTL             time.Duration `mapstructure:"error_ttl"`
}

type ActionsConfig struct {
	Enabled     bool                      `mapstructure:"enabled"`
	Timeout     time.Duration             `mapstructure:"timeout"`
	MaxRetries  int                       `mapstructure:"max_retries"`
	Definitions map[string]ActionDefinition `mapstructure:"definitions"`
}

type ActionDefinition struct {
	Type        string            `mapstructure:"type"`
	Command     string            `mapstructure:"command,omitempty"`
	Args        []string          `mapstructure:"args,omitempty"`
	Environment map[string]string `mapstructure:"environment,omitempty"`
	Timeout     time.Duration     `mapstructure:"timeout,omitempty"`
	RetryCount  int               `mapstructure:"retry_count,omitempty"`
}

// ValidateConfig ensures all configurations are valid
func (c *Config) ValidateConfig() error {
	// Validate scheduler configuration
	if c.Scheduler.Enabled {
		if c.Scheduler.StartupTimeout <= 0 {
			return fmt.Errorf("scheduler startup_timeout must be positive")
		}
		if c.Scheduler.ShutdownTimeout <= 0 {
			return fmt.Errorf("scheduler shutdown_timeout must be positive")
		}
		if c.Scheduler.MaxRestartAttempts < 0 {
			return fmt.Errorf("scheduler max_restart_attempts cannot be negative")
		}
	}

	// Validate monitor configurations
	if err := c.validateMonitorConfigs(); err != nil {
		return fmt.Errorf("monitor configuration validation failed: %w", err)
	}

	// Validate event bus configuration
	if c.EventBus.Enabled && c.EventBus.BufferSize <= 0 {
		return fmt.Errorf("event_bus buffer_size must be positive when enabled")
	}

	return nil
}

func (c *Config) validateMonitorConfigs() error {
	// Validate enhanced monitors
	monitors := []struct {
		name    string
		enabled bool
		config  BaseMonitorConfig
	}{
		{"enhanced_sentry", c.Monitors.EnhancedSentry.Enabled, c.Monitors.EnhancedSentry.BaseMonitorConfig},
		{"enhanced_sentinel", c.Monitors.EnhancedSentinel.Enabled, c.Monitors.EnhancedSentinel.BaseMonitorConfig},
		{"enhanced_detector", c.Monitors.EnhancedDetector.Enabled, c.Monitors.EnhancedDetector.BaseMonitorConfig},
		{"enhanced_analyzer", c.Monitors.EnhancedAnalyzer.Enabled, c.Monitors.EnhancedAnalyzer.BaseMonitorConfig},
		{"enhanced_scribe", c.Monitors.EnhancedScribe.Enabled, c.Monitors.EnhancedScribe.BaseMonitorConfig},
	}

	for _, monitor := range monitors {
		if monitor.enabled {
			if monitor.config.Interval <= 0 {
				return fmt.Errorf("monitor %s interval must be positive", monitor.name)
			}
			if monitor.config.MaxMemoryMB <= 0 {
				return fmt.Errorf("monitor %s max_memory_mb must be positive", monitor.name)
			}
			if monitor.config.Timeout <= 0 {
				return fmt.Errorf("monitor %s timeout must be positive", monitor.name)
			}
		}
	}

	return nil
}

// GetEnabledMonitors returns list of enabled monitor names
func (c *Config) GetEnabledMonitors() []string {
	var enabled []string

	// Enhanced monitors
	if c.Monitors.EnhancedSentry.Enabled {
		enabled = append(enabled, "enhanced_sentry")
	}
	if c.Monitors.EnhancedSentinel.Enabled {
		enabled = append(enabled, "enhanced_sentinel")
	}
	if c.Monitors.EnhancedDetector.Enabled {
		enabled = append(enabled, "enhanced_detector")
	}
	if c.Monitors.EnhancedAnalyzer.Enabled {
		enabled = append(enabled, "enhanced_analyzer")
	}
	if c.Monitors.EnhancedScribe.Enabled {
		enabled = append(enabled, "enhanced_scribe")
	}

	// Legacy monitors for backward compatibility
	if c.Monitors.Sentry.Enabled {
		enabled = append(enabled, "sentry")
	}
	if c.Monitors.Sentinel.Enabled {
		enabled = append(enabled, "sentinel")
	}
	if c.Monitors.Detector.Enabled {
		enabled = append(enabled, "detector")
	}
	if c.Monitors.Analyzer.Enabled {
		enabled = append(enabled, "analyzer")
	}
	if c.Monitors.Scribe.Enabled {
		enabled = append(enabled, "scribe")
	}

	return enabled
}

// GetMonitorConfig returns configuration for a specific monitor by name
func (c *Config) GetMonitorConfig(name string) *MonitorConfig {
	// Convert enhanced monitors to legacy format for scheduler compatibility
	switch name {
	case "enhanced_sentry":
		if c.Monitors.EnhancedSentry.Enabled {
			return &MonitorConfig{
				Name:     name,
				Enabled:  c.Monitors.EnhancedSentry.Enabled,
				Interval: c.Monitors.EnhancedSentry.Interval.String(),
				Actions:  c.Monitors.EnhancedSentry.Actions,
				Config:   c.convertSentryToMap(c.Monitors.EnhancedSentry),
			}
		}
	case "enhanced_analyzer":
		if c.Monitors.EnhancedAnalyzer.Enabled {
			return &MonitorConfig{
				Name:     name,
				Enabled:  c.Monitors.EnhancedAnalyzer.Enabled,
				Interval: c.Monitors.EnhancedAnalyzer.Interval.String(),
				Actions:  c.Monitors.EnhancedAnalyzer.Actions,
				Config:   c.convertAnalyzerToMap(c.Monitors.EnhancedAnalyzer),
			}
		}
	// Add other monitor conversions as needed
	}

	return nil
}

// Helper functions to convert enhanced configs to map[string]interface{}
func (c *Config) convertSentryToMap(config EnhancedSentryConfig) map[string]interface{} {
	return map[string]interface{}{
		"high_value_paths":                config.HighValuePaths,
		"critical_processes":              config.CriticalProcesses,
		"response_mode":                   config.ResponseMode,
		"response_threshold":              config.ResponseThreshold,
		"integrity_check_mode":            config.IntegrityCheckMode,
		"patrol_interval":                 config.PatrolInterval,
		"threat_assessment_enabled":       config.ThreatAssessment,
		"network_monitoring_enabled":      config.NetworkMonitoring,
		"upload_threshold_mb":             config.UploadThresholdMB,
		"file_sharing_domains":            config.FileSharingDomains,
		"realtime_watching_enabled":       config.RealtimeWatching,
		"critical_paths":                  config.CriticalPaths,
		"exclude_paths":                   config.ExcludePaths,
		"monitor_hidden_files":            config.MonitorHiddenFiles,
		"alert_on_suid_changes":           config.AlertOnSUIDChanges,
		"suid_check_interval":             config.SUIDCheckInterval,
		"suid_baseline_file":              config.SUIDBaselineFile,
		"config_baseline_dir":             config.ConfigBaselineDir,
		"rootkit_detection_enabled":       config.RootkitDetection,
		"manual_checks_enabled":           config.ManualChecks,
		"chkrootkit_enabled":              config.ChkrootkitEnabled,
		"rkhunter_enabled":                config.RkhunterEnabled,
		"firmware_monitoring_enabled":     config.FirmwareMonitoring,
		"run_interval":                    config.RunInterval,
	}
}

func (c *Config) convertAnalyzerToMap(config EnhancedAnalyzerConfig) map[string]interface{} {
	return map[string]interface{}{
		"analysis_interval":                config.AnalysisInterval,
		"event_analysis_window":            config.EventAnalysisWindow,
		"threat_score_threshold":           config.ThreatScoreThreshold,
		"max_analysis_depth":               config.MaxAnalysisDepth,
		"threat_correlation_enabled":       config.ThreatCorrelationEnabled,
		"correlation_time_window":          config.CorrelationTimeWindow,
		"pattern_learning_enabled":         config.PatternLearningEnabled,
		"min_pattern_occurrence":           config.MinPatternOccurrence,
		"pattern_significance_score":       config.PatternSignificanceScore,
		"pattern_categories":               config.PatternCategories,
		"anomaly_detection_enabled":        config.AnomalyDetectionEnabled,
		"anomaly_threshold":                config.AnomalyThreshold,
		"baseline_learning_period":         config.BaselineLearningPeriod,
		"model_update_interval":            config.ModelUpdateInterval,
		"containment_enabled":              config.ContainmentEnabled,
		"auto_containment_enabled":         config.AutoContainmentEnabled,
		"containment_approval_required":    config.ContainmentApprovalRequired,
		"max_containment_actions":          config.MaxContainmentActions,
		"historical_analysis_enabled":      config.HistoricalAnalysisEnabled,
		"external_ai_enabled":              config.ExternalAIEnabled,
		"ai_analysis_endpoint":             config.AIAnalysisEndpoint,
		"forensics_integration":            config.ForensicsIntegration,
		"correlation_engine":               config.CorrelationEngine,
		"threat_intelligence":              config.ThreatIntelligence,
		"containment_strategies":           config.ContainmentStrategies,
		"response_automation":              config.ResponseAutomation,
		"run_interval":                     config.RunInterval,
	}
}