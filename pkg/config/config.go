// pkg/config/monitor_configs.go
package config

import "time"

// MonitorConfigs holds all monitor-specific configurations
type MonitorConfigs struct {
	Sentry   SentryConfig   `mapstructure:"sentry"`
	Sentinel SentinelConfig `mapstructure:"sentinel"`
	Detector DetectorConfig `mapstructure:"detector"`
	Analyzer AnalyzerConfig `mapstructure:"analyzer"`
	Scribe   ScribeConfig   `mapstructure:"scribe"`
}

// SentryConfig for high-value target protection
type SentryConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	Interval          time.Duration `mapstructure:"interval"`
	HighValuePaths    []string      `mapstructure:"high_value_paths"`
	CriticalProcesses []string      `mapstructure:"critical_processes"`
	ResponseMode      string        `mapstructure:"response_mode"` // monitor, respond, aggressive
	Actions           []string      `mapstructure:"actions"`
}

// SentinelConfig for system-wide monitoring
type SentinelConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	Interval           time.Duration `mapstructure:"interval"`
	SystemHealth       bool          `mapstructure:"system_health"`
	ResourceMonitoring bool          `mapstructure:"resource_monitoring"`
	NetworkMonitoring  bool          `mapstructure:"network_monitoring"`
	ProcessMonitoring  bool          `mapstructure:"process_monitoring"`
	CPUThreshold       float64       `mapstructure:"cpu_threshold"`
	MemoryThreshold    float64       `mapstructure:"memory_threshold"`
	DiskThreshold      float64       `mapstructure:"disk_threshold"`
	Actions            []string      `mapstructure:"actions"`
}

// DetectorConfig for ML-based detection
type DetectorConfig struct {
	Enabled             bool          `mapstructure:"enabled"`
	Interval            time.Duration `mapstructure:"interval"`
	MachineLearning     bool          `mapstructure:"machine_learning"`
	BehaviorAnalysis    bool          `mapstructure:"behavior_analysis"`
	AnomalyThreshold    float64       `mapstructure:"anomaly_threshold"`
	LearningPeriod      time.Duration `mapstructure:"learning_period"`
	ModelUpdateInterval time.Duration `mapstructure:"model_update_interval"`
	FeatureEngineering  bool          `mapstructure:"feature_engineering"`
	Actions             []string      `mapstructure:"actions"`
}

// AnalyzerConfig for incident analysis
type AnalyzerConfig struct {
	Enabled               bool          `mapstructure:"enabled"`
	Interval              time.Duration `mapstructure:"interval"`
	CorrelationEngine     bool          `mapstructure:"correlation_engine"`
	ThreatIntelligence    bool          `mapstructure:"threat_intelligence"`
	ContainmentStrategies []string      `mapstructure:"containment_strategies"`
	ResponseAutomation    bool          `mapstructure:"response_automation"`
	Actions               []string      `mapstructure:"actions"`
}

// ScribeConfig for forensic documentation
type ScribeConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	Interval        time.Duration `mapstructure:"interval"`
	EvidenceStorage string        `mapstructure:"evidence_storage"`
	ReportFormats   []string      `mapstructure:"report_formats"`
	ChainOfCustody  bool          `mapstructure:"chain_of_custody"`
	DigitalSigning  bool          `mapstructure:"digital_signing"`
	LegalCompliance []string      `mapstructure:"legal_compliance"`
	RetentionDays   int           `mapstructure:"retention_days"`
	Actions         []string      `mapstructure:"actions"`
}

// Enhanced main config to include monitor configs
type Config struct {
	LogLevel string         `mapstructure:"log_level"`
	APIPort  string         `mapstructure:"api_port"`
	Actions  ActionsConfig  `mapstructure:"actions"`
	Monitors MonitorConfigs `mapstructure:"monitors"`

	// Legacy support during transition
	LegacyMonitors []MonitorConfig `mapstructure:"legacy_monitors,omitempty"`
}

// ValidateConfig ensures all configurations are valid
func (c *Config) ValidateConfig() error {
	// Add validation logic here
	return nil
}

// GetEnabledMonitors returns list of enabled monitor names
func (c *Config) GetEnabledMonitors() []string {
	var enabled []string

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
