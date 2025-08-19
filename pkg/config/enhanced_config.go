// pkg/config/enhanced_config.go
package config

import (
	"time"
)

// EnhancedConfig represents the enterprise configuration structure
type EnhancedConfig struct {
	*Config // Embed existing config

	// Enterprise features
	EventBus        EventBusConfig        `mapstructure:"event_bus"`
	Correlation     CorrelationConfig     `mapstructure:"correlation"`
	MachineLearning MachineLearningConfig `mapstructure:"machine_learning"`
	ThreatIntel     ThreatIntelConfig     `mapstructure:"threat_intelligence"`
	Forensics       ForensicsConfig       `mapstructure:"forensics"`
	Performance     PerformanceConfig     `mapstructure:"performance"`
	//Enterprise      EnterpriseConfig      `mapstructure:"enterprise"`
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

// type EnterpriseConfig struct {
// 	DeploymentMode  string            `mapstructure:"deployment_mode"` // "standalone", "cluster", "cloud"
// 	ClusterNodes    []string          `mapstructure:"cluster_nodes"`
// 	LoadBalancer    LoadBalancerConfig `mapstructure:"load_balancer"`
// 	HighAvailability HAConfig         `mapstructure:"high_availability"`
// 	Scaling         ScalingConfig     `mapstructure:"scaling"`
// }

// type LoadBalancerConfig struct {
// }
