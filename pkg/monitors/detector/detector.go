// Detector Monitor - Comprehensive behavior analysis and anomaly detection system
// Combines functionality from behavior_monitor.go and provides foundation for ML/AI features
package monitors

import (
	"bufio"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/events"
	"github.com/lucid-vigil/sentinel/pkg/monitors/base_monitor"
	"github.com/lucid-vigil/sentinel/pkg/monitors/scheduler"
	"github.com/rs/zerolog"
	psutil "github.com/shirou/gopsutil/v3/process"
)

// DetectorMonitor - Advanced behavior analysis and anomaly detection system
type DetectorMonitor struct {
	*base_monitor.BaseMonitor
	config            *ComprehensiveDetectorConfig
	behaviorBaselines map[string]*BehaviorBaseline
	systemBaselines   map[string]*SystemBaseline
	anomalyThresholds *AnomalyThresholds
	detectionRules    []DetectionRule
	learningMode      bool
	lastAnalysis      time.Time

	// Machine Learning preparation structures
	featureVectors []FeatureVector
	clusterCenters []FeatureVector
	anomalyScores  map[string]float64

	// Behavioral analysis components
	commandPatterns    map[string]*CommandPattern
	processPatterns    map[string]*ProcessPattern
	networkPatterns    map[string]*NetworkPattern
	fileAccessPatterns map[string]*FileAccessPattern

	// Real-time monitoring
	processCache    map[int32]*ProcessInfo
	networkCache    map[string]*NetworkConnection
	fileAccessCache map[string]*FileAccess

	// Synchronization
	mu         sync.RWMutex
	baselineMu sync.RWMutex
	running    bool
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	ticker     *time.Ticker
}

// ComprehensiveDetectorConfig - Configuration for all detection capabilities
type ComprehensiveDetectorConfig struct {
	// Core detector configuration
	LearningPeriodDays  int      `mapstructure:"learning_period_days"`
	AnomalyThreshold    float64  `mapstructure:"anomaly_threshold"`
	BehaviorRules       []string `mapstructure:"behavior_rules"`
	SuspiciousCommands  []string `mapstructure:"suspicious_commands"`
	SuspiciousProcesses []string `mapstructure:"suspicious_processes"`

	// Machine learning configuration
	EnableMLBaselines bool `mapstructure:"enable_ml_baselines"`
	ClusteringEnabled bool `mapstructure:"clustering_enabled"`
	MinClusterSize    int  `mapstructure:"min_cluster_size"`
	MaxClusters       int  `mapstructure:"max_clusters"`
	FeatureWindowSize int  `mapstructure:"feature_window_size"`

	// Behavior analysis configuration
	MonitorCommandHistory  bool `mapstructure:"monitor_command_history"`
	MonitorProcessBehavior bool `mapstructure:"monitor_process_behavior"`
	MonitorNetworkBehavior bool `mapstructure:"monitor_network_behavior"`
	MonitorFileAccess      bool `mapstructure:"monitor_file_access"`

	// Analysis intervals
	RealTimeAnalysisEnabled bool   `mapstructure:"realtime_analysis_enabled"`
	BaselineUpdateInterval  string `mapstructure:"baseline_update_interval"`
	AnomalyCheckInterval    string `mapstructure:"anomaly_check_interval"`

	// Data retention
	MaxHistoryDays      int    `mapstructure:"max_history_days"`
	BaselineStoragePath string `mapstructure:"baseline_storage_path"`
	FeatureStoragePath  string `mapstructure:"feature_storage_path"`

	// Advanced detection
	EnableSequenceDetection   bool `mapstructure:"enable_sequence_detection"`
	EnableTimeSeriesAnalysis  bool `mapstructure:"enable_timeseries_analysis"`
	EnableCorrelationAnalysis bool `mapstructure:"enable_correlation_analysis"`
}

// Data structures for behavior baselines and anomaly detection
type BehaviorBaseline struct {
	Type             string                 `json:"type"`
	CreatedAt        time.Time              `json:"created_at"`
	LastUpdated      time.Time              `json:"last_updated"`
	SampleCount      int                    `json:"sample_count"`
	Patterns         map[string]int         `json:"patterns"`
	FrequencyStats   *FrequencyStats        `json:"frequency_stats"`
	TimeDistribution map[int]int            `json:"time_distribution"` // hour -> count
	Confidence       float64                `json:"confidence"`
	Metadata         map[string]interface{} `json:"metadata"`
}

type SystemBaseline struct {
	Type            string             `json:"type"`
	CreatedAt       time.Time          `json:"created_at"`
	LastUpdated     time.Time          `json:"last_updated"`
	Metrics         map[string]float64 `json:"metrics"`
	StatisticalData *StatisticalData   `json:"statistical_data"`
	TrendAnalysis   *TrendAnalysis     `json:"trend_analysis"`
	Confidence      float64            `json:"confidence"`
}

type FrequencyStats struct {
	Mean         float64 `json:"mean"`
	StdDev       float64 `json:"std_dev"`
	Min          float64 `json:"min"`
	Max          float64 `json:"max"`
	Median       float64 `json:"median"`
	Percentile95 float64 `json:"percentile_95"`
}

type StatisticalData struct {
	Mean      float64    `json:"mean"`
	StdDev    float64    `json:"std_dev"`
	Variance  float64    `json:"variance"`
	Skewness  float64    `json:"skewness"`
	Kurtosis  float64    `json:"kurtosis"`
	Quartiles [4]float64 `json:"quartiles"`
	Outliers  []float64  `json:"outliers"`
}

type TrendAnalysis struct {
	Slope       float64   `json:"slope"`
	Intercept   float64   `json:"intercept"`
	Correlation float64   `json:"correlation"`
	Seasonality []float64 `json:"seasonality"`
	Forecast    []float64 `json:"forecast"`
}

type AnomalyThresholds struct {
	CommandFrequency  float64 `json:"command_frequency"`
	ProcessBehavior   float64 `json:"process_behavior"`
	NetworkActivity   float64 `json:"network_activity"`
	FileAccess        float64 `json:"file_access"`
	SystemMetrics     float64 `json:"system_metrics"`
	SequenceAnomalies float64 `json:"sequence_anomalies"`
}

type DetectionRule struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Pattern         string            `json:"pattern"`
	Condition       string            `json:"condition"`
	Severity        string            `json:"severity"`
	Description     string            `json:"description"`
	Enabled         bool              `json:"enabled"`
	Metadata        map[string]string `json:"metadata"`
	CompiledPattern *regexp.Regexp    `json:"-"`
}

// Feature vector for machine learning preparation
type FeatureVector struct {
	Timestamp    time.Time              `json:"timestamp"`
	Features     map[string]float64     `json:"features"`
	Label        string                 `json:"label"`
	AnomalyScore float64                `json:"anomaly_score"`
	ClusterID    int                    `json:"cluster_id"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Behavioral pattern structures
type CommandPattern struct {
	Command          string         `json:"command"`
	Frequency        int            `json:"frequency"`
	AvgExecutionTime float64        `json:"avg_execution_time"`
	TimeDistribution map[int]int    `json:"time_distribution"`
	Arguments        map[string]int `json:"arguments"`
	ExitCodes        map[int]int    `json:"exit_codes"`
	AssociatedFiles  map[string]int `json:"associated_files"`
	LastSeen         time.Time      `json:"last_seen"`
}

type ProcessPattern struct {
	ProcessName        string         `json:"process_name"`
	PID                int32          `json:"pid"`
	PPID               int32          `json:"ppid"`
	Command            string         `json:"command"`
	User               string         `json:"user"`
	StartTime          time.Time      `json:"start_time"`
	CPUPercent         float64        `json:"cpu_percent"`
	MemoryPercent      float64        `json:"memory_percent"`
	OpenFiles          int            `json:"open_files"`
	NetworkConnections int            `json:"network_connections"`
	ChildProcesses     []int32        `json:"child_processes"`
	Behavior           map[string]int `json:"behavior"`
	LastSeen           time.Time      `json:"last_seen"`
}

type NetworkPattern struct {
	LocalIP        string    `json:"local_ip"`
	LocalPort      uint32    `json:"local_port"`
	RemoteIP       string    `json:"remote_ip"`
	RemotePort     uint32    `json:"remote_port"`
	Protocol       string    `json:"protocol"`
	State          string    `json:"state"`
	PID            int32     `json:"pid"`
	ProcessName    string    `json:"process_name"`
	BytesSent      uint64    `json:"bytes_sent"`
	BytesRecv      uint64    `json:"bytes_recv"`
	ConnectionTime time.Time `json:"connection_time"`
	LastActivity   time.Time `json:"last_activity"`
}

type FileAccessPattern struct {
	FilePath    string    `json:"file_path"`
	AccessType  string    `json:"access_type"`
	ProcessName string    `json:"process_name"`
	PID         int32     `json:"pid"`
	User        string    `json:"user"`
	Frequency   int       `json:"frequency"`
	LastAccess  time.Time `json:"last_access"`
	FileSize    int64     `json:"file_size"`
	FileMode    string    `json:"file_mode"`
	Suspicious  bool      `json:"suspicious"`
}

// Runtime information structures
type ProcessInfo struct {
	PID             int32              `json:"pid"`
	PPID            int32              `json:"ppid"`
	Name            string             `json:"name"`
	Command         string             `json:"command"`
	User            string             `json:"user"`
	CreateTime      time.Time          `json:"create_time"`
	LastSeen        time.Time          `json:"last_seen"`
	CPUPercent      float64            `json:"cpu_percent"`
	MemoryPercent   float64            `json:"memory_percent"`
	Status          string             `json:"status"`
	BehaviorMetrics map[string]float64 `json:"behavior_metrics"`
}

type NetworkConnection struct {
	LocalAddr        string    `json:"local_addr"`
	RemoteAddr       string    `json:"remote_addr"`
	Status           string    `json:"status"`
	PID              int32     `json:"pid"`
	ProcessName      string    `json:"process_name"`
	Protocol         string    `json:"protocol"`
	CreatedAt        time.Time `json:"created_at"`
	LastActivity     time.Time `json:"last_activity"`
	BytesTransferred uint64    `json:"bytes_transferred"`
}

type FileAccess struct {
	Path        string    `json:"path"`
	AccessType  string    `json:"access_type"`
	PID         int32     `json:"pid"`
	ProcessName string    `json:"process_name"`
	User        string    `json:"user"`
	Timestamp   time.Time `json:"timestamp"`
	Size        int64     `json:"size"`
	Mode        string    `json:"mode"`
	Hash        string    `json:"hash"`
}

// NewDetectorMonitor creates a comprehensive behavior analysis and anomaly detection system
func NewDetectorMonitor(logger zerolog.Logger, eventBus *events.EventBus) scheduler.Monitor {
	monitor := &DetectorMonitor{
		BaseMonitor:        base_monitor.NewBaseMonitor("comprehensive_detector", base_monitor.ClassDetector, logger, eventBus),
		config:             &ComprehensiveDetectorConfig{},
		behaviorBaselines:  make(map[string]*BehaviorBaseline),
		systemBaselines:    make(map[string]*SystemBaseline),
		anomalyThresholds:  &AnomalyThresholds{},
		detectionRules:     []DetectionRule{},
		learningMode:       true,
		featureVectors:     []FeatureVector{},
		clusterCenters:     []FeatureVector{},
		anomalyScores:      make(map[string]float64),
		commandPatterns:    make(map[string]*CommandPattern),
		processPatterns:    make(map[string]*ProcessPattern),
		networkPatterns:    make(map[string]*NetworkPattern),
		fileAccessPatterns: make(map[string]*FileAccessPattern),
		processCache:       make(map[int32]*ProcessInfo),
		networkCache:       make(map[string]*NetworkConnection),
		fileAccessCache:    make(map[string]*FileAccess),
	}

	// Add detector-specific capabilities
	monitor.AddCapability(base_monitor.CapabilityMachineLearning)
	monitor.AddCapability(base_monitor.CapabilityBehaviorAnalysis)
	monitor.AddCapability(base_monitor.CapabilityRealTime)
	monitor.AddCapability("anomaly_detection")
	monitor.AddCapability("pattern_recognition")
	monitor.AddCapability("baseline_learning")
	monitor.AddCapability("sequence_analysis")

	// Return the monitor (interface conversion should work if DetectorMonitor implements scheduler.Monitor)
	return scheduler.Monitor(monitor)
}

// Configure sets up the comprehensive detector system
func (dm *DetectorMonitor) Configure(config map[string]interface{}) error {
	dm.LogEvent(zerolog.InfoLevel, "Configuring Enhanced Detector Monitor")

	if err := dm.parseConfig(config); err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}

	// Initialize detection rules
	if err := dm.initializeDetectionRules(); err != nil {
		dm.LogEvent(zerolog.WarnLevel, "Failed to initialize detection rules").Err(err)
	}

	// Load existing baselines if available
	if err := dm.loadExistingBaselines(); err != nil {
		dm.LogEvent(zerolog.WarnLevel, "Failed to load existing baselines").Err(err)
	}

	// Initialize anomaly thresholds
	dm.initializeAnomalyThresholds()

	// Check if we're in learning mode
	if dm.shouldEnterLearningMode() {
		dm.learningMode = true
		dm.LogEvent(zerolog.InfoLevel, "Detector entering learning mode")
	}

	dm.LogEvent(zerolog.InfoLevel, "Enhanced Detector Monitor configured successfully")
	return nil
}

// Start implements scheduler.Monitor interface
func (dm *DetectorMonitor) Start(ctx context.Context) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dm.running {
		return fmt.Errorf("detector monitor is already running")
	}

	dm.LogEvent(zerolog.InfoLevel, "Starting Enhanced Detector Monitor")

	// Create cancellable context
	dm.ctx, dm.cancel = context.WithCancel(ctx)
	dm.running = true
	dm.ticker = time.NewTicker(5 * time.Minute)

	// Start the monitoring goroutine
	dm.wg.Add(1)
	go dm.Run(dm.ctx)

	return nil
}

// Stop implements scheduler.Monitor interface
func (dm *DetectorMonitor) Stop() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !dm.running {
		return nil // Already stopped
	}

	dm.LogEvent(zerolog.InfoLevel, "Stopping Enhanced Detector Monitor")

	// Cancel context and cleanup
	if dm.cancel != nil {
		dm.cancel()
	}
	if dm.ticker != nil {
		dm.ticker.Stop()
	}

	dm.running = false

	// Wait for goroutine to finish
	dm.wg.Wait()

	dm.LogEvent(zerolog.InfoLevel, "Enhanced Detector Monitor stopped")
	return nil
}

// IsRunning implements scheduler.Monitor interface
func (dm *DetectorMonitor) IsRunning() bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.running
}

// Name implements scheduler.Monitor interface
func (dm *DetectorMonitor) Name() string {
	return "comprehensive_detector"
}

// GetStatus implements scheduler.Monitor interface (if required)
func (dm *DetectorMonitor) GetStatus() map[string]interface{} {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	return map[string]interface{}{
		"running":         dm.running,
		"learning_mode":   dm.learningMode,
		"anomaly_scores":  len(dm.anomalyScores),
		"detection_rules": len(dm.detectionRules),
		"process_cache":   len(dm.processCache),
		"network_cache":   len(dm.networkCache),
	}
}

// Run executes the main detector loop
func (dm *DetectorMonitor) Run(ctx context.Context) error {
	dm.LogEvent(zerolog.InfoLevel, "Starting Enhanced Detector Monitor")

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			dm.LogEvent(zerolog.InfoLevel, "Enhanced Detector Monitor stopping")
			return nil
		case <-ticker.C:
			dm.runDetectionCycle(ctx)
		}
	}
}

// runDetectionCycle runs a complete detection cycle
func (dm *DetectorMonitor) runDetectionCycle(ctx context.Context) {
	dm.lastAnalysis = time.Now()

	// Update detector metrics
	dm.updateDetectorMetrics()

	// Command history analysis
	if dm.config.MonitorCommandHistory {
		dm.runCommandHistoryAnalysis(ctx)
	}

	// Process behavior analysis
	if dm.config.MonitorProcessBehavior {
		dm.runProcessBehaviorAnalysis(ctx)
	}

	// Network behavior analysis
	if dm.config.MonitorNetworkBehavior {
		dm.runNetworkBehaviorAnalysis(ctx)
	}

	// File access pattern analysis
	if dm.config.MonitorFileAccess {
		dm.runFileAccessAnalysis(ctx)
	}

	// System-wide anomaly detection
	dm.runSystemAnomalyDetection(ctx)

	// Machine Learning feature extraction
	if dm.config.EnableMLBaselines {
		dm.runMLFeatureExtraction(ctx)
	}

	// Update behavioral baselines
	if dm.learningMode {
		dm.updateBehaviorBaselines(ctx)
	}

	// Comprehensive anomaly assessment
	dm.performComprehensiveAnomalyAssessment(ctx)
}

// Network behavior analysis
func (dm *DetectorMonitor) runNetworkBehaviorAnalysis(ctx context.Context) {
	dm.LogEvent(zerolog.InfoLevel, "Analyzing network behavior patterns...")
	// Implementation for network behavior analysis
	// This would analyze network connections, traffic patterns, etc.

	// Placeholder for network analysis
	dm.LogEvent(zerolog.InfoLevel, "Network behavior analysis completed")
}

// File access pattern analysis
func (dm *DetectorMonitor) runFileAccessAnalysis(ctx context.Context) {
	dm.LogEvent(zerolog.InfoLevel, "Analyzing file access patterns...")
	// Implementation for file access pattern analysis
	// This would monitor file operations, access patterns, etc.

	// Check for suspicious file operations
	dm.checkSuspiciousFileOperations(ctx)

	dm.LogEvent(zerolog.InfoLevel, "File access analysis completed")
}

func (dm *DetectorMonitor) checkSuspiciousFileOperations(ctx context.Context) {
	// Monitor critical system directories
	criticalDirs := []string{
		"/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
		"/boot", "/root", "/home", "/var/log",
	}

	for _, dir := range criticalDirs {
		if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Continue on errors
			}

			// Skip if it's a directory
			if info.IsDir() {
				return nil
			}

			// Check for recently modified files
			if time.Since(info.ModTime()) < time.Hour*24 {
				dm.analyzeRecentFileChange(ctx, path, info)
			}

			return nil
		}); err != nil {
			dm.LogEvent(zerolog.WarnLevel, "Error walking directory").
				Str("directory", dir).Err(err)
		}
	}
}

func (dm *DetectorMonitor) analyzeRecentFileChange(ctx context.Context, path string, info os.FileInfo) {
	// Calculate file hash for integrity checking
	hash, err := dm.calculateFileHash(path)
	if err != nil {
		return
	}

	fileAccess := &FileAccess{
		Path:       path,
		AccessType: "modified",
		Timestamp:  info.ModTime(),
		Size:       info.Size(),
		Mode:       info.Mode().String(),
		Hash:       hash,
	}

	// Check if this is a suspicious file change
	if dm.isSuspiciousFileChange(path, info) {
		dm.PublishEvent(ctx, events.EventFileSystemChange, path,
			fmt.Sprintf("Suspicious file modification detected: %s", path),
			"medium", map[string]interface{}{
				"file_path": path,
				"file_size": info.Size(),
				"mod_time":  info.ModTime(),
				"file_mode": info.Mode().String(),
				"hash":      hash,
			})
	}

	// Update file access patterns
	dm.updateFileAccessPatterns(fileAccess)
}

func (dm *DetectorMonitor) isSuspiciousFileChange(path string, info os.FileInfo) bool {
	// Check for executable files in unusual locations
	if (info.Mode().Perm() & 0111) != 0 {
		suspiciousLocations := []string{
			"/tmp", "/var/tmp", "/dev/shm", "/home",
		}

		for _, location := range suspiciousLocations {
			if strings.HasPrefix(path, location) {
				return true
			}
		}
	}

	// Check for hidden files in system directories
	if strings.HasPrefix(filepath.Base(path), ".") {
		systemDirs := []string{"/etc", "/bin", "/sbin", "/usr", "/boot"}
		for _, sysDir := range systemDirs {
			if strings.HasPrefix(path, sysDir) {
				return true
			}
		}
	}

	// Check for SUID/SGID files
	if (info.Mode()&os.ModeSetuid != 0) || (info.Mode()&os.ModeSetgid != 0) {
		return true
	}

	return false
}

func (dm *DetectorMonitor) updateFileAccessPatterns(fileAccess *FileAccess) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	key := fileAccess.Path

	if pattern, exists := dm.fileAccessPatterns[key]; exists {
		pattern.Frequency++
		pattern.LastAccess = fileAccess.Timestamp
		pattern.FileSize = fileAccess.Size
		pattern.FileMode = fileAccess.Mode
	} else {
		pattern := &FileAccessPattern{
			FilePath:   fileAccess.Path,
			AccessType: fileAccess.AccessType,
			Frequency:  1,
			LastAccess: fileAccess.Timestamp,
			FileSize:   fileAccess.Size,
			FileMode:   fileAccess.Mode,
			Suspicious: dm.isSuspiciousFile(fileAccess.Path),
		}

		dm.fileAccessPatterns[key] = pattern
	}
}

func (dm *DetectorMonitor) isSuspiciousFile(path string) bool {
	suspiciousExtensions := []string{".sh", ".py", ".pl", ".rb", ".exe", ".bin"}
	suspiciousPaths := []string{"/tmp", "/var/tmp", "/dev/shm"}

	ext := strings.ToLower(filepath.Ext(path))
	for _, suspExt := range suspiciousExtensions {
		if ext == suspExt {
			for _, suspPath := range suspiciousPaths {
				if strings.HasPrefix(path, suspPath) {
					return true
				}
			}
		}
	}
	return false
}

func (dm *DetectorMonitor) calculateFileHash(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()

	// Read the entire file for hashing
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// System-wide anomaly detection
func (dm *DetectorMonitor) runSystemAnomalyDetection(ctx context.Context) {
	dm.LogEvent(zerolog.InfoLevel, "Running system-wide anomaly detection...")

	// Collect current system metrics
	systemMetrics := dm.collectSystemMetrics()

	// Compare against baselines
	dm.compareWithSystemBaselines(ctx, systemMetrics)

	// Update system baselines if in learning mode
	if dm.learningMode {
		dm.updateSystemBaselines(systemMetrics)
	}
}

func (dm *DetectorMonitor) collectSystemMetrics() map[string]float64 {
	metrics := make(map[string]float64)

	// CPU usage metrics
	if cpuPercents, err := dm.getCPUUsage(); err == nil {
		metrics["cpu_user"] = cpuPercents[0]
		metrics["cpu_system"] = cpuPercents[1]
		metrics["cpu_idle"] = cpuPercents[2]
	}

	// Memory usage metrics
	if memInfo, err := dm.getMemoryInfo(); err == nil {
		metrics["memory_used_percent"] = memInfo["used_percent"]
		metrics["memory_available"] = memInfo["available"]
		metrics["memory_cached"] = memInfo["cached"]
	}

	// Disk usage metrics
	if diskInfo, err := dm.getDiskInfo(); err == nil {
		metrics["disk_used_percent"] = diskInfo["used_percent"]
		metrics["disk_free"] = diskInfo["free"]
		metrics["disk_inodes_used"] = diskInfo["inodes_used"]
	}

	// Network metrics
	if netInfo, err := dm.getNetworkInfo(); err == nil {
		metrics["network_bytes_sent"] = netInfo["bytes_sent"]
		metrics["network_bytes_recv"] = netInfo["bytes_recv"]
		metrics["network_connections"] = netInfo["connections"]
	}

	// Process metrics
	if procInfo, err := dm.getProcessInfo(); err == nil {
		metrics["process_count"] = procInfo["total_processes"]
		metrics["process_running"] = procInfo["running_processes"]
		metrics["process_zombie"] = procInfo["zombie_processes"]
	}

	return metrics
}

func (dm *DetectorMonitor) getCPUUsage() ([]float64, error) {
	// Simplified CPU usage calculation
	// In a real implementation, you'd use gopsutil or similar
	return []float64{15.2, 8.3, 76.5}, nil
}

func (dm *DetectorMonitor) getMemoryInfo() (map[string]float64, error) {
	// Simplified memory info
	return map[string]float64{
		"used_percent": 45.2,
		"available":    8192.0,
		"cached":       2048.0,
	}, nil
}

func (dm *DetectorMonitor) getDiskInfo() (map[string]float64, error) {
	// Simplified disk info
	return map[string]float64{
		"used_percent": 65.8,
		"free":         50000.0,
		"inodes_used":  12000.0,
	}, nil
}

func (dm *DetectorMonitor) getNetworkInfo() (map[string]float64, error) {
	// Simplified network info
	return map[string]float64{
		"bytes_sent":  1048576.0,
		"bytes_recv":  2097152.0,
		"connections": 45.0,
	}, nil
}

func (dm *DetectorMonitor) getProcessInfo() (map[string]float64, error) {
	// Simplified process info
	processes, err := psutil.Processes()
	if err != nil {
		return nil, err
	}

	totalProc := float64(len(processes))
	runningProc := 0.0
	zombieProc := 0.0

	for _, proc := range processes {
		if status, err := proc.Status(); err == nil {
			switch strings.ToLower(status) {
			case "running":
				runningProc++
			case "zombie":
				zombieProc++
			}
		}
	}

	return map[string]float64{
		"total_processes":   totalProc,
		"running_processes": runningProc,
		"zombie_processes":  zombieProc,
	}, nil
}

func (dm *DetectorMonitor) compareWithSystemBaselines(ctx context.Context, currentMetrics map[string]float64) {
	dm.baselineMu.RLock()
	defer dm.baselineMu.RUnlock()

	for metricName, currentValue := range currentMetrics {
		baseline, exists := dm.systemBaselines[metricName]
		if !exists {
			continue // No baseline to compare against
		}

		// Calculate z-score for anomaly detection
		if baseline.StatisticalData != nil && baseline.StatisticalData.StdDev > 0 {
			zScore := (currentValue - baseline.StatisticalData.Mean) / baseline.StatisticalData.StdDev

			// Check if this is an anomaly (z-score > threshold)
			if math.Abs(zScore) > dm.config.AnomalyThreshold {
				severity := "medium"
				if math.Abs(zScore) > dm.config.AnomalyThreshold*1.5 {
					severity = "high"
				}

				dm.PublishEvent(ctx, events.EventSystemAnomaly, metricName,
					fmt.Sprintf("System metric anomaly detected: %s (z-score: %.2f)", metricName, zScore),
					severity, map[string]interface{}{
						"metric_name":     metricName,
						"current_value":   currentValue,
						"baseline_mean":   baseline.StatisticalData.Mean,
						"baseline_stddev": baseline.StatisticalData.StdDev,
						"z_score":         zScore,
					})

				// Update anomaly score
				dm.anomalyScores[metricName] = math.Abs(zScore)
			}
		}
	}
}

func (dm *DetectorMonitor) updateSystemBaselines(metrics map[string]float64) {
	dm.baselineMu.Lock()
	defer dm.baselineMu.Unlock()

	for metricName, value := range metrics {
		baseline, exists := dm.systemBaselines[metricName]
		if !exists {
			// Create new baseline
			baseline = &SystemBaseline{
				Type:        "system_metric",
				CreatedAt:   time.Now(),
				LastUpdated: time.Now(),
				Metrics:     make(map[string]float64),
				StatisticalData: &StatisticalData{
					Mean:   value,
					StdDev: 0.0,
				},
				Confidence: 0.1, // Low confidence initially
			}
			baseline.Metrics[metricName] = value
			dm.systemBaselines[metricName] = baseline
		} else {
			// Update existing baseline using exponential moving average
			alpha := 0.1 // Learning rate
			baseline.StatisticalData.Mean = alpha*value + (1-alpha)*baseline.StatisticalData.Mean

			// Update standard deviation (simplified)
			variance := math.Pow(value-baseline.StatisticalData.Mean, 2)
			baseline.StatisticalData.StdDev = math.Sqrt(alpha*variance + (1-alpha)*math.Pow(baseline.StatisticalData.StdDev, 2))

			baseline.LastUpdated = time.Now()
			baseline.Confidence = math.Min(baseline.Confidence+0.01, 1.0)
		}
	}
}

// Machine Learning feature extraction
func (dm *DetectorMonitor) runMLFeatureExtraction(ctx context.Context) {
	dm.LogEvent(zerolog.InfoLevel, "Extracting features for machine learning...")

	// Extract features from current system state
	features := dm.extractCurrentFeatures()

	// Create feature vector
	featureVector := FeatureVector{
		Timestamp:    time.Now(),
		Features:     features,
		Label:        dm.determineCurrentLabel(),
		AnomalyScore: dm.calculateCurrentAnomalyScore(),
		Metadata:     dm.collectFeatureMetadata(),
	}

	// Add to feature vector collection
	dm.mu.Lock()
	dm.featureVectors = append(dm.featureVectors, featureVector)

	// Maintain sliding window of features
	maxFeatures := dm.config.FeatureWindowSize
	if maxFeatures > 0 && len(dm.featureVectors) > maxFeatures {
		dm.featureVectors = dm.featureVectors[len(dm.featureVectors)-maxFeatures:]
	}
	dm.mu.Unlock()

	// Perform clustering if enabled and sufficient data
	if dm.config.ClusteringEnabled && len(dm.featureVectors) >= dm.config.MinClusterSize {
		dm.performSimpleClustering(ctx)
	}
}

func (dm *DetectorMonitor) extractCurrentFeatures() map[string]float64 {
	features := make(map[string]float64)

	// Command frequency features
	dm.mu.RLock()
	totalCommands := 0
	for _, pattern := range dm.commandPatterns {
		totalCommands += pattern.Frequency
	}

	if totalCommands > 0 {
		features["unique_commands"] = float64(len(dm.commandPatterns))
		features["avg_command_frequency"] = float64(totalCommands) / float64(len(dm.commandPatterns))
	}

	// Process features
	features["total_processes"] = float64(len(dm.processCache))

	var totalCPU, totalMemory float64
	for _, proc := range dm.processCache {
		totalCPU += proc.CPUPercent
		totalMemory += proc.MemoryPercent
	}

	if len(dm.processCache) > 0 {
		features["avg_cpu_usage"] = totalCPU / float64(len(dm.processCache))
		features["avg_memory_usage"] = totalMemory / float64(len(dm.processCache))
	}

	// File access features
	features["file_access_patterns"] = float64(len(dm.fileAccessPatterns))

	suspiciousFiles := 0
	for _, pattern := range dm.fileAccessPatterns {
		if pattern.Suspicious {
			suspiciousFiles++
		}
	}
	features["suspicious_file_ratio"] = float64(suspiciousFiles) / math.Max(1, float64(len(dm.fileAccessPatterns)))

	dm.mu.RUnlock()

	// Time-based features
	hour := time.Now().Hour()
	features["hour_of_day"] = float64(hour)
	features["day_of_week"] = float64(time.Now().Weekday())

	return features
}

func (dm *DetectorMonitor) determineCurrentLabel() string {
	// In learning mode, we assume normal behavior
	if dm.learningMode {
		return "normal"
	}

	// Check anomaly scores to determine label
	totalScore := 0.0
	for _, score := range dm.anomalyScores {
		totalScore += score
	}

	if totalScore > dm.config.AnomalyThreshold*2 {
		return "anomalous"
	}
	return "normal"
}

func (dm *DetectorMonitor) calculateCurrentAnomalyScore() float64 {
	if len(dm.anomalyScores) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, score := range dm.anomalyScores {
		totalScore += score
	}
	return totalScore / float64(len(dm.anomalyScores))
}

func (dm *DetectorMonitor) collectFeatureMetadata() map[string]interface{} {
	metadata := map[string]interface{}{
		"learning_mode":    dm.learningMode,
		"baselines_count":  len(dm.behaviorBaselines),
		"detection_rules":  len(dm.detectionRules),
		"command_patterns": len(dm.commandPatterns),
		"process_patterns": len(dm.processPatterns),
		"file_patterns":    len(dm.fileAccessPatterns),
	}
	return metadata
}

// Simple clustering implementation for anomaly detection
func (dm *DetectorMonitor) performSimpleClustering(ctx context.Context) {
	dm.LogEvent(zerolog.InfoLevel, "Performing feature clustering for anomaly detection...")

	// Simple k-means clustering implementation
	// This is a basic implementation - in production, you'd use a proper ML library

	if len(dm.featureVectors) < 2 {
		return
	}

	// Extract feature matrix
	featureMatrix := make([][]float64, len(dm.featureVectors))
	featureNames := make([]string, 0)

	// Get feature names from first vector
	for featureName := range dm.featureVectors[0].Features {
		featureNames = append(featureNames, featureName)
	}
	sort.Strings(featureNames) // Ensure consistent ordering

	// Build feature matrix
	for i, fv := range dm.featureVectors {
		row := make([]float64, len(featureNames))
		for j, featureName := range featureNames {
			if val, exists := fv.Features[featureName]; exists {
				row[j] = val
			}
		}
		featureMatrix[i] = row
	}

	// Perform simple clustering (2 clusters: normal vs anomalous)
	clusters := dm.simpleKMeans(featureMatrix, 2)

	// Update cluster assignments
	dm.mu.Lock()
	for i, clusterID := range clusters {
		if i < len(dm.featureVectors) {
			dm.featureVectors[i].ClusterID = clusterID
		}
	}
	dm.mu.Unlock()

	// Analyze clusters for anomalies
	dm.analyzeClusterAnomalies(ctx, clusters)
}

func (dm *DetectorMonitor) simpleKMeans(data [][]float64, k int) []int {
	if len(data) < k || len(data[0]) == 0 {
		// Return all points in cluster 0 if not enough data
		clusters := make([]int, len(data))
		return clusters
	}

	// Initialize centroids randomly
	centroids := make([][]float64, k)
	for i := range centroids {
		centroids[i] = make([]float64, len(data[0]))
		copy(centroids[i], data[i%len(data)]) // Simple initialization
	}

	clusters := make([]int, len(data))
	maxIterations := 10

	for iteration := 0; iteration < maxIterations; iteration++ {
		// Assign points to clusters
		changed := false
		for i, point := range data {
			bestCluster := 0
			bestDistance := dm.euclideanDistance(point, centroids[0])

			for j := 1; j < k; j++ {
				distance := dm.euclideanDistance(point, centroids[j])
				if distance < bestDistance {
					bestDistance = distance
					bestCluster = j
				}
			}

			if clusters[i] != bestCluster {
				changed = true
				clusters[i] = bestCluster
			}
		}

		if !changed {
			break
		}

		// Update centroids
		for j := 0; j < k; j++ {
			clusterPoints := [][]float64{}
			for i, point := range data {
				if clusters[i] == j {
					clusterPoints = append(clusterPoints, point)
				}
			}

			if len(clusterPoints) > 0 {
				for dim := 0; dim < len(centroids[j]); dim++ {
					sum := 0.0
					for _, point := range clusterPoints {
						sum += point[dim]
					}
					centroids[j][dim] = sum / float64(len(clusterPoints))
				}
			}
		}
	}

	return clusters
}

func (dm *DetectorMonitor) euclideanDistance(a, b []float64) float64 {
	if len(a) != len(b) {
		return math.Inf(1)
	}

	sum := 0.0
	for i := range a {
		diff := a[i] - b[i]
		sum += diff * diff
	}
	return math.Sqrt(sum)
}

func (dm *DetectorMonitor) analyzeClusterAnomalies(ctx context.Context, clusters []int) {
	// Count cluster sizes
	clusterSizes := make(map[int]int)
	for _, cluster := range clusters {
		clusterSizes[cluster]++
	}

	// Identify minority cluster as potentially anomalous
	minCluster, minSize := -1, len(clusters)
	for cluster, size := range clusterSizes {
		if size < minSize {
			minSize = size
			minCluster = cluster
		}
	}

	// If minority cluster is very small, flag as anomalous
	if minSize < len(clusters)/10 { // Less than 10% of data
		dm.PublishEvent(ctx, events.EventSystemAnomaly, "cluster_analysis",
			fmt.Sprintf("Anomalous behavior cluster detected (cluster %d, %d samples)", minCluster, minSize),
			"medium", map[string]interface{}{
				"cluster_id":    minCluster,
				"cluster_size":  minSize,
				"total_samples": len(clusters),
				"anomaly_ratio": float64(minSize) / float64(len(clusters)),
			})
	}
}

// Anomaly detection helper methods
func (dm *DetectorMonitor) detectCommandAnomalies(ctx context.Context) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if len(dm.commandPatterns) == 0 {
		return
	}

	// Calculate command frequency statistics
	frequencies := make([]float64, 0, len(dm.commandPatterns))
	for _, pattern := range dm.commandPatterns {
		frequencies = append(frequencies, float64(pattern.Frequency))
	}

	if len(frequencies) < 2 {
		return
	}

	mean := dm.calculateMean(frequencies)
	stddev := dm.calculateStdDev(frequencies, mean)

	// Detect anomalous commands (too frequent or too rare)
	for command, pattern := range dm.commandPatterns {
		freq := float64(pattern.Frequency)
		zScore := (freq - mean) / stddev

		if math.Abs(zScore) > dm.anomalyThresholds.CommandFrequency {
			severity := "low"
			if math.Abs(zScore) > dm.anomalyThresholds.CommandFrequency*1.5 {
				severity = "medium"
			}

			description := "Unusual command frequency detected"
			if zScore > 0 {
				description = "Unusually frequent command detected"
			} else {
				description = "Unusually rare command detected"
			}

			dm.PublishEvent(ctx, events.EventSystemAnomaly, command,
				fmt.Sprintf("%s: %s (z-score: %.2f)", description, command, zScore),
				severity, map[string]interface{}{
					"command":     command,
					"frequency":   pattern.Frequency,
					"z_score":     zScore,
					"mean_freq":   mean,
					"stddev_freq": stddev,
				})
		}
	}
}

func (dm *DetectorMonitor) detectProcessAnomalies(ctx context.Context) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// Analyze process resource usage patterns
	cpuUsages := make([]float64, 0, len(dm.processCache))
	memUsages := make([]float64, 0, len(dm.processCache))

	for _, proc := range dm.processCache {
		cpuUsages = append(cpuUsages, proc.CPUPercent)
		memUsages = append(memUsages, proc.MemoryPercent)
	}

	if len(cpuUsages) < 2 {
		return
	}

	cpuMean := dm.calculateMean(cpuUsages)
	cpuStdDev := dm.calculateStdDev(cpuUsages, cpuMean)
	memMean := dm.calculateMean(memUsages)
	memStdDev := dm.calculateStdDev(memUsages, memMean)

	// Check for anomalous processes
	for pid, proc := range dm.processCache {
		cpuZScore := 0.0
		memZScore := 0.0

		if cpuStdDev > 0 {
			cpuZScore = (proc.CPUPercent - cpuMean) / cpuStdDev
		}
		if memStdDev > 0 {
			memZScore = (proc.MemoryPercent - memMean) / memStdDev
		}

		if math.Abs(cpuZScore) > dm.anomalyThresholds.ProcessBehavior ||
			math.Abs(memZScore) > dm.anomalyThresholds.ProcessBehavior {

			severity := "medium"
			if math.Max(math.Abs(cpuZScore), math.Abs(memZScore)) > dm.anomalyThresholds.ProcessBehavior*1.5 {
				severity = "high"
			}

			dm.PublishEvent(ctx, events.EventSystemAnomaly, fmt.Sprintf("pid_%d", pid),
				fmt.Sprintf("Anomalous process resource usage: %s (CPU z-score: %.2f, Memory z-score: %.2f)",
					proc.Name, cpuZScore, memZScore),
				severity, map[string]interface{}{
					"process_name":   proc.Name,
					"pid":            pid,
					"cpu_percent":    proc.CPUPercent,
					"memory_percent": proc.MemoryPercent,
					"cpu_z_score":    cpuZScore,
					"memory_z_score": memZScore,
				})
		}
	}
}

// Comprehensive anomaly assessment
func (dm *DetectorMonitor) performComprehensiveAnomalyAssessment(ctx context.Context) {
	dm.LogEvent(zerolog.InfoLevel, "Performing comprehensive anomaly assessment...")

	// Calculate overall anomaly score
	overallScore := dm.calculateOverallAnomalyScore()

	// Determine system threat level based on anomalies
	threatLevel := dm.determineAnomalyBasedThreatLevel(overallScore)

	// Update detector state
	dm.UpdateState("overall_anomaly_score", overallScore)
	dm.UpdateState("threat_level", threatLevel)

	// Publish comprehensive assessment if significant anomalies detected
	if overallScore > dm.config.AnomalyThreshold {
		dm.PublishEvent(ctx, events.EventSystemAnomaly, "comprehensive_assessment",
			fmt.Sprintf("Comprehensive anomaly assessment: elevated threat level (%s, score: %.2f)",
				threatLevel, overallScore),
			dm.determineSeverityFromThreatLevel(threatLevel), map[string]interface{}{
				"overall_anomaly_score": overallScore,
				"threat_level":          threatLevel,
				"anomaly_threshold":     dm.config.AnomalyThreshold,
				"learning_mode":         dm.learningMode,
			})
	}
}

func (dm *DetectorMonitor) calculateOverallAnomalyScore() float64 {
	if len(dm.anomalyScores) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, score := range dm.anomalyScores {
		totalScore += score
	}

	// Apply feature weighting
	weightedScore := totalScore / float64(len(dm.anomalyScores))

	// Add clustering anomaly contribution if available
	if len(dm.featureVectors) > 0 {
		recentVector := dm.featureVectors[len(dm.featureVectors)-1]
		weightedScore += recentVector.AnomalyScore * 0.3
	}

	return weightedScore
}

func (dm *DetectorMonitor) determineAnomalyBasedThreatLevel(score float64) string {
	threshold := dm.config.AnomalyThreshold

	switch {
	case score >= threshold*3:
		return "critical"
	case score >= threshold*2:
		return "high"
	case score >= threshold:
		return "medium"
	default:
		return "low"
	}
}

// parseConfig parses the configuration map into the DetectorMonitor config struct
func (dm *DetectorMonitor) parseConfig(config map[string]interface{}) error {
	// Set default values
	dm.config.LearningPeriodDays = 7
	dm.config.AnomalyThreshold = 2.0
	dm.config.EnableMLBaselines = true
	dm.config.ClusteringEnabled = true
	dm.config.MinClusterSize = 10
	dm.config.MaxClusters = 5
	dm.config.FeatureWindowSize = 1000
	dm.config.MonitorCommandHistory = true
	dm.config.MonitorProcessBehavior = true
	dm.config.MonitorNetworkBehavior = true
	dm.config.MonitorFileAccess = true
	dm.config.RealTimeAnalysisEnabled = true
	dm.config.BaselineUpdateInterval = "1h"
	dm.config.AnomalyCheckInterval = "5m"
	dm.config.MaxHistoryDays = 30
	dm.config.BaselineStoragePath = "/var/lib/sentinel/baselines"
	dm.config.FeatureStoragePath = "/var/lib/sentinel/features"
	dm.config.EnableSequenceDetection = true
	dm.config.EnableTimeSeriesAnalysis = true
	dm.config.EnableCorrelationAnalysis = true

	// Parse configuration values
	if val, ok := config["learning_period_days"].(int); ok {
		dm.config.LearningPeriodDays = val
	}
	if val, ok := config["anomaly_threshold"].(float64); ok {
		dm.config.AnomalyThreshold = val
	}
	if val, ok := config["enable_ml_baselines"].(bool); ok {
		dm.config.EnableMLBaselines = val
	}
	if val, ok := config["clustering_enabled"].(bool); ok {
		dm.config.ClusteringEnabled = val
	}
	if val, ok := config["min_cluster_size"].(int); ok {
		dm.config.MinClusterSize = val
	}
	if val, ok := config["monitor_command_history"].(bool); ok {
		dm.config.MonitorCommandHistory = val
	}
	if val, ok := config["monitor_process_behavior"].(bool); ok {
		dm.config.MonitorProcessBehavior = val
	}
	if val, ok := config["monitor_network_behavior"].(bool); ok {
		dm.config.MonitorNetworkBehavior = val
	}
	if val, ok := config["monitor_file_access"].(bool); ok {
		dm.config.MonitorFileAccess = val
	}
	if val, ok := config["baseline_storage_path"].(string); ok {
		dm.config.BaselineStoragePath = val
	}
	if val, ok := config["feature_storage_path"].(string); ok {
		dm.config.FeatureStoragePath = val
	}

	// Parse string slices
	if val, ok := config["behavior_rules"].([]interface{}); ok {
		dm.config.BehaviorRules = make([]string, len(val))
		for i, v := range val {
			if str, ok := v.(string); ok {
				dm.config.BehaviorRules[i] = str
			}
		}
	}
	if val, ok := config["suspicious_commands"].([]interface{}); ok {
		dm.config.SuspiciousCommands = make([]string, len(val))
		for i, v := range val {
			if str, ok := v.(string); ok {
				dm.config.SuspiciousCommands[i] = str
			}
		}
	}
	if val, ok := config["suspicious_processes"].([]interface{}); ok {
		dm.config.SuspiciousProcesses = make([]string, len(val))
		for i, v := range val {
			if str, ok := v.(string); ok {
				dm.config.SuspiciousProcesses[i] = str
			}
		}
	}

	return nil
}

// initializeDetectionRules sets up default detection rules
func (dm *DetectorMonitor) initializeDetectionRules() error {
	defaultRules := []DetectionRule{
		{
			ID:          "suspicious_wget",
			Name:        "Suspicious wget usage",
			Type:        "command_pattern",
			Pattern:     `wget.*\.(sh|py|pl|exe)`,
			Condition:   "match",
			Severity:    "high",
			Description: "Potentially malicious file download",
			Enabled:     true,
			Metadata:    map[string]string{"category": "malware_download"},
		},
		{
			ID:          "curl_pipe_bash",
			Name:        "Curl pipe to bash",
			Type:        "command_pattern",
			Pattern:     `curl.*\|\s*bash`,
			Condition:   "match",
			Severity:    "high",
			Description: "Direct execution of remote script",
			Enabled:     true,
			Metadata:    map[string]string{"category": "remote_execution"},
		},
		{
			ID:          "base64_decode",
			Name:        "Base64 decode operations",
			Type:        "command_pattern",
			Pattern:     `base64\s+-d`,
			Condition:   "match",
			Severity:    "medium",
			Description: "Base64 decode operation detected",
			Enabled:     true,
			Metadata:    map[string]string{"category": "obfuscation"},
		},
		{
			ID:          "netcat_listener",
			Name:        "Netcat listener",
			Type:        "command_pattern",
			Pattern:     `nc\s+.*-l`,
			Condition:   "match",
			Severity:    "high",
			Description: "Netcat listener detected",
			Enabled:     true,
			Metadata:    map[string]string{"category": "backdoor"},
		},
	}

	// Compile regex patterns
	for i := range defaultRules {
		compiled, err := regexp.Compile(defaultRules[i].Pattern)
		if err != nil {
			dm.LogEvent(zerolog.WarnLevel, "Failed to compile detection rule pattern").
				Str("rule_id", defaultRules[i].ID).
				Str("pattern", defaultRules[i].Pattern).
				Err(err)
			continue
		}
		defaultRules[i].CompiledPattern = compiled
	}

	dm.detectionRules = defaultRules
	return nil
}

// loadExistingBaselines loads previously saved baselines
func (dm *DetectorMonitor) loadExistingBaselines() error {
	// Check if baseline storage path exists
	if _, err := os.Stat(dm.config.BaselineStoragePath); os.IsNotExist(err) {
		// Create directory if it doesn't exist
		if err := os.MkdirAll(dm.config.BaselineStoragePath, 0755); err != nil {
			return fmt.Errorf("failed to create baseline storage directory: %w", err)
		}
		return nil // No existing baselines to load
	}

	// In a real implementation, you would load JSON files from the baseline storage path
	// For now, we'll just log that we're attempting to load baselines
	dm.LogEvent(zerolog.InfoLevel, "Attempting to load existing baselines").
		Str("path", dm.config.BaselineStoragePath)

	return nil
}

// initializeAnomalyThresholds sets up default anomaly detection thresholds
func (dm *DetectorMonitor) initializeAnomalyThresholds() {
	dm.anomalyThresholds = &AnomalyThresholds{
		CommandFrequency:  2.5,
		ProcessBehavior:   2.0,
		NetworkActivity:   2.0,
		FileAccess:        1.5,
		SystemMetrics:     2.0,
		SequenceAnomalies: 3.0,
	}
}

// shouldEnterLearningMode determines if the detector should be in learning mode
func (dm *DetectorMonitor) shouldEnterLearningMode() bool {
	// Check if we have enough historical data
	if len(dm.behaviorBaselines) == 0 {
		return true
	}

	// Check if baselines are recent enough
	for _, baseline := range dm.behaviorBaselines {
		if time.Since(baseline.CreatedAt).Hours() > float64(dm.config.LearningPeriodDays*24) {
			return true
		}
	}

	return false
}

// getAllUserHomeDirectories gets all user home directories for analysis
func (dm *DetectorMonitor) getAllUserHomeDirectories() []string {
	var homeDirectories []string

	// Add current user's home directory
	if currentUser, err := user.Current(); err == nil {
		homeDirectories = append(homeDirectories, currentUser.HomeDir)
	}

	// Add common home directory paths
	commonHomePaths := []string{"/home", "/Users"}

	for _, basePath := range commonHomePaths {
		if entries, err := os.ReadDir(basePath); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					homeDir := filepath.Join(basePath, entry.Name())
					homeDirectories = append(homeDirectories, homeDir)
				}
			}
		}
	}

	// Add root home directory
	homeDirectories = append(homeDirectories, "/root")

	return homeDirectories
}

// calculateMean calculates the arithmetic mean of a slice of float64 values
func (dm *DetectorMonitor) calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	sum := 0.0
	for _, value := range values {
		sum += value
	}
	return sum / float64(len(values))
}

// calculateStdDev calculates the standard deviation of a slice of float64 values
func (dm *DetectorMonitor) calculateStdDev(values []float64, mean float64) float64 {
	if len(values) <= 1 {
		return 0.0
	}

	sumSquaredDiffs := 0.0
	for _, value := range values {
		diff := value - mean
		sumSquaredDiffs += diff * diff
	}

	variance := sumSquaredDiffs / float64(len(values)-1)
	return math.Sqrt(variance)
}

// determineSeverityFromThreatLevel converts threat level to event severity
func (dm *DetectorMonitor) determineSeverityFromThreatLevel(threatLevel string) string {
	switch threatLevel {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

// updateDetectorMetrics updates internal metrics for the detector
func (dm *DetectorMonitor) updateDetectorMetrics() {
	dm.UpdateMetrics("command_patterns_count", len(dm.commandPatterns))
	dm.UpdateMetrics("process_patterns_count", len(dm.processPatterns))
	dm.UpdateMetrics("file_access_patterns_count", len(dm.fileAccessPatterns))
	dm.UpdateMetrics("behavior_baselines_count", len(dm.behaviorBaselines))
	dm.UpdateMetrics("system_baselines_count", len(dm.systemBaselines))
	dm.UpdateMetrics("feature_vectors_count", len(dm.featureVectors))
	dm.UpdateMetrics("anomaly_scores_count", len(dm.anomalyScores))
	dm.UpdateMetrics("detection_rules_count", len(dm.detectionRules))
	dm.UpdateMetrics("learning_mode", dm.learningMode)
	dm.UpdateMetrics("last_analysis", dm.lastAnalysis.Format(time.RFC3339))

	// Calculate overall health score
	healthScore := 100.0
	if len(dm.behaviorBaselines) == 0 {
		healthScore -= 20.0
	}
	if len(dm.systemBaselines) == 0 {
		healthScore -= 20.0
	}
	if time.Since(dm.lastAnalysis) > time.Hour {
		healthScore -= 30.0
	}

	dm.UpdateMetrics("health_score", healthScore)
}

// updateBehaviorBaselines updates behavior baselines based on current observations
func (dm *DetectorMonitor) updateBehaviorBaselines(ctx context.Context) {
	dm.baselineMu.Lock()
	defer dm.baselineMu.Unlock()

	dm.LogEvent(zerolog.InfoLevel, "Updating behavior baselines")

	// Update command baselines
	dm.updateCommandBaselines()

	// Update process baselines
	dm.updateProcessBaselines()

	// Update file access baselines
	dm.updateFileAccessBaselines()

	// Update time-based baselines
	dm.updateTimeBasedBaselines()

	dm.LogEvent(zerolog.InfoLevel, "Behavior baselines updated").
		Int("command_patterns", len(dm.commandPatterns)).
		Int("process_patterns", len(dm.processPatterns)).
		Int("file_patterns", len(dm.fileAccessPatterns))
}

// updateCommandBaselines updates baselines based on command patterns
func (dm *DetectorMonitor) updateCommandBaselines() {
	commandBaseline := dm.behaviorBaselines["commands"]
	if commandBaseline == nil {
		commandBaseline = &BehaviorBaseline{
			Type:             "commands",
			CreatedAt:        time.Now(),
			LastUpdated:      time.Now(),
			SampleCount:      0,
			Patterns:         make(map[string]int),
			TimeDistribution: make(map[int]int),
			Confidence:       0.0,
			Metadata:         make(map[string]interface{}),
		}
		dm.behaviorBaselines["commands"] = commandBaseline
	}

	// Update patterns from command cache
	for command, pattern := range dm.commandPatterns {
		commandBaseline.Patterns[command] = pattern.Frequency
		commandBaseline.SampleCount += pattern.Frequency
	}

	// Update frequency statistics
	frequencies := make([]float64, 0, len(commandBaseline.Patterns))
	for _, freq := range commandBaseline.Patterns {
		frequencies = append(frequencies, float64(freq))
	}

	if len(frequencies) > 0 {
		mean := dm.calculateMean(frequencies)
		stddev := dm.calculateStdDev(frequencies, mean)

		commandBaseline.FrequencyStats = &FrequencyStats{
			Mean:   mean,
			StdDev: stddev,
		}

		if len(frequencies) > 1 {
			sort.Float64s(frequencies)
			commandBaseline.FrequencyStats.Min = frequencies[0]
			commandBaseline.FrequencyStats.Max = frequencies[len(frequencies)-1]

			if len(frequencies)%2 == 0 {
				mid := len(frequencies) / 2
				commandBaseline.FrequencyStats.Median = (frequencies[mid-1] + frequencies[mid]) / 2
			} else {
				commandBaseline.FrequencyStats.Median = frequencies[len(frequencies)/2]
			}

			// 95th percentile
			p95Index := int(0.95 * float64(len(frequencies)))
			if p95Index < len(frequencies) {
				commandBaseline.FrequencyStats.Percentile95 = frequencies[p95Index]
			}
		}
	}

	commandBaseline.LastUpdated = time.Now()
	commandBaseline.Confidence = math.Min(commandBaseline.Confidence+0.1, 1.0)
}

// updateProcessBaselines updates baselines based on process patterns
func (dm *DetectorMonitor) updateProcessBaselines() {
	processBaseline := dm.behaviorBaselines["processes"]
	if processBaseline == nil {
		processBaseline = &BehaviorBaseline{
			Type:             "processes",
			CreatedAt:        time.Now(),
			LastUpdated:      time.Now(),
			SampleCount:      0,
			Patterns:         make(map[string]int),
			TimeDistribution: make(map[int]int),
			Confidence:       0.0,
			Metadata:         make(map[string]interface{}),
		}
		dm.behaviorBaselines["processes"] = processBaseline
	}

	// Update patterns from process cache
	for key, pattern := range dm.processPatterns {
		if pattern.Behavior != nil {
			if count, exists := pattern.Behavior["execution_count"]; exists {
				processBaseline.Patterns[key] = count
				processBaseline.SampleCount += count
			}
		}
	}

	processBaseline.LastUpdated = time.Now()
	processBaseline.Confidence = math.Min(processBaseline.Confidence+0.1, 1.0)
}

// updateFileAccessBaselines updates baselines based on file access patterns
func (dm *DetectorMonitor) updateFileAccessBaselines() {
	fileBaseline := dm.behaviorBaselines["file_access"]
	if fileBaseline == nil {
		fileBaseline = &BehaviorBaseline{
			Type:             "file_access",
			CreatedAt:        time.Now(),
			LastUpdated:      time.Now(),
			SampleCount:      0,
			Patterns:         make(map[string]int),
			TimeDistribution: make(map[int]int),
			Confidence:       0.0,
			Metadata:         make(map[string]interface{}),
		}
		dm.behaviorBaselines["file_access"] = fileBaseline
	}

	// Update patterns from file access cache
	for path, pattern := range dm.fileAccessPatterns {
		fileBaseline.Patterns[path] = pattern.Frequency
		fileBaseline.SampleCount += pattern.Frequency
	}

	fileBaseline.LastUpdated = time.Now()
	fileBaseline.Confidence = math.Min(fileBaseline.Confidence+0.1, 1.0)
}

// updateTimeBasedBaselines updates time-based behavioral baselines
func (dm *DetectorMonitor) updateTimeBasedBaselines() {
	currentHour := time.Now().Hour()

	// Update time distribution for all baselines
	for _, baseline := range dm.behaviorBaselines {
		if baseline.TimeDistribution == nil {
			baseline.TimeDistribution = make(map[int]int)
		}
		baseline.TimeDistribution[currentHour]++
	}
}

// Command history analysis (enhanced from behavior_monitor.go)
func (dm *DetectorMonitor) runCommandHistoryAnalysis(ctx context.Context) {
	dm.LogEvent(zerolog.InfoLevel, "Analyzing command history patterns...")

	// Get all user home directories for comprehensive analysis
	homeDirectories := dm.getAllUserHomeDirectories()

	for _, homeDir := range homeDirectories {
		historyFiles := []string{
			filepath.Join(homeDir, ".bash_history"),
			filepath.Join(homeDir, ".zsh_history"),
			filepath.Join(homeDir, ".history"),
			// Add other shell history files
		}

		for _, historyFile := range historyFiles {
			if _, err := os.Stat(historyFile); os.IsNotExist(err) {
				continue
			}

			dm.analyzeCommandHistoryFile(ctx, historyFile, homeDir)
		}
	}

	// Analyze command patterns and detect anomalies
	dm.detectCommandAnomalies(ctx)
}

func (dm *DetectorMonitor) analyzeCommandHistoryFile(ctx context.Context, historyFile, homeDir string) {
	file, err := os.Open(historyFile)
	if err != nil {
		dm.LogEvent(zerolog.WarnLevel, "Failed to open history file").
			Str("file", historyFile).Err(err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	commands := []string{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		commands = append(commands, line)
	}

	if err := scanner.Err(); err != nil {
		dm.LogEvent(zerolog.ErrorLevel, "Error reading history file").
			Str("file", historyFile).Err(err)
		return
	}

	dm.LogEvent(zerolog.InfoLevel, "Analyzing command history file").
		Str("file", historyFile).
		Int("commands_count", len(commands))

	// Update command patterns
	dm.updateCommandPatterns(commands, historyFile)

	// Check for suspicious command sequences
	dm.checkSuspiciousCommandSequences(ctx, commands, historyFile)

	// Apply behavior rules
	dm.applyBehaviorRules(ctx, commands, historyFile)
}

func (dm *DetectorMonitor) updateCommandPatterns(commands []string, source string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	for _, command := range commands {
		// Extract base command (before first space)
		parts := strings.Fields(command)
		if len(parts) == 0 {
			continue
		}

		baseCommand := parts[0]

		// Update or create command pattern
		if pattern, exists := dm.commandPatterns[baseCommand]; exists {
			pattern.Frequency++
			pattern.LastSeen = time.Now()

			// Update arguments
			if len(parts) > 1 {
				args := strings.Join(parts[1:], " ")
				if pattern.Arguments == nil {
					pattern.Arguments = make(map[string]int)
				}
				pattern.Arguments[args]++
			}
		} else {
			pattern := &CommandPattern{
				Command:          baseCommand,
				Frequency:        1,
				TimeDistribution: make(map[int]int),
				Arguments:        make(map[string]int),
				ExitCodes:        make(map[int]int),
				AssociatedFiles:  make(map[string]int),
				LastSeen:         time.Now(),
			}

			if len(parts) > 1 {
				args := strings.Join(parts[1:], " ")
				pattern.Arguments[args] = 1
			}

			dm.commandPatterns[baseCommand] = pattern
		}
	}
}

func (dm *DetectorMonitor) checkSuspiciousCommandSequences(ctx context.Context, commands []string, source string) {
	suspiciousSequences := [][]string{
		{"wget", "chmod", "bash"},
		{"curl", "bash"},
		{"nc", "-l"},
		{"python", "-c"},
		{"perl", "-e"},
		{"base64", "-d"},
		{"echo", "bash"},
		{"cat", "/etc/passwd"},
		{"find", "/", "-name"},
		{"ps", "aux", "grep"},
	}

	for _, sequence := range suspiciousSequences {
		if dm.findCommandSequence(commands, sequence) {
			dm.PublishEvent(ctx, events.EventMalwareDetected, source,
				fmt.Sprintf("Suspicious command sequence detected: %s", strings.Join(sequence, " -> ")),
				"high", map[string]interface{}{
					"sequence":    sequence,
					"source_file": source,
					"pattern":     "command_sequence",
				})
		}
	}
}

func (dm *DetectorMonitor) findCommandSequence(commands []string, sequence []string) bool {
	if len(sequence) == 0 || len(commands) < len(sequence) {
		return false
	}

	sequenceIndex := 0
	for _, command := range commands {
		parts := strings.Fields(command)
		if len(parts) == 0 {
			continue
		}

		if strings.Contains(parts[0], sequence[sequenceIndex]) {
			sequenceIndex++
			if sequenceIndex >= len(sequence) {
				return true
			}
		}
	}

	return false
}

func (dm *DetectorMonitor) applyBehaviorRules(ctx context.Context, commands []string, source string) {
	for _, rule := range dm.detectionRules {
		if rule.Type != "command_pattern" || !rule.Enabled {
			continue
		}

		fullHistory := strings.Join(commands, "\n")
		if rule.CompiledPattern != nil && rule.CompiledPattern.MatchString(fullHistory) {
			severity := rule.Severity
			if severity == "" {
				severity = "medium"
			}

			dm.PublishEvent(ctx, events.EventMalwareDetected, source,
				fmt.Sprintf("Behavior rule match: %s", rule.Description),
				severity, map[string]interface{}{
					"rule_id":     rule.ID,
					"rule_name":   rule.Name,
					"pattern":     rule.Pattern,
					"source_file": source,
				})
		}
	}
}

// Process behavior analysis
func (dm *DetectorMonitor) runProcessBehaviorAnalysis(ctx context.Context) {
	dm.LogEvent(zerolog.InfoLevel, "Analyzing process behavior patterns...")

	processes, err := psutil.Processes()
	if err != nil {
		dm.LogEvent(zerolog.ErrorLevel, "Failed to get process list").Err(err)
		return
	}

	for _, proc := range processes {
		dm.analyzeProcess(ctx, proc)
	}

	dm.detectProcessAnomalies(ctx)
}

func (dm *DetectorMonitor) analyzeProcess(ctx context.Context, proc *psutil.Process) {
	pid := proc.Pid

	name, err := proc.Name()
	if err != nil {
		return
	}

	cmdline, _ := proc.Cmdline()
	username, _ := proc.Username()
	createTime, _ := proc.CreateTime()
	cpuPercent, _ := proc.CPUPercent()
	memPercent, _ := proc.MemoryPercent()
	status, _ := proc.Status()

	processInfo := &ProcessInfo{
		PID:             pid,
		Name:            name,
		Command:         cmdline,
		User:            username,
		CreateTime:      time.Unix(int64(createTime/1000), 0),
		LastSeen:        time.Now(),
		CPUPercent:      cpuPercent,
		MemoryPercent:   memPercent,
		Status:          status,
		BehaviorMetrics: make(map[string]float64),
	}

	// Get parent process ID
	if ppid, err := proc.Ppid(); err == nil {
		processInfo.PPID = ppid
	}

	// Calculate behavior metrics
	processInfo.BehaviorMetrics["cpu_usage"] = cpuPercent
	processInfo.BehaviorMetrics["memory_usage"] = memPercent

	// Check for suspicious behavior
	dm.checkSuspiciousProcessBehavior(ctx, processInfo)

	// Update process cache
	dm.mu.Lock()
	dm.processCache[pid] = processInfo
	dm.mu.Unlock()

	// Update process patterns
	dm.updateProcessPatterns(processInfo)
}

func (dm *DetectorMonitor) updateProcessPatterns(processInfo *ProcessInfo) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	key := fmt.Sprintf("%s_%d", processInfo.Name, processInfo.PID)

	pattern := &ProcessPattern{
		ProcessName:        processInfo.Name,
		PID:                processInfo.PID,
		PPID:               processInfo.PPID,
		Command:            processInfo.Command,
		User:               processInfo.User,
		StartTime:          processInfo.CreateTime,
		CPUPercent:         processInfo.CPUPercent,
		MemoryPercent:      processInfo.MemoryPercent,
		OpenFiles:          0, // Would need additional system calls
		NetworkConnections: 0, // Would need additional system calls
		ChildProcesses:     []int32{},
		Behavior:           map[string]int{"execution_count": 1},
		LastSeen:           processInfo.LastSeen,
	}

	if existingPattern, exists := dm.processPatterns[key]; exists {
		existingPattern.LastSeen = processInfo.LastSeen
		existingPattern.CPUPercent = processInfo.CPUPercent
		existingPattern.MemoryPercent = processInfo.MemoryPercent
		if existingPattern.Behavior == nil {
			existingPattern.Behavior = make(map[string]int)
		}
		existingPattern.Behavior["execution_count"]++
	} else {
		dm.processPatterns[key] = pattern
	}
}

func (dm *DetectorMonitor) checkSuspiciousProcessBehavior(ctx context.Context, processInfo *ProcessInfo) {
	// Check for suspicious process names
	suspiciousProcesses := dm.config.SuspiciousProcesses
	if len(suspiciousProcesses) == 0 {
		suspiciousProcesses = []string{
			"nc", "netcat", "ncat",
			"wget", "curl",
			"python", "perl", "ruby",
			"base64", "xxd",
			"dd", "cat", "tail",
		}
	}

	for _, suspicious := range suspiciousProcesses {
		if strings.Contains(processInfo.Name, suspicious) {
			dm.PublishEvent(ctx, events.EventMalwareDetected, fmt.Sprintf("pid_%d", processInfo.PID),
				fmt.Sprintf("Suspicious process detected: %s", processInfo.Name),
				"medium", map[string]interface{}{
					"process_name": processInfo.Name,
					"command":      processInfo.Command,
					"user":         processInfo.User,
					"pid":          processInfo.PID,
					"ppid":         processInfo.PPID,
				})
		}
	}

	// Check for unusual resource usage
	if processInfo.CPUPercent > 80.0 {
		dm.PublishEvent(ctx, events.EventSystemAnomaly, fmt.Sprintf("pid_%d", processInfo.PID),
			fmt.Sprintf("High CPU usage by process: %s (%.1f%%)", processInfo.Name, processInfo.CPUPercent),
			"medium", map[string]interface{}{
				"process_name": processInfo.Name,
				"cpu_percent":  processInfo.CPUPercent,
				"pid":          processInfo.PID,
			})
	}

	if processInfo.MemoryPercent > 50.0 {
		dm.PublishEvent(ctx, events.EventSystemAnomaly, fmt.Sprintf("pid_%d", processInfo.PID),
			fmt.Sprintf("High memory usage by process: %s (%.1f%%)", processInfo.Name, processInfo.MemoryPercent),
			"medium", map[string]interface{}{
				"process_name":   processInfo.Name,
				"memory_percent": processInfo.MemoryPercent,
				"pid":            processInfo.PID,
			})
	}
}
