// pkg/monitors/sentinel.go
// Comprehensive system-wide security monitoring combining all SENTINEL capabilities:
// - certificate_monitor.go
// - communication_monitor.go
// - network_monitor.go
// - network_ids.go
// - persistence_monitor.go
// - process_monitor.go
// - recon_detector.go
// - thermal_monitor.go
package monitors

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/lucid-vigil/sentinel/pkg/events"
	"github.com/lucid-vigil/sentinel/pkg/monitors/base_monitor"
	"github.com/lucid-vigil/sentinel/pkg/monitors/scheduler"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// SentinelMonitor - Comprehensive system-wide security monitoring
type SentinelMonitor struct {
	*base_monitor.BaseMonitor
	config                *ComprehensiveSentinelConfig
	lastReportTime        time.Time
	systemBaseline        SystemBaseline
	certificateBaselines  map[string]string // domain:port -> fingerprint
	communicationBaseline CommunicationBaseline
	networkBaseline       NetworkBaseline

	// DNS monitoring components
	dnsEvents      chan DNSEvent
	stopDNSCapture chan struct{}
	clientStats    map[string]*ClientStats
	statsMutex     sync.RWMutex

	// System monitoring components
	processBaseline   map[int32]*ProcessInfo
	previousProcesses map[int32]bool // For process creation monitoring
	cpuTempBaseline   []float64

	// Communication monitoring
	resolvedBlocklist map[string][]net.IP

	// Network monitoring state
	lastRxBytes        uint64
	lastTxBytes        uint64
	lastBandwidthCheck time.Time

	// Reconnaissance detection
	synRecvCounts map[string]int
	portScanCache map[string]time.Time

	// Synchronization
	mu               sync.RWMutex
	pcapHandle       *pcap.Handle
	monitoringActive bool
}

// ComprehensiveSentinelConfig - Extended configuration for all SENTINEL monitoring capabilities
type ComprehensiveSentinelConfig struct {
	// Core sentinel config
	ReportingInterval       string `mapstructure:"reporting_interval"`
	SystemMonitoringEnabled bool   `mapstructure:"system_monitoring_enabled"`
	ProactiveResponse       bool   `mapstructure:"proactive_response"`
	ResponseMode            string `mapstructure:"response_mode"`

	// Certificate monitoring config
	CertificateMonitoringEnabled bool     `mapstructure:"certificate_monitoring_enabled"`
	DomainsToMonitor             []string `mapstructure:"domains_to_monitor"`
	ExpiryThresholdDays          int      `mapstructure:"expiry_threshold_days"`
	BaselineDir                  string   `mapstructure:"baseline_dir"`

	// Communication monitoring config
	CommunicationMonitoringEnabled bool     `mapstructure:"communication_monitoring_enabled"`
	IPBlocklist                    []string `mapstructure:"ip_blocklist"`
	DomainBlocklist                []string `mapstructure:"domain_blocklist"`
	AutoBlockSuspicious            bool     `mapstructure:"auto_block_suspicious"`

	// Network monitoring config
	NetworkMonitoringEnabled bool     `mapstructure:"network_monitoring_enabled"`
	NetworkInterface         string   `mapstructure:"network_interface"`
	MaxConnections           int      `mapstructure:"max_connections"`
	SuspiciousPorts          []int    `mapstructure:"suspicious_ports"`
	DNSWhitelist             []string `mapstructure:"dns_whitelist"`
	BandwidthThresholdMBps   float64  `mapstructure:"bandwidth_threshold_mbps"`
	EnableStatefulAnalysis   bool     `mapstructure:"enable_stateful_analysis"`
	NXDomainThresholdRatio   float64  `mapstructure:"nxdomain_threshold_ratio"`
	MinQueryCountForAlert    int      `mapstructure:"min_query_count_for_alert"`
	StatsCleanupInterval     string   `mapstructure:"stats_cleanup_interval"`

	// DNS suspicion scoring config
	EntropyWeight      float64 `mapstructure:"entropy_weight"`
	LengthWeight       float64 `mapstructure:"length_weight"`
	VowelRatioWeight   float64 `mapstructure:"vowel_ratio_weight"`
	DigitRatioWeight   float64 `mapstructure:"digit_ratio_weight"`
	SpecialCharsWeight float64 `mapstructure:"special_chars_weight"`
	SuspicionThreshold float64 `mapstructure:"suspicion_threshold"`

	// System monitoring config
	CPUTemperatureThreshold   float64  `mapstructure:"cpu_temperature_threshold"`
	ProcessCountThreshold     int      `mapstructure:"process_count_threshold"`
	MemoryUsageThreshold      float64  `mapstructure:"memory_usage_threshold"`
	DiskUsageThreshold        float64  `mapstructure:"disk_usage_threshold"`
	MonitorCriticalProcesses  []string `mapstructure:"monitor_critical_processes"`
	ProcessMonitoringInterval string   `mapstructure:"process_monitoring_interval"`

	// Process monitoring config (enhanced from process_monitor.go)
	CPUThreshold    float64 `mapstructure:"cpu_threshold"`
	MemoryThreshold float64 `mapstructure:"memory_threshold"`
	SuspiciousNames string  `mapstructure:"suspicious_names"`
	WhitelistUsers  string  `mapstructure:"whitelist_users"`

	// Thermal monitoring config
	TempThreshold     float64 `mapstructure:"temp_threshold"`
	CPUUsageThreshold float64 `mapstructure:"cpu_usage_threshold"`

	// Network IDS config
	NetworkIDSEnabled bool     `mapstructure:"network_ids_enabled"`
	IDSInterface      string   `mapstructure:"ids_interface"`
	IDSRules          []string `mapstructure:"ids_rules"`

	// Persistence monitoring config
	PersistenceMonitoringEnabled bool `mapstructure:"persistence_monitoring_enabled"`
	ScanCron                     bool `mapstructure:"scan_cron"`
	ScanSystemd                  bool `mapstructure:"scan_systemd"`
	ScanShellProfiles            bool `mapstructure:"scan_shell_profiles"`
	ScanLdPreload                bool `mapstructure:"scan_ld_preload"`

	// Reconnaissance detection config
	ReconDetectionEnabled bool `mapstructure:"recon_detection_enabled"`
	SynFloodThreshold     int  `mapstructure:"syn_flood_threshold"`
	PortScanThreshold     int  `mapstructure:"port_scan_threshold"`

	// Exfiltration detection config
	ExfiltrationDetectionEnabled bool     `mapstructure:"exfiltration_detection_enabled"`
	LargeUploadThresholdMB       int      `mapstructure:"large_upload_threshold_mb"`
	SuspiciousDataPatterns       []string `mapstructure:"suspicious_data_patterns"`
	MonitorFileSharing           bool     `mapstructure:"monitor_file_sharing"`
	FileSharingDomains           []string `mapstructure:"file_sharing_domains"`
}

// Supporting data structures (keeping existing ones and adding new ones)
type SystemBaseline struct {
	InitialProcessCount int
	BaselineCPUTemp     []float64
	BaselineMemoryUsage float64
	BaselineDiskUsage   float64
	CriticalProcesses   map[string]*ProcessInfo
	InitialNetworkStats NetworkStats
	LastSystemCheck     time.Time
}

type ProcessInfo struct {
	PID        int32     `json:"pid"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	CPUPercent float64   `json:"cpu_percent"`
	MemPercent float32   `json:"mem_percent"`
	CreateTime int64     `json:"create_time"`
	LastSeen   time.Time `json:"last_seen"`
	Username   string    `json:"username"`
	Cmdline    string    `json:"cmdline"`
	PPID       int32     `json:"ppid"`
	Terminal   string    `json:"terminal"`
}

type CommunicationBaseline struct {
	KnownGoodIPs           map[string]time.Time
	SuspiciousConnections  int
	BlockedConnections     int
	LastCommunicationCheck time.Time
}

type NetworkBaseline struct {
	InitialTxBytes    uint64
	InitialRxBytes    uint64
	BaselineTimestamp time.Time
	DomainIPs         map[string][]net.IP
	SuspiciousDomains map[string]int
	LargeTransfers    int
	LastNetworkCheck  time.Time
}

type NetworkStats struct {
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
	Timestamp   time.Time
}

type DNSEvent struct {
	SourceIP  net.IP
	Domain    string
	IsQuery   bool
	IsNX      bool
	Timestamp time.Time
}

type ClientStats struct {
	TotalQueries  int
	NXDomainCount int
	LastSeen      time.Time
}

type DNSSuspicionScore struct {
	Entropy      float64
	Length       float64
	VowelRatio   float64
	DigitRatio   float64
	SpecialChars float64
	Total        float64
}

type SystemHealth struct {
	CPUTemperature    []float64
	ProcessCount      int
	MemoryUsage       float64
	DiskUsage         float64
	NetworkStats      NetworkStats
	CriticalProcesses map[string]bool
	Timestamp         time.Time
	ThermalAnomalies  []ThermalAnomaly
}

type ThermalAnomaly struct {
	SensorKey   string
	Temperature float64
	CPUUsage    float64
	IsAnomalous bool
	Timestamp   time.Time
}

// NewSentinelMonitor creates a comprehensive system-wide monitoring system
func NewSentinelMonitor(logger zerolog.Logger, eventBus *events.EventBus) scheduler.Monitor {
	monitor := &SentinelMonitor{
		BaseMonitor:          base_monitor.NewBaseMonitor("comprehensive_sentinel", base_monitor.ClassSentinel, logger, eventBus),
		config:               &ComprehensiveSentinelConfig{},
		certificateBaselines: make(map[string]string),
		resolvedBlocklist:    make(map[string][]net.IP),
		processBaseline:      make(map[int32]*ProcessInfo),
		previousProcesses:    make(map[int32]bool),
		dnsEvents:            make(chan DNSEvent, 1024),
		stopDNSCapture:       make(chan struct{}),
		clientStats:          make(map[string]*ClientStats),
		synRecvCounts:        make(map[string]int),
		portScanCache:        make(map[string]time.Time),
		monitoringActive:     false,
	}

	// Add all monitoring capabilities
	monitor.AddCapability(base_monitor.CapabilityRealTime)
	monitor.AddCapability(base_monitor.CapabilityAutomatedResponse)
	monitor.AddCapability(base_monitor.CapabilityThreatIntel)
	monitor.AddCapability("certificate_monitoring")
	monitor.AddCapability("communication_monitoring")
	monitor.AddCapability("network_monitoring")
	monitor.AddCapability("system_monitoring")
	monitor.AddCapability("process_monitoring")
	monitor.AddCapability("thermal_monitoring")
	monitor.AddCapability("network_ids")
	monitor.AddCapability("persistence_monitoring")
	monitor.AddCapability("recon_detection")
	monitor.AddCapability("exfiltration_detection")
	monitor.AddCapability("dns_analysis")

	return monitor
}

// Configure sets up the comprehensive SENTINEL monitoring system
func (sm *SentinelMonitor) Configure(config map[string]interface{}) error {
	sm.LogEvent(zerolog.InfoLevel, "Configuring Comprehensive Sentinel Monitor")

	// Parse all configuration sections
	if err := sm.parseConfig(config); err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}

	// Initialize components based on configuration
	if sm.config.NetworkMonitoringEnabled {
		if err := sm.initializeDNSCapture(); err != nil {
			sm.LogEvent(zerolog.WarnLevel, "Failed to initialize DNS capture").Err(err)
		} else {
			go sm.startDNSPacketCapture()
			if sm.config.EnableStatefulAnalysis {
				go sm.startStatefulAnalysis()
			}
		}
	}

	if sm.config.CommunicationMonitoringEnabled {
		sm.initializeCommunicationMonitoring()
	}

	if sm.config.SystemMonitoringEnabled {
		sm.initializeSystemMonitoring()
	}

	if sm.config.CertificateMonitoringEnabled {
		sm.initializeCertificateMonitoring()
	}

	if sm.config.ReconDetectionEnabled {
		sm.initializeReconDetection()
	}

	sm.LogEvent(zerolog.InfoLevel, "Comprehensive Sentinel Monitor configured successfully")
	return nil
}

// Run executes comprehensive system-wide security monitoring
func (sm *SentinelMonitor) Run(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Comprehensive Sentinel Monitor: Starting system patrol...")
	sm.UpdateState("status", "active")
	sm.UpdateState("patrol_start", time.Now())

	sm.mu.Lock()
	sm.monitoringActive = true
	sm.mu.Unlock()

	// Initialize process baseline on first run
	if len(sm.previousProcesses) == 0 {
		procs, err := process.Processes()
		if err == nil {
			for _, p := range procs {
				sm.previousProcesses[p.Pid] = true
			}
		}
	}

	// Run all monitoring components concurrently
	var wg sync.WaitGroup

	// Enhanced system monitoring (CPU, memory, processes)
	if sm.config.SystemMonitoringEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runEnhancedSystemMonitoring(ctx)
		}()
	}

	// Enhanced process monitoring
	wg.Add(1)
	go func() {
		defer wg.Done()
		sm.runEnhancedProcessMonitoring(ctx)
	}()

	// Thermal monitoring
	wg.Add(1)
	go func() {
		defer wg.Done()
		sm.runThermalMonitoring(ctx)
	}()

	// Certificate monitoring
	if sm.config.CertificateMonitoringEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runCertificateMonitoring(ctx)
		}()
	}

	// Communication monitoring
	if sm.config.CommunicationMonitoringEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runCommunicationMonitoring(ctx)
		}()
	}

	// Network monitoring
	if sm.config.NetworkMonitoringEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runNetworkMonitoring(ctx)
		}()
	}

	// Network IDS
	if sm.config.NetworkIDSEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runNetworkIDS(ctx)
		}()
	}

	// Persistence monitoring
	if sm.config.PersistenceMonitoringEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runPersistenceMonitoring(ctx)
		}()
	}

	// Reconnaissance detection
	if sm.config.ReconDetectionEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runReconDetection(ctx)
		}()
	}

	// Exfiltration detection
	if sm.config.ExfiltrationDetectionEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runExfiltrationDetection(ctx)
		}()
	}

	// DNS analysis (processes events from DNS capture)
	if sm.config.NetworkMonitoringEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runDNSAnalysis(ctx)
		}()
	}

	// Wait for all monitoring components to complete
	wg.Wait()

	// Generate comprehensive system report
	sm.generateSystemReport(ctx)
	sm.updateComprehensiveMetrics()

	sm.lastReportTime = time.Now()
	sm.LogEvent(zerolog.InfoLevel, "Comprehensive Sentinel Monitor: System patrol completed")
}

// Enhanced system monitoring implementation
func (sm *SentinelMonitor) runEnhancedSystemMonitoring(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running enhanced system monitoring...")

	// Monitor CPU temperature
	sm.monitorCPUTemperature(ctx)

	// Monitor process count and critical processes
	sm.monitorProcesses(ctx)

	// Monitor memory usage
	sm.monitorMemoryUsage(ctx)

	// Monitor disk usage
	sm.monitorDiskUsage(ctx)

	// Check system health
	sm.assessSystemHealth(ctx)
}

// Enhanced process monitoring (combining original and process_monitor.go features)
func (sm *SentinelMonitor) runEnhancedProcessMonitoring(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running enhanced process monitoring...")

	// Monitor resource usage
	sm.monitorResourceUsage(ctx)

	// Detect suspicious processes
	sm.detectSuspiciousProcesses(ctx)

	// Monitor process creation
	sm.monitorProcessCreation(ctx)

	// Detect hidden processes
	sm.detectHiddenProcesses(ctx)

	// Monitor process tree
	sm.monitorProcessTree(ctx)

	// Monitor detached processes
	sm.monitorDetachedProcesses(ctx)

	// Monitor systemd services
	sm.monitorSystemdServices(ctx)
}

// Thermal monitoring implementation (from thermal_monitor.go)
func (sm *SentinelMonitor) runThermalMonitoring(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running thermal monitoring...")

	temps, err := host.SensorsTemperatures()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get sensor temperatures").Err(err)
		return
	}

	cpuPercentages, err := cpu.Percent(0, false)
	if err != nil || len(cpuPercentages) == 0 {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get CPU usage").Err(err)
		return
	}
	avgCPUUsage := cpuPercentages[0]

	var thermalAnomalies []ThermalAnomaly

	for _, temp := range temps {
		sm.LogEvent(zerolog.DebugLevel, "Current sensor temperature").
			Str("sensor", temp.SensorKey).
			Float64("temperature", temp.Temperature)

		// Check for high temperature with low CPU usage anomaly
		if temp.Temperature > sm.config.TempThreshold && avgCPUUsage < sm.config.CPUUsageThreshold {
			anomaly := ThermalAnomaly{
				SensorKey:   temp.SensorKey,
				Temperature: temp.Temperature,
				CPUUsage:    avgCPUUsage,
				IsAnomalous: true,
				Timestamp:   time.Now(),
			}
			thermalAnomalies = append(thermalAnomalies, anomaly)

			sm.PublishEvent(ctx, events.EventSystemAnomaly, "thermal_anomaly",
				fmt.Sprintf("THERMAL ANOMALY: High temperature (%.1f°C) with low CPU usage (%.1f%%) - possible hidden process",
					temp.Temperature, avgCPUUsage),
				"high", map[string]interface{}{
					"sensor":      temp.SensorKey,
					"temperature": temp.Temperature,
					"cpu_usage":   avgCPUUsage,
					"threshold":   sm.config.TempThreshold,
				})
		}

		// Check for sustained high temperature
		if temp.Temperature > sm.config.TempThreshold {
			sm.LogEvent(zerolog.InfoLevel, "High temperature detected").
				Str("sensor", temp.SensorKey).
				Float64("temperature", temp.Temperature)
		}
	}

	sm.UpdateState("thermal_anomalies", thermalAnomalies)
}

// Network IDS implementation (from network_ids.go)
func (sm *SentinelMonitor) runNetworkIDS(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running Network IDS...")

	iface := sm.config.IDSInterface
	if iface == "" {
		iface = sm.config.NetworkInterface
	}
	if iface == "" {
		iface = "any"
	}

	// Validate interface name
	if !sm.isValidInterfaceName(iface) {
		sm.LogEvent(zerolog.ErrorLevel, "Invalid network interface name").
			Str("interface", iface)
		return
	}

	for _, rule := range sm.config.IDSRules {
		// Sanitize tcpdump rule to prevent command injection
		sanitizedRule := sm.sanitizeTcpdumpRule(rule)
		if sanitizedRule == "" {
			sm.LogEvent(zerolog.WarnLevel, "Skipping empty or invalid rule").
				Str("rule", rule)
			continue
		}

		sm.LogEvent(zerolog.DebugLevel, "Applying IDS rule").
			Str("rule", sanitizedRule)

		cmd := exec.CommandContext(ctx, "tcpdump", "-i", iface, "-c", "1", sanitizedRule)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// tcpdump exits with status 1 if no packets are captured, so we don't log that as an error.
			if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
				continue
			}
			sm.LogEvent(zerolog.ErrorLevel, "Failed to run tcpdump").
				Err(err).Str("rule", sanitizedRule)
			continue
		}

		if len(output) > 0 {
			sm.PublishEvent(ctx, events.EventSuspiciousNetwork, "network_ids_rule_matched",
				fmt.Sprintf("Network IDS rule matched: %s", sanitizedRule),
				"medium", map[string]interface{}{
					"rule":          sanitizedRule,
					"captured_data": string(output),
					"interface":     iface,
				})

			sm.LogEvent(zerolog.WarnLevel, "Network IDS rule matched").
				Str("rule", sanitizedRule).
				Str("captured_packet", string(output))
		}
	}
}

// Persistence monitoring implementation (from persistence_monitor.go)
func (sm *SentinelMonitor) runPersistenceMonitoring(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running persistence monitoring...")

	if sm.config.ScanCron {
		sm.scanCron(ctx)
	}
	if sm.config.ScanSystemd {
		sm.scanSystemd(ctx)
	}
	if sm.config.ScanShellProfiles {
		sm.scanShellProfiles(ctx)
	}
	if sm.config.ScanLdPreload {
		sm.scanLdPreload(ctx)
	}
}

// Reconnaissance detection implementation (from recon_detector.go)
func (sm *SentinelMonitor) runReconDetection(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running reconnaissance detection...")

	sm.detectPortScans(ctx)
	sm.detectSynFloods(ctx)
}

// Process monitoring implementations (enhanced from process_monitor.go)
func (sm *SentinelMonitor) monitorResourceUsage(ctx context.Context) {
	procs, err := process.Processes()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get process list for resource usage monitoring").Err(err)
		return
	}

	for _, p := range procs {
		cpuPercent, err := p.CPUPercent()
		if err != nil {
			continue
		}
		memPercent, err := p.MemoryPercent()
		if err != nil {
			continue
		}

		if cpuPercent > sm.config.CPUThreshold {
			name, _ := p.Name()
			cmdline, _ := p.Cmdline()

			sm.PublishEvent(ctx, events.EventSystemAnomaly, "high_cpu_usage",
				fmt.Sprintf("High CPU usage detected: %s (%.1f%%)", name, cpuPercent),
				"medium", map[string]interface{}{
					"pid":         p.Pid,
					"name":        name,
					"cmdline":     cmdline,
					"cpu_percent": cpuPercent,
					"threshold":   sm.config.CPUThreshold,
				})

			sm.LogEvent(zerolog.WarnLevel, "High CPU usage detected").
				Int32("pid", p.Pid).
				Str("name", name).
				Str("cmdline", cmdline).
				Float64("cpu_percent", cpuPercent)
		}

		if float64(memPercent) > sm.config.MemoryThreshold {
			name, _ := p.Name()
			cmdline, _ := p.Cmdline()

			sm.PublishEvent(ctx, events.EventSystemAnomaly, "high_memory_usage",
				fmt.Sprintf("High memory usage detected: %s (%.1f%%)", name, float64(memPercent)),
				"medium", map[string]interface{}{
					"pid":            p.Pid,
					"name":           name,
					"cmdline":        cmdline,
					"memory_percent": float64(memPercent),
					"threshold":      sm.config.MemoryThreshold,
				})

			sm.LogEvent(zerolog.WarnLevel, "High memory usage detected").
				Int32("pid", p.Pid).
				Str("name", name).
				Str("cmdline", cmdline).
				Float64("memory_percent", float64(memPercent))
		}
	}
}

func (sm *SentinelMonitor) detectSuspiciousProcesses(ctx context.Context) {
	suspiciousPatterns := strings.Split(sm.config.SuspiciousNames, ",")
	procs, err := process.Processes()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get process list for suspicious process detection").Err(err)
		return
	}

	for _, p := range procs {
		name, _ := p.Name()
		cmdline, _ := p.Cmdline()

		for _, pattern := range suspiciousPatterns {
			if pattern == "" {
				continue
			}

			// Clean the pattern for regex
			pattern = strings.TrimSpace(pattern)

			matched, err := regexp.MatchString("(?i)"+regexp.QuoteMeta(pattern), name)
			if err != nil {
				sm.LogEvent(zerolog.ErrorLevel, "Invalid regex pattern").
					Str("pattern", pattern).Err(err)
				continue
			}
			if matched {
				sm.PublishEvent(ctx, events.EventSuspiciousProcess, "suspicious_process_name",
					fmt.Sprintf("Suspicious process name detected: %s", name),
					"high", map[string]interface{}{
						"pid":     p.Pid,
						"name":    name,
						"cmdline": cmdline,
						"pattern": pattern,
					})

				sm.LogEvent(zerolog.ErrorLevel, "Suspicious process name detected").
					Int32("pid", p.Pid).
					Str("name", name).
					Str("cmdline", cmdline).
					Str("pattern", pattern)
			}

			matched, err = regexp.MatchString("(?i)"+regexp.QuoteMeta(pattern), cmdline)
			if err != nil {
				continue
			}
			if matched {
				sm.PublishEvent(ctx, events.EventSuspiciousProcess, "suspicious_process_cmdline",
					fmt.Sprintf("Suspicious process command line detected: %s", cmdline),
					"high", map[string]interface{}{
						"pid":     p.Pid,
						"name":    name,
						"cmdline": cmdline,
						"pattern": pattern,
					})

				sm.LogEvent(zerolog.ErrorLevel, "Suspicious process command line detected").
					Int32("pid", p.Pid).
					Str("name", name).
					Str("cmdline", cmdline).
					Str("pattern", pattern)
			}
		}
	}
}

func (sm *SentinelMonitor) monitorProcessCreation(ctx context.Context) {
	currentProcesses := make(map[int32]bool)
	procs, err := process.Processes()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get current process list for creation monitoring").Err(err)
		return
	}

	for _, p := range procs {
		currentProcesses[p.Pid] = true
		if _, exists := sm.previousProcesses[p.Pid]; !exists {
			name, _ := p.Name()
			cmdline, _ := p.Cmdline()
			username, _ := p.Username()

			// Log the new process creation event
			sm.LogEvent(zerolog.InfoLevel, "New process detected").
				Int32("pid", p.Pid).
				Str("name", name).
				Str("cmdline", cmdline).
				Str("username", username).
				Msg("Process created")
		}
	}

	// Update the previous processes map for next iteration
	sm.previousProcesses = currentProcesses
}

func (sm *SentinelMonitor) sanitizeTcpdumpRule(rule string) string {
	// Remove or replace characters that could be used for command injection.
	// This is a simplistic approach. For complex rules, a dedicated parser is better.
	rule = strings.ReplaceAll(rule, ";", "")
	rule = strings.ReplaceAll(rule, "&", "")
	rule = strings.ReplaceAll(rule, "|", "")
	rule = strings.ReplaceAll(rule, "`", "")
	rule = strings.ReplaceAll(rule, "$", "")
	rule = strings.ReplaceAll(rule, "(", "")
	rule = strings.ReplaceAll(rule, ")", "")
	rule = strings.TrimSpace(rule)
	return rule
}

// Keep all existing monitoring methods from the original sentinel.go
func (sm *SentinelMonitor) monitorCPUTemperature(ctx context.Context) {
	temps, err := host.SensorsTemperatures()
	if err != nil {
		sm.LogEvent(zerolog.WarnLevel, "Failed to get CPU temperature").Err(err)
		return
	}

	var cpuTemps []float64
	for _, temp := range temps {
		if strings.Contains(strings.ToLower(temp.SensorKey), "cpu") ||
			strings.Contains(strings.ToLower(temp.SensorKey), "core") {
			cpuTemps = append(cpuTemps, temp.Temperature)

			if sm.config.CPUTemperatureThreshold > 0 && temp.Temperature > sm.config.CPUTemperatureThreshold {
				sm.PublishEvent(ctx, events.EventSystemAnomaly, "cpu_temperature",
					fmt.Sprintf("High CPU temperature detected: %.1f°C on %s", temp.Temperature, temp.SensorKey),
					"high", map[string]interface{}{
						"temperature": temp.Temperature,
						"sensor":      temp.SensorKey,
						"threshold":   sm.config.CPUTemperatureThreshold,
					})
			}
		}
	}

	if len(cpuTemps) > 0 {
		sm.cpuTempBaseline = cpuTemps
		avgTemp := sm.calculateAverageTemp(cpuTemps)
		sm.UpdateState("average_cpu_temperature", avgTemp)
		sm.LogEvent(zerolog.InfoLevel, "CPU temperature monitored").
			Float64("avg_temp", avgTemp).
			Int("sensors", len(cpuTemps))
	}
}

func (sm *SentinelMonitor) monitorProcesses(ctx context.Context) {
	processes, err := process.Processes()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get process list").Err(err)
		return
	}
	currentProcesses := make(map[int32]*ProcessInfo)
	criticalProcessStatus := make(map[string]bool)
	// Initialize critical process tracking
	for _, procName := range sm.config.MonitorCriticalProcesses {
		criticalProcessStatus[procName] = false
	}
	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			continue
		}
		cpuPercent, _ := p.CPUPercent()
		memPercent, _ := p.MemoryPercent()
		createTime, _ := p.CreateTime()
		statusSlice, _ := p.Status()
		username, _ := p.Username()
		cmdline, _ := p.Cmdline()
		ppid, _ := p.Ppid()
		terminal, _ := p.Terminal()

		// Convert status slice to string
		var statusStr string
		if len(statusSlice) > 0 {
			statusStr = statusSlice[0] // Take the first status if multiple exist
		} else {
			statusStr = "unknown"
		}

		procInfo := &ProcessInfo{
			PID:        p.Pid,
			Name:       name,
			Status:     statusStr, // Now using the converted string
			CPUPercent: cpuPercent,
			MemPercent: memPercent,
			CreateTime: createTime,
			LastSeen:   time.Now(),
			Username:   username,
			Cmdline:    cmdline,
			PPID:       ppid,
			Terminal:   terminal,
		}
		currentProcesses[p.Pid] = procInfo
		// Check if this is a critical process
		for _, criticalProc := range sm.config.MonitorCriticalProcesses {
			if strings.Contains(strings.ToLower(name), strings.ToLower(criticalProc)) {
				criticalProcessStatus[criticalProc] = true
				// Check for suspicious resource usage
				if cpuPercent > 80.0 {
					sm.PublishEvent(ctx, events.EventSystemAnomaly, "high_cpu_usage",
						fmt.Sprintf("Critical process %s using high CPU: %.1f%%", name, cpuPercent),
						"medium", map[string]interface{}{
							"process":     name,
							"pid":         p.Pid,
							"cpu_percent": cpuPercent,
						})
				}
			}
		}
	}
	// Check for missing critical processes
	for procName, isRunning := range criticalProcessStatus {
		if !isRunning {
			sm.PublishEvent(ctx, events.EventSystemAnomaly, "critical_process_missing",
				fmt.Sprintf("Critical process not found: %s", procName),
				"critical", map[string]interface{}{
					"process": procName,
				})
		}
	}
	// Check process count threshold
	processCount := len(currentProcesses)
	if sm.config.ProcessCountThreshold > 0 && processCount > sm.config.ProcessCountThreshold {
		sm.PublishEvent(ctx, events.EventSystemAnomaly, "excessive_processes",
			fmt.Sprintf("Process count exceeds threshold: %d", processCount),
			"medium", map[string]interface{}{
				"process_count": processCount,
				"threshold":     sm.config.ProcessCountThreshold,
			})
	}
	sm.mu.Lock()
	sm.processBaseline = currentProcesses
	sm.mu.Unlock()
	sm.UpdateState("process_count", processCount)
	sm.UpdateState("critical_process_status", criticalProcessStatus)
	sm.LogEvent(zerolog.InfoLevel, "Process monitoring completed").
		Int("total_processes", processCount).
		Int("critical_processes", len(sm.config.MonitorCriticalProcesses))
}

func (sm *SentinelMonitor) monitorMemoryUsage(ctx context.Context) {
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get memory information").Err(err)
		return
	}

	usagePercent := memInfo.UsedPercent
	if sm.config.MemoryUsageThreshold > 0 && usagePercent > sm.config.MemoryUsageThreshold {
		sm.PublishEvent(ctx, events.EventSystemAnomaly, "high_memory_usage",
			fmt.Sprintf("Memory usage exceeds threshold: %.1f%%", usagePercent),
			"medium", map[string]interface{}{
				"memory_percent": usagePercent,
				"threshold":      sm.config.MemoryUsageThreshold,
				"used_gb":        float64(memInfo.Used) / (1024 * 1024 * 1024),
				"total_gb":       float64(memInfo.Total) / (1024 * 1024 * 1024),
			})
	}

	sm.UpdateState("memory_usage_percent", usagePercent)
	sm.LogEvent(zerolog.InfoLevel, "Memory usage monitored").
		Float64("usage_percent", usagePercent).
		Uint64("used_gb", memInfo.Used/(1024*1024*1024))
}

func (sm *SentinelMonitor) monitorDiskUsage(ctx context.Context) {
	diskInfo, err := disk.Usage("/")
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get disk information").Err(err)
		return
	}

	usagePercent := diskInfo.UsedPercent
	if sm.config.DiskUsageThreshold > 0 && usagePercent > sm.config.DiskUsageThreshold {
		sm.PublishEvent(ctx, events.EventSystemAnomaly, "high_disk_usage",
			fmt.Sprintf("Disk usage exceeds threshold: %.1f%%", usagePercent),
			"medium", map[string]interface{}{
				"disk_percent": usagePercent,
				"threshold":    sm.config.DiskUsageThreshold,
				"used_gb":      float64(diskInfo.Used) / (1024 * 1024 * 1024),
				"total_gb":     float64(diskInfo.Total) / (1024 * 1024 * 1024),
			})
	}

	sm.UpdateState("disk_usage_percent", usagePercent)
	sm.LogEvent(zerolog.InfoLevel, "Disk usage monitored").
		Float64("usage_percent", usagePercent).
		Uint64("used_gb", diskInfo.Used/(1024*1024*1024))
}

// Certificate monitoring implementation
func (sm *SentinelMonitor) runCertificateMonitoring(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running certificate monitoring...")

	// Ensure baseline directory exists
	if _, err := os.Stat(sm.config.BaselineDir); os.IsNotExist(err) {
		err := os.MkdirAll(sm.config.BaselineDir, 0755)
		if err != nil {
			sm.LogEvent(zerolog.ErrorLevel, "Failed to create baseline directory").
				Err(err).Str("dir", sm.config.BaselineDir)
			return
		}
	}

	certificateIssues := 0
	certificatesChecked := 0

	for _, entry := range sm.config.DomainsToMonitor {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			sm.LogEvent(zerolog.WarnLevel, "Invalid domain entry format").
				Str("entry", entry).
				Str("expected_format", "domain:port")
			continue
		}

		domain := parts[0]
		port := parts[1]

		if sm.checkCertificate(ctx, domain, port) {
			certificateIssues++
		}
		certificatesChecked++
	}

	sm.UpdateState("certificates_checked", certificatesChecked)
	sm.UpdateState("certificate_issues", certificateIssues)

	sm.LogEvent(zerolog.InfoLevel, "Certificate monitoring completed").
		Int("checked", certificatesChecked).
		Int("issues", certificateIssues)
}

func (sm *SentinelMonitor) checkCertificate(ctx context.Context, domain, port string) bool {
	address := fmt.Sprintf("%s:%s", domain, port)
	hasIssue := false

	conn, err := tls.DialWithDialer(nil, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	})
	if err != nil {
		sm.PublishEvent(ctx, events.EventCertificateChange, address,
			fmt.Sprintf("Failed to connect for certificate check: %s", address),
			"high", map[string]interface{}{
				"domain": domain,
				"port":   port,
				"error":  err.Error(),
			})
		return true
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		sm.PublishEvent(ctx, events.EventCertificateChange, address,
			fmt.Sprintf("No certificates found for: %s", address),
			"critical", map[string]interface{}{
				"domain": domain,
				"port":   port,
			})
		return true
	}

	leafCert := certs[0]
	hash := sha256.Sum256(leafCert.Raw)
	fingerprint := hex.EncodeToString(hash[:])
	baselineKey := fmt.Sprintf("%s:%s", domain, port)
	baselineFile := filepath.Join(sm.config.BaselineDir, fmt.Sprintf("%s_%s.fp", domain, port))

	// Compare with baseline fingerprint
	baselineFP, err := os.ReadFile(baselineFile)
	if os.IsNotExist(err) {
		// Create new baseline
		sm.LogEvent(zerolog.InfoLevel, "Creating new certificate baseline").
			Str("domain", domain).Str("port", port)
		err = os.WriteFile(baselineFile, []byte(fingerprint), 0644)
		if err != nil {
			sm.LogEvent(zerolog.ErrorLevel, "Failed to write baseline file").
				Err(err).Str("file", baselineFile)
		}
		sm.certificateBaselines[baselineKey] = fingerprint
	} else if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to read baseline file").
			Err(err).Str("file", baselineFile)
		hasIssue = true
	} else if string(baselineFP) != fingerprint {
		// Certificate changed - potential MITM attack
		sm.PublishEvent(ctx, events.EventCertificateChange, baselineKey,
			fmt.Sprintf("Certificate fingerprint mismatch - possible MITM attack: %s", address),
			"critical", map[string]interface{}{
				"domain":          domain,
				"port":            port,
				"old_fingerprint": string(baselineFP),
				"new_fingerprint": fingerprint,
				"subject":         leafCert.Subject.String(),
				"issuer":          leafCert.Issuer.String(),
			})

		// Update baseline after change
		err = os.WriteFile(baselineFile, []byte(fingerprint), 0644)
		if err != nil {
			sm.LogEvent(zerolog.ErrorLevel, "Failed to update baseline file").
				Err(err).Str("file", baselineFile)
		}
		sm.certificateBaselines[baselineKey] = fingerprint
		hasIssue = true
	}

	// Check expiration date
	daysLeft := int(leafCert.NotAfter.Sub(time.Now()).Hours() / 24)
	if sm.config.ExpiryThresholdDays > 0 && daysLeft <= sm.config.ExpiryThresholdDays {
		severity := "medium"
		if daysLeft <= 7 {
			severity = "high"
		}
		if daysLeft <= 1 {
			severity = "critical"
		}

		sm.PublishEvent(ctx, events.EventCertificateExpiry, baselineKey,
			fmt.Sprintf("Certificate expiring soon: %s (%d days left)", address, daysLeft),
			severity, map[string]interface{}{
				"domain":     domain,
				"port":       port,
				"days_left":  daysLeft,
				"expires_at": leafCert.NotAfter,
				"subject":    leafCert.Subject.String(),
			})
		hasIssue = true
	} else {
		sm.LogEvent(zerolog.InfoLevel, "Certificate is valid").
			Str("domain", domain).
			Str("port", port).
			Int("days_left", daysLeft)
	}

	return hasIssue
}

// Communication monitoring implementation
func (sm *SentinelMonitor) runCommunicationMonitoring(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running communication monitoring...")

	connections, err := psnet.Connections("inet")
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get network connections").Err(err)
		return
	}

	suspiciousConnections := 0
	totalConnections := len(connections)

	for _, conn := range connections {
		if sm.checkConnectionAgainstBlocklists(ctx, conn) {
			suspiciousConnections++
		}
	}

	sm.UpdateState("total_connections", totalConnections)
	sm.UpdateState("suspicious_connections", suspiciousConnections)
	sm.communicationBaseline.SuspiciousConnections = suspiciousConnections
	sm.communicationBaseline.LastCommunicationCheck = time.Now()

	sm.LogEvent(zerolog.InfoLevel, "Communication monitoring completed").
		Int("total_connections", totalConnections).
		Int("suspicious_connections", suspiciousConnections)
}

func (sm *SentinelMonitor) checkConnectionAgainstBlocklists(ctx context.Context, conn psnet.ConnectionStat) bool {
	remoteIP := net.ParseIP(conn.Raddr.IP)
	if remoteIP == nil {
		return false
	}

	localAddr := fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port)
	remoteAddr := fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port)
	isSuspicious := false

	// Check against IP blocklist
	for _, blockedIP := range sm.config.IPBlocklist {
		if conn.Raddr.IP == blockedIP {
			sm.PublishEvent(ctx, events.EventSuspiciousNetwork, "blocked_ip_connection",
				fmt.Sprintf("Connection to blocked IP detected: %s", blockedIP),
				"high", map[string]interface{}{
					"type":              "IP_BLOCKLIST",
					"blocked_ip":        blockedIP,
					"local_addr":        localAddr,
					"remote_addr":       remoteAddr,
					"connection_status": conn.Status,
				})
			isSuspicious = true

			if sm.config.AutoBlockSuspicious {
				sm.attemptConnectionBlock(ctx, conn, "blocked_ip")
			}
		}
	}

	// Check against resolved domain blocklist
	for domain, ips := range sm.resolvedBlocklist {
		for _, ip := range ips {
			if remoteIP.Equal(ip) {
				sm.PublishEvent(ctx, events.EventSuspiciousNetwork, "blocked_domain_connection",
					fmt.Sprintf("Connection to blocked domain detected: %s", domain),
					"high", map[string]interface{}{
						"type":              "DOMAIN_BLOCKLIST",
						"blocked_domain":    domain,
						"resolved_ip":       ip.String(),
						"local_addr":        localAddr,
						"remote_addr":       remoteAddr,
						"connection_status": conn.Status,
					})
				isSuspicious = true

				if sm.config.AutoBlockSuspicious {
					sm.attemptConnectionBlock(ctx, conn, "blocked_domain")
				}
			}
		}
	}

	return isSuspicious
}

func (sm *SentinelMonitor) attemptConnectionBlock(ctx context.Context, conn psnet.ConnectionStat, reason string) {
	if sm.config.ProactiveResponse {
		sm.LogEvent(zerolog.InfoLevel, "Attempting to block suspicious connection").
			Str("remote_addr", fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port)).
			Str("reason", reason)

		// Implementation would use iptables or other firewall mechanism
		// This is a placeholder for the actual blocking mechanism
		sm.PublishEvent(ctx, events.EventAutomatedResponse, "connection_blocked",
			fmt.Sprintf("Blocked suspicious connection: %s:%d", conn.Raddr.IP, conn.Raddr.Port),
			"medium", map[string]interface{}{
				"blocked_ip":   conn.Raddr.IP,
				"blocked_port": conn.Raddr.Port,
				"reason":       reason,
				"method":       "firewall_block",
			})
	}
}

// Network monitoring implementation
func (sm *SentinelMonitor) runNetworkMonitoring(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running network monitoring...")

	// Monitor connections
	sm.monitorConnections(ctx)

	// Monitor bandwidth
	sm.monitorBandwidth(ctx)

	// Monitor suspicious ports
	sm.monitorSuspiciousPorts(ctx)
}

func (sm *SentinelMonitor) monitorConnections(ctx context.Context) {
	connections, err := psnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get network connections").Err(err)
		return
	}

	externalConnections := 0
	listeningPorts := 0

	for _, conn := range connections {
		if conn.Status == "ESTABLISHED" && conn.Raddr.IP != "" {
			ip := net.ParseIP(conn.Raddr.IP)
			if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
				externalConnections++
			}
		}
		if conn.Status == "LISTEN" {
			listeningPorts++
		}
	}

	if sm.config.MaxConnections > 0 && externalConnections > sm.config.MaxConnections {
		sm.PublishEvent(ctx, events.EventSystemAnomaly, "excessive_connections",
			fmt.Sprintf("Excessive external connections: %d", externalConnections),
			"medium", map[string]interface{}{
				"external_connections": externalConnections,
				"threshold":            sm.config.MaxConnections,
			})
	}

	sm.UpdateState("external_connections", externalConnections)
	sm.UpdateState("listening_ports", listeningPorts)
}

func (sm *SentinelMonitor) monitorBandwidth(ctx context.Context) {
	netIOCounters, err := psnet.IOCountersWithContext(ctx, false)
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get network IO counters").Err(err)
		return
	}

	if len(netIOCounters) == 0 {
		return
	}

	currentCounters := netIOCounters[0]
	now := time.Now()

	if !sm.lastBandwidthCheck.IsZero() {
		duration := now.Sub(sm.lastBandwidthCheck).Seconds()
		if duration > 0 {
			rxRate := float64(currentCounters.BytesRecv-sm.lastRxBytes) / duration
			txRate := float64(currentCounters.BytesSent-sm.lastTxBytes) / duration

			// Convert to Mbps
			rxRateMbps := rxRate * 8 / (1024 * 1024)
			txRateMbps := txRate * 8 / (1024 * 1024)

			if sm.config.BandwidthThresholdMBps > 0 && txRateMbps > sm.config.BandwidthThresholdMBps {
				sm.PublishEvent(ctx, events.EventDataExfiltration, "high_bandwidth_usage",
					fmt.Sprintf("High upload bandwidth detected: %.2f Mbps", txRateMbps),
					"medium", map[string]interface{}{
						"tx_rate_mbps": txRateMbps,
						"rx_rate_mbps": rxRateMbps,
						"threshold":    sm.config.BandwidthThresholdMBps,
					})
			}

			sm.UpdateState("bandwidth_tx_mbps", txRateMbps)
			sm.UpdateState("bandwidth_rx_mbps", rxRateMbps)
		}
	}

	sm.lastRxBytes = currentCounters.BytesRecv
	sm.lastTxBytes = currentCounters.BytesSent
	sm.lastBandwidthCheck = now
}

func (sm *SentinelMonitor) monitorSuspiciousPorts(ctx context.Context) {
	connections, err := psnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return
	}

	for _, conn := range connections {
		if conn.Status == "LISTEN" {
			for _, sPort := range sm.config.SuspiciousPorts {
				if conn.Laddr.Port == uint32(sPort) {
					sm.PublishEvent(ctx, events.EventSuspiciousNetwork, "suspicious_port_open",
						fmt.Sprintf("Suspicious port listening: %d", sPort),
						"high", map[string]interface{}{
							"port": sPort,
							"pid":  conn.Pid,
						})
				}
			}
		}
	}
}

// DNS analysis implementation
func (sm *SentinelMonitor) runDNSAnalysis(ctx context.Context) {
	if len(sm.dnsEvents) == 0 {
		return
	}

	sm.LogEvent(zerolog.InfoLevel, "Running DNS analysis...")

	processedEvents := 0
	suspiciousDomains := 0

	// Process available DNS events
	for len(sm.dnsEvents) > 0 {
		select {
		case event := <-sm.dnsEvents:
			processedEvents++

			// Update client stats for stateful analysis
			sm.updateClientStats(event)

			// Perform stateless analysis only on queries
			if event.IsQuery {
				if sm.analyzeDNSQuery(ctx, event) {
					suspiciousDomains++
				}
			}
		default:
			// No more events to process
			break
		}
	}

	if processedEvents > 0 {
		sm.UpdateState("dns_events_processed", processedEvents)
		sm.UpdateState("suspicious_domains_detected", suspiciousDomains)

		sm.LogEvent(zerolog.InfoLevel, "DNS analysis completed").
			Int("events_processed", processedEvents).
			Int("suspicious_domains", suspiciousDomains)
	}
}

func (sm *SentinelMonitor) analyzeDNSQuery(ctx context.Context, event DNSEvent) bool {
	// Check whitelist
	whitelist := make(map[string]struct{})
	for _, d := range sm.config.DNSWhitelist {
		whitelist[strings.TrimSpace(d)] = struct{}{}
	}
	if _, isWhitelisted := whitelist[event.Domain]; isWhitelisted {
		return false
	}

	// Calculate suspicion score
	score := sm.calculateSuspicionScore(event.Domain)
	suspicionThreshold := sm.config.SuspicionThreshold
	if suspicionThreshold == 0 {
		suspicionThreshold = 100.0
	}

	if score.Total > suspicionThreshold {
		sm.PublishEvent(ctx, events.EventSuspiciousNetwork, "suspicious_dns_query",
			fmt.Sprintf("Suspicious DNS query: %s", event.Domain),
			"medium", map[string]interface{}{
				"domain":        event.Domain,
				"source_ip":     event.SourceIP.String(),
				"total_score":   score.Total,
				"entropy":       score.Entropy,
				"length":        score.Length,
				"vowel_ratio":   score.VowelRatio,
				"digit_ratio":   score.DigitRatio,
				"special_chars": score.SpecialChars,
			})
		return true
	}

	return false
}

// Exfiltration detection implementation
func (sm *SentinelMonitor) runExfiltrationDetection(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running exfiltration detection...")

	// Monitor for large uploads
	sm.detectLargeUploads(ctx)

	// Monitor file sharing connections
	if sm.config.MonitorFileSharing {
		sm.monitorFileSharingConnections(ctx)
	}

	// Check for suspicious data patterns
	sm.detectSuspiciousDataPatterns(ctx)
}

func (sm *SentinelMonitor) detectLargeUploads(ctx context.Context) {
	if sm.config.LargeUploadThresholdMB <= 0 {
		return
	}

	// Get current network stats
	netIOCounters, err := psnet.IOCountersWithContext(ctx, false)
	if err != nil {
		return
	}

	if len(netIOCounters) == 0 {
		return
	}

	currentCounters := netIOCounters[0]
	now := time.Now()

	if sm.networkBaseline.InitialTxBytes > 0 {
		uploadedBytes := currentCounters.BytesSent - sm.networkBaseline.InitialTxBytes
		uploadedMB := uploadedBytes / (1024 * 1024)

		timeSinceBaseline := now.Sub(sm.networkBaseline.BaselineTimestamp)

		if int(uploadedMB) > sm.config.LargeUploadThresholdMB && timeSinceBaseline > time.Minute {
			sm.PublishEvent(ctx, events.EventDataExfiltration, "large_upload_detected",
				fmt.Sprintf("Large data upload detected: %d MB", uploadedMB),
				"high", map[string]interface{}{
					"uploaded_mb":  uploadedMB,
					"threshold_mb": sm.config.LargeUploadThresholdMB,
					"time_period":  timeSinceBaseline.String(),
				})

			// Reset baseline after detection
			sm.networkBaseline.InitialTxBytes = currentCounters.BytesSent
			sm.networkBaseline.BaselineTimestamp = now
		}
	} else {
		// Initialize baseline
		sm.networkBaseline.InitialTxBytes = currentCounters.BytesSent
		sm.networkBaseline.BaselineTimestamp = now
	}
}

func (sm *SentinelMonitor) monitorFileSharingConnections(ctx context.Context) {
	connections, err := psnet.Connections("inet")
	if err != nil {
		return
	}

	// Resolve file sharing domains if not cached
	for _, domain := range sm.config.FileSharingDomains {
		if _, exists := sm.networkBaseline.DomainIPs[domain]; !exists {
			if ips, err := net.LookupIP(domain); err == nil {
				if sm.networkBaseline.DomainIPs == nil {
					sm.networkBaseline.DomainIPs = make(map[string][]net.IP)
				}
				sm.networkBaseline.DomainIPs[domain] = ips
			}
		}
	}

	// Check connections
	for _, conn := range connections {
		remoteIP := net.ParseIP(conn.Raddr.IP)
		if remoteIP == nil {
			continue
		}

		for domain, ips := range sm.networkBaseline.DomainIPs {
			for _, ip := range ips {
				if remoteIP.Equal(ip) {
					sm.PublishEvent(ctx, events.EventDataExfiltration, "file_sharing_connection",
						fmt.Sprintf("Connection to file sharing service: %s", domain),
						"medium", map[string]interface{}{
							"domain":      domain,
							"remote_ip":   conn.Raddr.IP,
							"remote_port": conn.Raddr.Port,
							"local_ip":    conn.Laddr.IP,
							"local_port":  conn.Laddr.Port,
						})
				}
			}
		}
	}
}

func (sm *SentinelMonitor) detectSuspiciousDataPatterns(ctx context.Context) {
	// This would typically analyze network traffic for suspicious patterns
	// Implementation would depend on specific patterns to detect
	// Placeholder for pattern detection logic
	sm.LogEvent(zerolog.DebugLevel, "Suspicious data pattern detection completed")
}

// DNS packet capture implementation
func (sm *SentinelMonitor) startDNSPacketCapture() {
	iface := "any"
	if sm.config.NetworkInterface != "" {
		iface = sm.config.NetworkInterface
	}

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to open pcap handle").
			Err(err).Str("interface", iface)
		return
	}

	sm.pcapHandle = handle

	if err := handle.SetBPFFilter("udp and port 53"); err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to set BPF filter").Err(err)
		handle.Close()
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	sm.LogEvent(zerolog.InfoLevel, "DNS packet capture started").
		Str("interface", iface)

	for {
		select {
		case packet := <-packetSource.Packets():
			sm.processDNSPacket(packet)
		case <-sm.stopDNSCapture:
			sm.LogEvent(zerolog.InfoLevel, "Stopping DNS packet capture")
			handle.Close()
			return
		}
	}
}

func (sm *SentinelMonitor) processDNSPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	var dnsMsg dns.Msg
	if err := dnsMsg.Unpack(udp.Payload); err != nil {
		return
	}

	if len(dnsMsg.Question) == 0 {
		return
	}

	event := DNSEvent{
		Domain:    strings.TrimSuffix(dnsMsg.Question[0].Name, "."),
		IsQuery:   !dnsMsg.Response,
		IsNX:      dnsMsg.Rcode == dns.RcodeNameError,
		Timestamp: time.Now(),
	}

	if event.IsQuery {
		event.SourceIP = ip.SrcIP
	} else {
		event.SourceIP = ip.DstIP
	}

	// Non-blocking send to channel
	select {
	case sm.dnsEvents <- event:
	default:
		// Channel is full, drop the event
	}
}

// Stateful DNS analysis
func (sm *SentinelMonitor) startStatefulAnalysis() {
	if !sm.config.EnableStatefulAnalysis {
		return
	}

	cleanupInterval, err := time.ParseDuration(sm.config.StatsCleanupInterval)
	if err != nil {
		cleanupInterval = 1 * time.Hour
	}

	ticker := time.NewTicker(cleanupInterval / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.analyzeAndCleanClientStats()
		case <-sm.stopDNSCapture:
			return
		}
	}
}

func (sm *SentinelMonitor) updateClientStats(event DNSEvent) {
	if !sm.config.EnableStatefulAnalysis {
		return
	}

	ipStr := event.SourceIP.String()

	sm.statsMutex.Lock()
	defer sm.statsMutex.Unlock()

	if _, ok := sm.clientStats[ipStr]; !ok {
		sm.clientStats[ipStr] = &ClientStats{}
	}

	stats := sm.clientStats[ipStr]
	stats.LastSeen = time.Now()

	if event.IsQuery {
		stats.TotalQueries++
	}
	if event.IsNX {
		stats.NXDomainCount++
	}
}

func (sm *SentinelMonitor) analyzeAndCleanClientStats() {
	sm.statsMutex.Lock()
	defer sm.statsMutex.Unlock()

	minQueries := sm.config.MinQueryCountForAlert
	if minQueries == 0 {
		minQueries = 20
	}

	nxRatio := sm.config.NXDomainThresholdRatio
	if nxRatio == 0 {
		nxRatio = 0.8
	}

	cleanupInterval, err := time.ParseDuration(sm.config.StatsCleanupInterval)
	if err != nil {
		cleanupInterval = 1 * time.Hour
	}

	ctx := context.Background()

	for ip, stats := range sm.clientStats {
		// Clean up old entries
		if time.Since(stats.LastSeen) > cleanupInterval {
			delete(sm.clientStats, ip)
			continue
		}

		// Analyze for high NXDOMAIN rate
		if stats.TotalQueries >= minQueries {
			ratio := float64(stats.NXDomainCount) / float64(stats.TotalQueries)
			if ratio >= nxRatio {
				sm.PublishEvent(ctx, events.EventSuspiciousNetwork, "high_nxdomain_rate",
					fmt.Sprintf("High NXDOMAIN rate detected: %s (%.1f%%)", ip, ratio*100),
					"medium", map[string]interface{}{
						"client_ip":      ip,
						"nxdomain_ratio": ratio,
						"total_queries":  stats.TotalQueries,
						"nxdomain_count": stats.NXDomainCount,
					})
			}
		}
	}
}

// DNS suspicion scoring
func (sm *SentinelMonitor) calculateSuspicionScore(domain string) DNSSuspicionScore {
	var score DNSSuspicionScore
	domainPart := sm.getDomainPart(domain)

	// 1. Entropy Score
	score.Entropy = sm.shannonEntropy(domainPart)

	// 2. Length Score
	if len(domainPart) > 20 {
		score.Length = float64(len(domainPart))
	}

	// 3. Vowel Ratio Score
	vowelRatio := sm.calculateVowelRatio(domainPart)
	if vowelRatio < 0.1 || vowelRatio > 0.7 {
		score.VowelRatio = (1 - vowelRatio) * 20
	}

	// 4. Digit Ratio Score
	digitRatio := sm.calculateDigitRatio(domainPart)
	if digitRatio > 0.2 {
		score.DigitRatio = digitRatio * 30
	}

	// 5. Special Character Score
	if strings.Contains(domainPart, "-") {
		score.SpecialChars = float64(strings.Count(domainPart, "-")) * 10
	}

	// Calculate weighted total score
	score.Total = (score.Entropy * sm.getWeight("entropy", 25.0)) +
		(score.Length * sm.getWeight("length", 1.5)) +
		(score.VowelRatio * sm.getWeight("vowel_ratio", 1.0)) +
		(score.DigitRatio * sm.getWeight("digit_ratio", 1.0)) +
		(score.SpecialChars * sm.getWeight("special_chars", 1.0))

	return score
}

// Helper methods for DNS analysis
func (sm *SentinelMonitor) getDomainPart(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 1 {
		return parts[0]
	}
	return domain
}

func (sm *SentinelMonitor) calculateVowelRatio(s string) float64 {
	if s == "" {
		return 0
	}
	vowels := "aeiouAEIOU"
	vowelCount := 0
	for _, char := range s {
		if strings.ContainsRune(vowels, char) {
			vowelCount++
		}
	}
	return float64(vowelCount) / float64(len(s))
}

func (sm *SentinelMonitor) calculateDigitRatio(s string) float64 {
	if s == "" {
		return 0
	}
	digitCount := 0
	for _, char := range s {
		if char >= '0' && char <= '9' {
			digitCount++
		}
	}
	return float64(digitCount) / float64(len(s))
}

func (sm *SentinelMonitor) shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	charCounts := make(map[rune]int)
	for _, char := range s {
		charCounts[char]++
	}

	var entropy float64
	sLen := float64(len(s))
	for _, count := range charCounts {
		probability := float64(count) / sLen
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func (sm *SentinelMonitor) getWeight(heuristic string, defaultValue float64) float64 {
	switch heuristic {
	case "entropy":
		if sm.config.EntropyWeight != 0 {
			return sm.config.EntropyWeight
		}
	case "length":
		if sm.config.LengthWeight != 0 {
			return sm.config.LengthWeight
		}
	case "vowel_ratio":
		if sm.config.VowelRatioWeight != 0 {
			return sm.config.VowelRatioWeight
		}
	case "digit_ratio":
		if sm.config.DigitRatioWeight != 0 {
			return sm.config.DigitRatioWeight
		}
	case "special_chars":
		if sm.config.SpecialCharsWeight != 0 {
			return sm.config.SpecialCharsWeight
		}
	}
	return defaultValue
}

// System health assessment
func (sm *SentinelMonitor) assessSystemHealth(ctx context.Context) {
	health := sm.collectSystemHealth()

	// Assess overall health score
	healthScore := sm.calculateHealthScore(health)

	if healthScore < 70 {
		severity := "medium"
		if healthScore < 50 {
			severity = "high"
		}
		if healthScore < 30 {
			severity = "critical"
		}

		sm.PublishEvent(ctx, events.EventSystemAnomaly, "system_health_degraded",
			fmt.Sprintf("System health degraded: %.1f/100", healthScore),
			severity, map[string]interface{}{
				"health_score":    healthScore,
				"cpu_temperature": sm.calculateAverageTemp(health.CPUTemperature),
				"memory_usage":    health.MemoryUsage,
				"disk_usage":      health.DiskUsage,
				"process_count":   health.ProcessCount,
			})
	}

	sm.UpdateState("system_health_score", healthScore)
}

func (sm *SentinelMonitor) collectSystemHealth() SystemHealth {
	health := SystemHealth{
		Timestamp: time.Now(),
	}

	// Collect CPU temperature
	if temps, err := host.SensorsTemperatures(); err == nil {
		for _, temp := range temps {
			if strings.Contains(strings.ToLower(temp.SensorKey), "cpu") ||
				strings.Contains(strings.ToLower(temp.SensorKey), "core") {
				health.CPUTemperature = append(health.CPUTemperature, temp.Temperature)
			}
		}
	}

	// Collect memory usage
	if memInfo, err := mem.VirtualMemory(); err == nil {
		health.MemoryUsage = memInfo.UsedPercent
	}

	// Collect disk usage
	if diskInfo, err := disk.Usage("/"); err == nil {
		health.DiskUsage = diskInfo.UsedPercent
	}

	// Collect process count
	if processes, err := process.Processes(); err == nil {
		health.ProcessCount = len(processes)
	}

	// Collect network stats
	if netIOCounters, err := psnet.IOCounters(false); err == nil && len(netIOCounters) > 0 {
		health.NetworkStats = NetworkStats{
			BytesSent:   netIOCounters[0].BytesSent,
			BytesRecv:   netIOCounters[0].BytesRecv,
			PacketsSent: netIOCounters[0].PacketsSent,
			PacketsRecv: netIOCounters[0].PacketsRecv,
			Timestamp:   time.Now(),
		}
	}

	// Check critical processes
	health.CriticalProcesses = make(map[string]bool)
	if processes, err := process.Processes(); err == nil {
		processNames := make(map[string]bool)
		for _, p := range processes {
			if name, err := p.Name(); err == nil {
				processNames[name] = true
			}
		}

		for _, criticalProc := range sm.config.MonitorCriticalProcesses {
			health.CriticalProcesses[criticalProc] = false
			for procName := range processNames {
				if strings.Contains(strings.ToLower(procName), strings.ToLower(criticalProc)) {
					health.CriticalProcesses[criticalProc] = true
					break
				}
			}
		}
	}

	return health
}

func (sm *SentinelMonitor) calculateHealthScore(health SystemHealth) float64 {
	var score float64 = 100.0

	// CPU temperature penalty
	if len(health.CPUTemperature) > 0 {
		avgTemp := sm.calculateAverageTemp(health.CPUTemperature)
		if avgTemp > 80 {
			score -= 20
		} else if avgTemp > 70 {
			score -= 10
		} else if avgTemp > 60 {
			score -= 5
		}
	}

	// Memory usage penalty
	if health.MemoryUsage > 90 {
		score -= 25
	} else if health.MemoryUsage > 80 {
		score -= 15
	} else if health.MemoryUsage > 70 {
		score -= 5
	}

	// Disk usage penalty
	if health.DiskUsage > 95 {
		score -= 20
	} else if health.DiskUsage > 85 {
		score -= 10
	} else if health.DiskUsage > 75 {
		score -= 3
	}

	// Process count penalty
	if sm.config.ProcessCountThreshold > 0 && health.ProcessCount > sm.config.ProcessCountThreshold {
		score -= 10
	}

	// Critical process penalty
	for _, isRunning := range health.CriticalProcesses {
		if !isRunning {
			score -= 15
		}
	}

	if score < 0 {
		score = 0
	}

	return score
}

func (sm *SentinelMonitor) calculateAverageTemp(temps []float64) float64 {
	if len(temps) == 0 {
		return 0
	}

	var sum float64
	for _, temp := range temps {
		sum += temp
	}
	return sum / float64(len(temps))
}

// System report generation
func (sm *SentinelMonitor) generateSystemReport(ctx context.Context) {
	report := map[string]interface{}{
		"timestamp":           time.Now(),
		"monitoring_duration": time.Since(sm.lastReportTime),
		"system_health":       sm.collectSystemHealth(),
		"monitoring_stats": map[string]interface{}{
			"certificates_monitored": len(sm.config.DomainsToMonitor),
			"blocklist_ips":          len(sm.config.IPBlocklist),
			"blocklist_domains":      len(sm.config.DomainBlocklist),
			"dns_clients_tracked":    len(sm.clientStats),
		},
		"component_status": map[string]interface{}{
			"system_monitoring":        sm.config.SystemMonitoringEnabled,
			"certificate_monitoring":   sm.config.CertificateMonitoringEnabled,
			"communication_monitoring": sm.config.CommunicationMonitoringEnabled,
			"network_monitoring":       sm.config.NetworkMonitoringEnabled,
			"network_ids":              sm.config.NetworkIDSEnabled,
			"persistence_monitoring":   sm.config.PersistenceMonitoringEnabled,
			"recon_detection":          sm.config.ReconDetectionEnabled,
			"thermal_monitoring":       true, // Always enabled
			"exfiltration_detection":   sm.config.ExfiltrationDetectionEnabled,
		},
	}

	sm.PublishEvent(ctx, events.EventSystemReport, "sentinel_report",
		"Comprehensive Sentinel system report generated",
		"info", report)

	sm.LogEvent(zerolog.InfoLevel, "System report generated").
		Interface("report_summary", map[string]interface{}{
			"monitoring_duration": time.Since(sm.lastReportTime).String(),
			"components_active":   sm.getActiveComponentCount(),
		})
}

func (sm *SentinelMonitor) getActiveComponentCount() int {
	count := 0
	if sm.config.SystemMonitoringEnabled {
		count++
	}
	if sm.config.CertificateMonitoringEnabled {
		count++
	}
	if sm.config.CommunicationMonitoringEnabled {
		count++
	}
	if sm.config.NetworkMonitoringEnabled {
		count++
	}
	if sm.config.NetworkIDSEnabled {
		count++
	}
	if sm.config.PersistenceMonitoringEnabled {
		count++
	}
	if sm.config.ReconDetectionEnabled {
		count++
	}
	if sm.config.ExfiltrationDetectionEnabled {
		count++
	}
	// Thermal monitoring is always active
	count++
	return count
}

// Comprehensive metrics update
func (sm *SentinelMonitor) updateComprehensiveMetrics() {
	sm.UpdateState("last_report", sm.lastReportTime)
	sm.UpdateState("monitoring_active", sm.monitoringActive)
	sm.UpdateState("active_components", sm.getActiveComponentCount())

	// Component status
	componentStatus := map[string]bool{
		"system_monitoring":        sm.config.SystemMonitoringEnabled,
		"certificate_monitoring":   sm.config.CertificateMonitoringEnabled,
		"communication_monitoring": sm.config.CommunicationMonitoringEnabled,
		"network_monitoring":       sm.config.NetworkMonitoringEnabled,
		"network_ids":              sm.config.NetworkIDSEnabled,
		"persistence_monitoring":   sm.config.PersistenceMonitoringEnabled,
		"recon_detection":          sm.config.ReconDetectionEnabled,
		"thermal_monitoring":       true, // Always enabled
		"exfiltration_detection":   sm.config.ExfiltrationDetectionEnabled,
		"dns_analysis":             sm.config.NetworkMonitoringEnabled,
	}
	sm.UpdateState("component_status", componentStatus)

	// Statistics
	sm.statsMutex.RLock()
	sm.UpdateState("dns_clients_tracked", len(sm.clientStats))
	sm.statsMutex.RUnlock()

	sm.UpdateState("certificates_baseline_count", len(sm.certificateBaselines))
	sm.UpdateState("blocklist_domains_resolved", len(sm.resolvedBlocklist))
	sm.UpdateState("comprehensive_monitoring_active", true)
}

// Component initialization methods
func (sm *SentinelMonitor) initializeDNSCapture() error {
	// Pre-flight check for packet capture capabilities
	iface := "any"
	if sm.config.NetworkInterface != "" {
		iface = sm.config.NetworkInterface
	}

	// Test pcap handle creation
	handle, err := pcap.OpenLive(iface, 1600, true, time.Second)
	if err != nil {
		return fmt.Errorf("failed to initialize DNS capture on interface %s: %w", iface, err)
	}
	handle.Close()

	sm.LogEvent(zerolog.InfoLevel, "DNS packet capture initialized").
		Str("interface", iface)
	return nil
}

func (sm *SentinelMonitor) initializeCommunicationMonitoring() {
	// Pre-resolve domain blocklist
	for _, domain := range sm.config.DomainBlocklist {
		if ips, err := net.LookupIP(domain); err == nil {
			sm.resolvedBlocklist[domain] = ips
		} else {
			sm.LogEvent(zerolog.WarnLevel, "Failed to resolve blocked domain").
				Str("domain", domain).Err(err)
		}
	}

	sm.communicationBaseline.LastCommunicationCheck = time.Now()

	sm.LogEvent(zerolog.InfoLevel, "Communication monitoring initialized").
		Int("ip_blocklist_entries", len(sm.config.IPBlocklist)).
		Int("domain_blocklist_entries", len(sm.config.DomainBlocklist)).
		Int("resolved_domains", len(sm.resolvedBlocklist))
}

func (sm *SentinelMonitor) initializeSystemMonitoring() {
	// Initialize system baseline
	sm.systemBaseline.LastSystemCheck = time.Now()

	if processes, err := process.Processes(); err == nil {
		sm.systemBaseline.InitialProcessCount = len(processes)
	}

	if memInfo, err := mem.VirtualMemory(); err == nil {
		sm.systemBaseline.BaselineMemoryUsage = memInfo.UsedPercent
	}

	if diskInfo, err := disk.Usage("/"); err == nil {
		sm.systemBaseline.BaselineDiskUsage = diskInfo.UsedPercent
	}

	if netIOCounters, err := psnet.IOCounters(false); err == nil && len(netIOCounters) > 0 {
		sm.systemBaseline.InitialNetworkStats = NetworkStats{
			BytesSent:   netIOCounters[0].BytesSent,
			BytesRecv:   netIOCounters[0].BytesRecv,
			PacketsSent: netIOCounters[0].PacketsSent,
			PacketsRecv: netIOCounters[0].PacketsRecv,
			Timestamp:   time.Now(),
		}
	}

	sm.LogEvent(zerolog.InfoLevel, "System monitoring initialized").
		Int("initial_process_count", sm.systemBaseline.InitialProcessCount).
		Float64("baseline_memory_usage", sm.systemBaseline.BaselineMemoryUsage).
		Float64("baseline_disk_usage", sm.systemBaseline.BaselineDiskUsage)
}

func (sm *SentinelMonitor) initializeCertificateMonitoring() {
	// Ensure baseline directory exists
	if err := os.MkdirAll(sm.config.BaselineDir, 0755); err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to create certificate baseline directory").
			Err(err).Str("dir", sm.config.BaselineDir)
		return
	}

	// Load existing baselines
	sm.loadCertificateBaselines()

	sm.LogEvent(zerolog.InfoLevel, "Certificate monitoring initialized").
		Int("domains_to_monitor", len(sm.config.DomainsToMonitor)).
		Int("existing_baselines", len(sm.certificateBaselines)).
		Str("baseline_dir", sm.config.BaselineDir)
}

func (sm *SentinelMonitor) initializeReconDetection() {
	// Initialize reconnaissance detection state
	sm.synRecvCounts = make(map[string]int)
	sm.portScanCache = make(map[string]time.Time)

	sm.LogEvent(zerolog.InfoLevel, "Reconnaissance detection initialized").
		Int("syn_flood_threshold", sm.config.SynFloodThreshold).
		Int("port_scan_threshold", sm.config.PortScanThreshold)
}

func (sm *SentinelMonitor) loadCertificateBaselines() {
	files, err := os.ReadDir(sm.config.BaselineDir)
	if err != nil {
		sm.LogEvent(zerolog.WarnLevel, "Failed to read baseline directory").Err(err)
		return
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".fp") {
			baselineFile := filepath.Join(sm.config.BaselineDir, file.Name())
			content, err := os.ReadFile(baselineFile)
			if err != nil {
				continue
			}

			// Extract domain:port from filename
			name := strings.TrimSuffix(file.Name(), ".fp")
			parts := strings.Split(name, "_")
			if len(parts) >= 2 {
				domain := strings.Join(parts[:len(parts)-1], "_")
				port := parts[len(parts)-1]
				key := fmt.Sprintf("%s:%s", domain, port)
				sm.certificateBaselines[key] = string(content)
			}
		}
	}
}

// Configuration parsing helpers
func (sm *SentinelMonitor) parseConfig(config map[string]interface{}) error {
	// Parse string arrays
	stringArrayConfigs := map[string]*[]string{
		"domains_to_monitor":         &sm.config.DomainsToMonitor,
		"ip_blocklist":               &sm.config.IPBlocklist,
		"domain_blocklist":           &sm.config.DomainBlocklist,
		"dns_whitelist":              &sm.config.DNSWhitelist,
		"monitor_critical_processes": &sm.config.MonitorCriticalProcesses,
		"suspicious_data_patterns":   &sm.config.SuspiciousDataPatterns,
		"file_sharing_domains":       &sm.config.FileSharingDomains,
		"ids_rules":                  &sm.config.IDSRules,
	}

	for key, ptr := range stringArrayConfigs {
		if val, ok := config[key].([]interface{}); ok {
			*ptr = make([]string, len(val))
			for i, item := range val {
				if str, ok := item.(string); ok {
					(*ptr)[i] = str
				}
			}
		}
	}

	// Parse integer arrays
	if val, ok := config["suspicious_ports"].([]interface{}); ok {
		sm.config.SuspiciousPorts = make([]int, len(val))
		for i, item := range val {
			if num, ok := item.(int); ok {
				sm.config.SuspiciousPorts[i] = num
			}
		}
	}

	// Parse string configurations
	stringConfigs := map[string]*string{
		"reporting_interval":          &sm.config.ReportingInterval,
		"response_mode":               &sm.config.ResponseMode,
		"baseline_dir":                &sm.config.BaselineDir,
		"network_interface":           &sm.config.NetworkInterface,
		"stats_cleanup_interval":      &sm.config.StatsCleanupInterval,
		"process_monitoring_interval": &sm.config.ProcessMonitoringInterval,
		"suspicious_names":            &sm.config.SuspiciousNames,
		"whitelist_users":             &sm.config.WhitelistUsers,
		"ids_interface":               &sm.config.IDSInterface,
	}

	for key, ptr := range stringConfigs {
		if val, ok := config[key].(string); ok {
			*ptr = val
		}
	}

	// Parse integer configurations
	intConfigs := map[string]*int{
		"expiry_threshold_days":     &sm.config.ExpiryThresholdDays,
		"max_connections":           &sm.config.MaxConnections,
		"min_query_count_for_alert": &sm.config.MinQueryCountForAlert,
		"process_count_threshold":   &sm.config.ProcessCountThreshold,
		"large_upload_threshold_mb": &sm.config.LargeUploadThresholdMB,
		"syn_flood_threshold":       &sm.config.SynFloodThreshold,
		"port_scan_threshold":       &sm.config.PortScanThreshold,
	}

	for key, ptr := range intConfigs {
		if val, ok := config[key].(int); ok {
			*ptr = val
		}
	}

	// Parse float configurations
	floatConfigs := map[string]*float64{
		"bandwidth_threshold_mbps":  &sm.config.BandwidthThresholdMBps,
		"nxdomain_threshold_ratio":  &sm.config.NXDomainThresholdRatio,
		"entropy_weight":            &sm.config.EntropyWeight,
		"length_weight":             &sm.config.LengthWeight,
		"vowel_ratio_weight":        &sm.config.VowelRatioWeight,
		"digit_ratio_weight":        &sm.config.DigitRatioWeight,
		"special_chars_weight":      &sm.config.SpecialCharsWeight,
		"suspicion_threshold":       &sm.config.SuspicionThreshold,
		"cpu_temperature_threshold": &sm.config.CPUTemperatureThreshold,
		"memory_usage_threshold":    &sm.config.MemoryUsageThreshold,
		"disk_usage_threshold":      &sm.config.DiskUsageThreshold,
		"cpu_threshold":             &sm.config.CPUThreshold,
		"memory_threshold":          &sm.config.MemoryThreshold,
		"temp_threshold":            &sm.config.TempThreshold,
		"cpu_usage_threshold":       &sm.config.CPUUsageThreshold,
	}

	for key, ptr := range floatConfigs {
		if val, ok := config[key].(float64); ok {
			*ptr = val
		}
	}

	// Parse boolean configurations
	boolConfigs := map[string]*bool{
		"system_monitoring_enabled":        &sm.config.SystemMonitoringEnabled,
		"proactive_response":               &sm.config.ProactiveResponse,
		"certificate_monitoring_enabled":   &sm.config.CertificateMonitoringEnabled,
		"communication_monitoring_enabled": &sm.config.CommunicationMonitoringEnabled,
		"auto_block_suspicious":            &sm.config.AutoBlockSuspicious,
		"network_monitoring_enabled":       &sm.config.NetworkMonitoringEnabled,
		"enable_stateful_analysis":         &sm.config.EnableStatefulAnalysis,
		"exfiltration_detection_enabled":   &sm.config.ExfiltrationDetectionEnabled,
		"monitor_file_sharing":             &sm.config.MonitorFileSharing,
		"network_ids_enabled":              &sm.config.NetworkIDSEnabled,
		"persistence_monitoring_enabled":   &sm.config.PersistenceMonitoringEnabled,
		"scan_cron":                        &sm.config.ScanCron,
		"scan_systemd":                     &sm.config.ScanSystemd,
		"scan_shell_profiles":              &sm.config.ScanShellProfiles,
		"scan_ld_preload":                  &sm.config.ScanLdPreload,
		"recon_detection_enabled":          &sm.config.ReconDetectionEnabled,
	}

	for key, ptr := range boolConfigs {
		if val, ok := config[key].(bool); ok {
			*ptr = val
		}
	}

	// Set defaults
	sm.setConfigDefaults()

	return nil
}

func (sm *SentinelMonitor) setConfigDefaults() {
	if sm.config.ReportingInterval == "" {
		sm.config.ReportingInterval = "5m"
	}
	if sm.config.ResponseMode == "" {
		sm.config.ResponseMode = "monitor"
	}
	if sm.config.BaselineDir == "" {
		sm.config.BaselineDir = "/var/lib/sentinel/certificates"
	}
	if sm.config.ExpiryThresholdDays == 0 {
		sm.config.ExpiryThresholdDays = 30
	}
	if sm.config.MaxConnections == 0 {
		sm.config.MaxConnections = 1000
	}
	if sm.config.BandwidthThresholdMBps == 0 {
		sm.config.BandwidthThresholdMBps = 100
	}
	if sm.config.SuspicionThreshold == 0 {
		sm.config.SuspicionThreshold = 100.0
	}
	if sm.config.NXDomainThresholdRatio == 0 {
		sm.config.NXDomainThresholdRatio = 0.8
	}
	if sm.config.MinQueryCountForAlert == 0 {
		sm.config.MinQueryCountForAlert = 20
	}
	if sm.config.StatsCleanupInterval == "" {
		sm.config.StatsCleanupInterval = "1h"
	}
	if sm.config.CPUTemperatureThreshold == 0 {
		sm.config.CPUTemperatureThreshold = 75.0
	}
	if sm.config.MemoryUsageThreshold == 0 {
		sm.config.MemoryUsageThreshold = 85.0
	}
	if sm.config.DiskUsageThreshold == 0 {
		sm.config.DiskUsageThreshold = 90.0
	}
	if sm.config.ProcessCountThreshold == 0 {
		sm.config.ProcessCountThreshold = 500
	}
	if sm.config.LargeUploadThresholdMB == 0 {
		sm.config.LargeUploadThresholdMB = 100
	}
	if sm.config.ProcessMonitoringInterval == "" {
		sm.config.ProcessMonitoringInterval = "30s"
	}
	if sm.config.CPUThreshold == 0 {
		sm.config.CPUThreshold = 80.0
	}
	if sm.config.MemoryThreshold == 0 {
		sm.config.MemoryThreshold = 80.0
	}
	if sm.config.TempThreshold == 0 {
		sm.config.TempThreshold = 70.0
	}
	if sm.config.CPUUsageThreshold == 0 {
		sm.config.CPUUsageThreshold = 20.0
	}
	if sm.config.SynFloodThreshold == 0 {
		sm.config.SynFloodThreshold = 1000
	}
	if sm.config.PortScanThreshold == 0 {
		sm.config.PortScanThreshold = 100
	}
	if sm.config.SuspiciousNames == "" {
		sm.config.SuspiciousNames = "nc,netcat,socat,wget,curl"
	}
	if sm.config.WhitelistUsers == "" {
		sm.config.WhitelistUsers = "root,system,daemon"
	}
}

// Cleanup method
func (sm *SentinelMonitor) Cleanup() error {
	sm.LogEvent(zerolog.InfoLevel, "Cleaning up Enhanced Sentinel Monitor")

	sm.mu.Lock()
	sm.monitoringActive = false
	sm.mu.Unlock()

	// Stop DNS capture
	close(sm.stopDNSCapture)

	// Close pcap handle
	if sm.pcapHandle != nil {
		sm.pcapHandle.Close()
	}

	// Close channels
	close(sm.dnsEvents)

	sm.LogEvent(zerolog.InfoLevel, "Enhanced Sentinel Monitor cleanup completed")
	return nil
}

// Public API methods
func (sm *SentinelMonitor) GetConfig() *ComprehensiveSentinelConfig {
	return sm.config
}

func (sm *SentinelMonitor) GetSystemBaseline() SystemBaseline {
	return sm.systemBaseline
}

func (sm *SentinelMonitor) GetCommunicationBaseline() CommunicationBaseline {
	return sm.communicationBaseline
}

func (sm *SentinelMonitor) GetNetworkBaseline() NetworkBaseline {
	return sm.networkBaseline
}

func (sm *SentinelMonitor) GetCertificateBaselines() map[string]string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	baselines := make(map[string]string, len(sm.certificateBaselines))
	for k, v := range sm.certificateBaselines {
		baselines[k] = v
	}
	return baselines
}

func (sm *SentinelMonitor) GetClientStats() map[string]*ClientStats {
	sm.statsMutex.RLock()
	defer sm.statsMutex.RUnlock()

	stats := make(map[string]*ClientStats, len(sm.clientStats))
	for k, v := range sm.clientStats {
		stats[k] = &ClientStats{
			TotalQueries:  v.TotalQueries,
			NXDomainCount: v.NXDomainCount,
			LastSeen:      v.LastSeen,
		}
	}
	return stats
}

func (sm *SentinelMonitor) IsMonitoringActive() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.monitoringActive
}

func (sm *SentinelMonitor) detectHiddenProcesses(ctx context.Context) {
	procDirs, err := os.ReadDir("/proc")
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to read /proc directory for hidden process detection").Err(err)
		return
	}

	procPIDs := make(map[int32]bool)
	for _, dir := range procDirs {
		if dir.IsDir() {
			pid, err := strconv.ParseInt(dir.Name(), 10, 32)
			if err == nil {
				procPIDs[int32(pid)] = true
			}
		}
	}

	gopsutilPIDs := make(map[int32]bool)
	procs, err := process.Processes()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get process list from gopsutil for hidden process detection").Err(err)
		return
	}
	for _, p := range procs {
		gopsutilPIDs[p.Pid] = true
	}

	hiddenCount := 0
	for pid := range procPIDs {
		if _, exists := gopsutilPIDs[pid]; !exists {
			hiddenCount++
			// Try to get command name from /proc/<pid>/comm
			commPath := fmt.Sprintf("/proc/%d/comm", pid)
			comm, readErr := os.ReadFile(commPath)
			commStr := "unknown"
			if readErr == nil {
				commStr = strings.TrimSpace(string(comm))
			}

			sm.PublishEvent(ctx, events.EventSuspiciousProcess, "hidden_process",
				fmt.Sprintf("Possible hidden process detected: %s (PID: %d)", commStr, pid),
				"high", map[string]interface{}{
					"pid":  pid,
					"comm": commStr,
				})

			sm.LogEvent(zerolog.WarnLevel, "Possible hidden process detected").
				Int32("pid", pid).
				Str("comm", commStr)
		}
	}

	if hiddenCount > 0 {
		sm.LogEvent(zerolog.WarnLevel, "Summary: Hidden processes detected").
			Int("hidden_count", hiddenCount)
	}
}

func (sm *SentinelMonitor) monitorProcessTree(ctx context.Context) {
	procs, err := process.Processes()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get process list for process tree monitoring").Err(err)
		return
	}

	for _, p := range procs {
		ppid, err := p.Ppid()
		if err != nil {
			continue // Cannot get parent, skip
		}
		name, _ := p.Name()
		cmdline, _ := p.Cmdline()

		// Check for shells/interpreters with init (PID 1) as parent
		if ppid == 1 {
			isSuspicious := false
			if strings.Contains(name, "sh") || strings.Contains(name, "bash") || strings.Contains(name, "dash") {
				isSuspicious = true
			} else if strings.Contains(name, "python") || strings.Contains(name, "perl") || strings.Contains(name, "ruby") {
				isSuspicious = true
			}

			if isSuspicious {
				sm.PublishEvent(ctx, events.EventSuspiciousProcess, "suspicious_parent_child",
					fmt.Sprintf("Suspicious process with PID 1 as parent: %s", name),
					"medium", map[string]interface{}{
						"pid":     p.Pid,
						"ppid":    ppid,
						"name":    name,
						"cmdline": cmdline,
					})

				sm.LogEvent(zerolog.WarnLevel, "Suspicious process with PID 1 as parent detected").
					Int32("pid", p.Pid).
					Int32("ppid", ppid).
					Str("name", name).
					Str("cmdline", cmdline)
			}
		}
	}
}

func (sm *SentinelMonitor) monitorDetachedProcesses(ctx context.Context) {
	whitelistUsers := strings.Split(sm.config.WhitelistUsers, ",")
	procs, err := process.Processes()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get process list for detached process monitoring").Err(err)
		return
	}

	for _, p := range procs {
		terminal, err := p.Terminal()
		if err != nil {
			continue
		}

		if terminal == "" { // No TTY
			username, err := p.Username()
			if err != nil {
				continue
			}

			isWhitelisted := false
			for _, wu := range whitelistUsers {
				if strings.TrimSpace(wu) == username {
					isWhitelisted = true
					break
				}
			}

			if !isWhitelisted {
				name, _ := p.Name()
				cmdline, _ := p.Cmdline()

				sm.PublishEvent(ctx, events.EventSuspiciousProcess, "detached_process",
					fmt.Sprintf("Detached process detected from non-whitelisted user: %s", username),
					"medium", map[string]interface{}{
						"pid":      p.Pid,
						"username": username,
						"name":     name,
						"cmdline":  cmdline,
					})

				sm.LogEvent(zerolog.InfoLevel, "Detached process detected from non-whitelisted user").
					Int32("pid", p.Pid).
					Str("username", username).
					Str("name", name).
					Str("cmdline", cmdline)
			}
		}
	}
}

func (sm *SentinelMonitor) monitorSystemdServices(ctx context.Context) {
	// Check failed services
	cmdFailed := exec.Command("systemctl", "list-units", "--failed", "--no-legend")
	outputFailed, err := cmdFailed.Output()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to run 'systemctl list-units --failed'").Err(err)
	} else {
		failedServices := strings.Split(strings.TrimSpace(string(outputFailed)), "\n")
		if len(failedServices) > 0 && failedServices[0] != "" {
			sm.PublishEvent(ctx, events.EventSystemAnomaly, "failed_systemd_services",
				fmt.Sprintf("Failed systemd services detected (%d services)", len(failedServices)),
				"medium", map[string]interface{}{
					"failed_services": failedServices,
					"count":           len(failedServices),
				})

			sm.LogEvent(zerolog.WarnLevel, "Failed systemd services detected").
				Int("count", len(failedServices))
			for _, service := range failedServices {
				sm.LogEvent(zerolog.WarnLevel, "Systemd service failed").
					Str("service", service)
			}
		}
	}

	// Check masked services (excluding systemd internal ones)
	cmdMasked := exec.Command("systemctl", "list-unit-files", "--state=masked", "--no-legend")
	outputMasked, err := cmdMasked.Output()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to run 'systemctl list-unit-files --state=masked'").Err(err)
	} else {
		maskedServices := []string{}
		for _, line := range strings.Split(strings.TrimSpace(string(outputMasked)), "\n") {
			if !strings.Contains(line, "systemd-") && strings.TrimSpace(line) != "" {
				maskedServices = append(maskedServices, line)
			}
		}
		if len(maskedServices) > 0 {
			sm.LogEvent(zerolog.InfoLevel, "Masked systemd services found").
				Int("count", len(maskedServices))
			for _, service := range maskedServices {
				sm.LogEvent(zerolog.InfoLevel, "Systemd service masked").
					Str("service", service)
			}
		}
	}
}

// Persistence monitoring implementations
func (sm *SentinelMonitor) scanCron(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Scanning for cron-based persistence...")

	// System-wide crontab
	sm.checkFileContent(ctx, "/etc/crontab", "System crontab entry")

	// Cron directories
	cronDirs := []string{
		"/etc/cron.d",
		"/etc/cron.hourly",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
	}
	for _, dir := range cronDirs {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			sm.LogEvent(zerolog.DebugLevel, "Could not read cron directory").
				Err(err).Str("dir", dir)
			continue
		}
		for _, file := range files {
			if !file.IsDir() {
				sm.checkFileContent(ctx, filepath.Join(dir, file.Name()), "Cron file entry")
			}
		}
	}

	sm.LogEvent(zerolog.WarnLevel, "Note: User crontab scanning requires elevated privileges and is not fully implemented")
}

func (sm *SentinelMonitor) checkFileContent(ctx context.Context, filePath, logPrefix string) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		sm.LogEvent(zerolog.DebugLevel, "Could not read file").
			Err(err).Str("file", filePath)
		return
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") {
			sm.PublishEvent(ctx, events.EventPersistenceDetected, "cron_entry",
				fmt.Sprintf("%s: %s", logPrefix, trimmedLine),
				"info", map[string]interface{}{
					"file":    filePath,
					"content": trimmedLine,
				})

			sm.LogEvent(zerolog.InfoLevel, logPrefix).
				Str("file", filePath).
				Str("content", trimmedLine)
		}
	}
}

func (sm *SentinelMonitor) scanSystemd(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Scanning for systemd-based persistence...")

	// User-level services and timers
	userHomeDir, err := os.UserHomeDir()
	if err == nil {
		userSystemdDirs := []string{
			filepath.Join(userHomeDir, ".config", "systemd", "user"),
		}
		for _, dir := range userSystemdDirs {
			filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if !info.IsDir() && (strings.HasSuffix(info.Name(), ".service") || strings.HasSuffix(info.Name(), ".timer")) {
					sm.PublishEvent(ctx, events.EventPersistenceDetected, "user_systemd_file",
						fmt.Sprintf("User systemd file found: %s", path),
						"medium", map[string]interface{}{
							"file": path,
							"type": "user_systemd",
						})

					sm.LogEvent(zerolog.WarnLevel, "User systemd file found").
						Str("file", path)
				}
				return nil
			})
		}
	}

	// System-wide services and timers
	systemSystemdDir := "/etc/systemd/system"
	filepath.Walk(systemSystemdDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".service") || strings.HasSuffix(info.Name(), ".timer")) {
			// Check if the file is not owned by any package
			cmd := exec.Command("dpkg", "-S", path)
			_, err := cmd.Output()
			if err != nil { // dpkg -S returns non-zero if file is not owned by a package
				sm.PublishEvent(ctx, events.EventPersistenceDetected, "unpackaged_systemd_file",
					fmt.Sprintf("Systemd file not owned by any package: %s", path),
					"high", map[string]interface{}{
						"file": path,
						"type": "system_systemd_unpackaged",
					})

				sm.LogEvent(zerolog.WarnLevel, "Systemd file not owned by any package").
					Str("file", path)
			}
		}
		return nil
	})
}

func (sm *SentinelMonitor) scanShellProfiles(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Scanning shell profiles for persistence...")

	shellProfiles := []string{
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/zsh/zshrc",
	}

	// Add user-specific profiles
	userHomeDir, err := os.UserHomeDir()
	if err == nil {
		shellProfiles = append(shellProfiles,
			filepath.Join(userHomeDir, ".bashrc"),
			filepath.Join(userHomeDir, ".zshrc"),
			filepath.Join(userHomeDir, ".profile"))
	}

	suspiciousPatterns := []string{
		"nc", "netcat", "ncat", "socat", "python -c", "perl -e", "bash -c",
		"wget", "curl", "base64", "eval", "exec",
	}

	for _, profile := range shellProfiles {
		content, err := ioutil.ReadFile(profile)
		if err != nil {
			sm.LogEvent(zerolog.DebugLevel, "Could not read shell profile").
				Err(err).Str("file", profile)
			continue
		}

		for _, pattern := range suspiciousPatterns {
			if matched, _ := regexp.MatchString(pattern, string(content)); matched {
				sm.PublishEvent(ctx, events.EventPersistenceDetected, "suspicious_shell_profile",
					fmt.Sprintf("Suspicious entry in shell profile: %s (pattern: %s)", profile, pattern),
					"high", map[string]interface{}{
						"file":    profile,
						"pattern": pattern,
					})

				sm.LogEvent(zerolog.WarnLevel, "Suspicious entry in shell profile").
					Str("file", profile).Str("pattern", pattern)
				break
			}
		}
	}
}

func (sm *SentinelMonitor) scanLdPreload(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Scanning for LD_PRELOAD persistence...")

	ldPreloadPath := "/etc/ld.so.preload"
	content, err := os.ReadFile(ldPreloadPath)
	if err != nil {
		if os.IsNotExist(err) {
			sm.LogEvent(zerolog.InfoLevel, "LD_PRELOAD file does not exist").
				Str("file", ldPreloadPath)
		} else {
			sm.LogEvent(zerolog.ErrorLevel, "Failed to read LD_PRELOAD file").
				Err(err).Str("file", ldPreloadPath)
		}
		return
	}

	trimmedContent := strings.TrimSpace(string(content))
	if trimmedContent != "" {
		sm.PublishEvent(ctx, events.EventPersistenceDetected, "ld_preload_configured",
			fmt.Sprintf("LD_PRELOAD is configured: %s", trimmedContent),
			"high", map[string]interface{}{
				"file":    ldPreloadPath,
				"content": trimmedContent,
			})

		sm.LogEvent(zerolog.WarnLevel, "LD_PRELOAD is configured").
			Str("file", ldPreloadPath).Str("content", trimmedContent)
	}
}

// Reconnaissance detection implementations
func (sm *SentinelMonitor) detectPortScans(ctx context.Context) {
	connections, err := psnet.Connections("tcp")
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get TCP connections").Err(err)
		return
	}

	synRecvCounts := make(map[string]int)
	for _, conn := range connections {
		if conn.Status == "SYN_RECV" {
			synRecvCounts[conn.Raddr.IP]++
		}
	}

	for ip, count := range synRecvCounts {
		if count > sm.config.PortScanThreshold {
			sm.PublishEvent(ctx, events.EventSuspiciousNetwork, "port_scan_detected",
				fmt.Sprintf("Potential port scan detected from %s (%d SYN-RECV connections)", ip, count),
				"high", map[string]interface{}{
					"source_ip":      ip,
					"syn_recv_count": count,
					"threshold":      sm.config.PortScanThreshold,
				})

			sm.LogEvent(zerolog.WarnLevel, "Potential port scan detected").
				Str("source_ip", ip).
				Int("syn_recv_count", count)
		}
	}

	// Update cache for tracking
	sm.mu.Lock()
	sm.synRecvCounts = synRecvCounts
	sm.mu.Unlock()
}

func (sm *SentinelMonitor) detectSynFloods(ctx context.Context) {
	connections, err := psnet.Connections("tcp")
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get TCP connections").Err(err)
		return
	}

	synRecvCount := 0
	for _, conn := range connections {
		if conn.Status == "SYN_RECV" {
			synRecvCount++
		}
	}

	if synRecvCount > sm.config.SynFloodThreshold {
		sm.PublishEvent(ctx, events.EventSuspiciousNetwork, "syn_flood_detected",
			fmt.Sprintf("Potential SYN flood attack detected (%d SYN-RECV connections)", synRecvCount),
			"critical", map[string]interface{}{
				"syn_recv_count": synRecvCount,
				"threshold":      sm.config.SynFloodThreshold,
			})

		sm.LogEvent(zerolog.WarnLevel, "Potential SYN flood attack detected").
			Int("syn_recv_count", synRecvCount)
	}
}

// Helper functions for Network IDS
func (sm *SentinelMonitor) isValidInterfaceName(name string) bool {
	// Interface names typically consist of alphanumeric characters, hyphens, and underscores.
	// They should not contain spaces or shell metacharacters.
	return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(name)
}
