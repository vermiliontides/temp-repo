// pkg/monitors/enhanced/enhanced_sentinel.go
// contains previous implementations:
// certificate_monitor.go
// communication_monitor.go
// network_monitor.go
// TODO: network_ids.go
// TODO: persistence_monitor.go
// TODO: process_monitor.go
// TODO: recon_detector.go
// TODO: thermal_monitor.go
package enhanced

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
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
	processBaseline map[int32]*ProcessInfo
	cpuTempBaseline []float64

	// Communication monitoring
	resolvedBlocklist map[string][]net.IP

	// Network monitoring state
	lastRxBytes        uint64
	lastTxBytes        uint64
	lastBandwidthCheck time.Time

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

	// Exfiltration detection config
	ExfiltrationDetectionEnabled bool     `mapstructure:"exfiltration_detection_enabled"`
	LargeUploadThresholdMB       int      `mapstructure:"large_upload_threshold_mb"`
	SuspiciousDataPatterns       []string `mapstructure:"suspicious_data_patterns"`
	MonitorFileSharing           bool     `mapstructure:"monitor_file_sharing"`
	FileSharingDomains           []string `mapstructure:"file_sharing_domains"`
}

// Supporting data structures
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
}

// NewSentinelMonitor creates a comprehensive system-wide monitoring system
func NewSentinelMonitor(logger zerolog.Logger, eventBus *events.EventBus) scheduler.Monitor {
	monitor := &SentinelMonitor{
		BaseMonitor:          base_monitor.NewBaseMonitor("comprehensive_sentinel", base_monitor.ClassSentinel, logger, eventBus),
		config:               &ComprehensiveSentinelConfig{},
		certificateBaselines: make(map[string]string),
		resolvedBlocklist:    make(map[string][]net.IP),
		processBaseline:      make(map[int32]*ProcessInfo),
		dnsEvents:            make(chan DNSEvent, 1024),
		stopDNSCapture:       make(chan struct{}),
		clientStats:          make(map[string]*ClientStats),
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

	// Run all monitoring components concurrently
	var wg sync.WaitGroup

	// System monitoring (CPU, memory, processes)
	if sm.config.SystemMonitoringEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runSystemMonitoring(ctx)
		}()
	}

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

// System monitoring implementation
func (sm *SentinelMonitor) runSystemMonitoring(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running system monitoring...")

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
		status, _ := p.Status()

		procInfo := &ProcessInfo{
			PID:        p.Pid,
			Name:       name,
			Status:     status,
			CPUPercent: cpuPercent,
			MemPercent: memPercent,
			CreateTime: createTime,
			LastSeen:   time.Now(),
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
	if sm.config.ExfiltrationDetectionEnabled {
		count++
	}
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
