// pkg/monitors/enhanced/enhanced_sentry.go
// contains previous implementations:
// exfiltration_monitor.go
// filesystem_monitor.go
// firmware_monitor.go
// rootkit_monitor.go
package enhanced

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/lucid-vigil/sentinel/pkg/events"
	"github.com/lucid-vigil/sentinel/pkg/monitors/base_monitor"
	"github.com/lucid-vigil/sentinel/pkg/monitors/scheduler"
	"github.com/rs/zerolog"
	psnet "github.com/shirou/gopsutil/v3/net"
)

// SentryMonitor - Comprehensive security monitoring system
type SentryMonitor struct {
	*base_monitor.BaseMonitor
	config           *ComprehensiveSentryConfig
	highValueTargets []HighValueTarget
	threatLevel      ThreatLevel
	lastPatrol       time.Time
	baseline         map[string]string // path -> hash mapping for integrity checks

	// Network monitoring components
	networkBaseline NetworkBaseline
	lastTxBytes     uint64

	// Filesystem monitoring components
	fsWatcher      *fsnotify.Watcher
	suidBaseline   map[string]time.Time
	configBaseline map[string]string

	// Rootkit detection components
	rootkitSignatures []RootkitSignature

	// Firmware monitoring
	firmwareBaseline FirmwareInfo

	// Synchronization
	mu          sync.RWMutex
	watcherDone chan bool
}

// ComprehensiveSentryConfig - Extended configuration for all monitoring capabilities
type ComprehensiveSentryConfig struct {
	// Core sentry config
	HighValuePaths          []string `mapstructure:"high_value_paths"`
	CriticalProcesses       []string `mapstructure:"critical_processes"`
	ResponseMode            string   `mapstructure:"response_mode"`
	ResponseThreshold       string   `mapstructure:"response_threshold"`
	IntegrityCheckMode      string   `mapstructure:"integrity_check_mode"`
	PatrolInterval          string   `mapstructure:"patrol_interval"`
	ThreatAssessmentEnabled bool     `mapstructure:"threat_assessment_enabled"`

	// Network monitoring config
	UploadThresholdMB        int      `mapstructure:"upload_threshold_mb"`
	FileSharingDomains       []string `mapstructure:"file_sharing_domains"`
	NetworkMonitoringEnabled bool     `mapstructure:"network_monitoring_enabled"`

	// Filesystem monitoring config
	CriticalPaths           string `mapstructure:"critical_paths"`
	ExcludePaths            string `mapstructure:"exclude_paths"`
	MonitorHiddenFiles      bool   `mapstructure:"monitor_hidden_files"`
	AlertOnSuidChanges      bool   `mapstructure:"alert_on_suid_changes"`
	SuidCheckInterval       int    `mapstructure:"suid_check_interval"`
	SuidBaselineFile        string `mapstructure:"suid_baseline_file"`
	ConfigBaselineDir       string `mapstructure:"config_baseline_dir"`
	RealTimeWatchingEnabled bool   `mapstructure:"realtime_watching_enabled"`

	// Rootkit detection config
	RootkitDetectionEnabled bool `mapstructure:"rootkit_detection_enabled"`
	ChkrootkitEnabled       bool `mapstructure:"chkrootkit_enabled"`
	RkhunterEnabled         bool `mapstructure:"rkhunter_enabled"`
	ManualChecksEnabled     bool `mapstructure:"manual_checks_enabled"`

	// Firmware monitoring config
	FirmwareMonitoringEnabled bool `mapstructure:"firmware_monitoring_enabled"`
}

// Supporting data structures
type NetworkBaseline struct {
	InitialTxBytes    uint64
	BaselineTimestamp time.Time
	DomainIPs         map[string][]net.IP
}

type RootkitSignature struct {
	Path        string
	Pattern     string
	Description string
	Severity    string
}

type FirmwareInfo struct {
	BIOSVendor  string
	BIOSVersion string
	BIOSDate    string
	LastChecked time.Time
}

type HighValueTarget struct {
	Path        string    `json:"path"`
	Type        string    `json:"type"`
	Criticality string    `json:"criticality"`
	LastChecked time.Time `json:"last_checked"`
	Status      string    `json:"status"`
	Hash        string    `json:"hash,omitempty"`
}

type ThreatLevel string

const (
	ThreatLevelGreen  ThreatLevel = "green"
	ThreatLevelYellow ThreatLevel = "yellow"
	ThreatLevelOrange ThreatLevel = "orange"
	ThreatLevelRed    ThreatLevel = "red"
)

// NewSentryMonitor creates a comprehensive security monitoring system
func NewSentryMonitor(logger zerolog.Logger, eventBus *events.EventBus) scheduler.Monitor {
	monitor := &SentryMonitor{
		BaseMonitor:       base_monitor.NewBaseMonitor("comprehensive_sentry", base_monitor.ClassSentry, logger, eventBus),
		config:            &ComprehensiveSentryConfig{},
		highValueTargets:  []HighValueTarget{},
		threatLevel:       ThreatLevelGreen,
		baseline:          make(map[string]string),
		suidBaseline:      make(map[string]time.Time),
		configBaseline:    make(map[string]string),
		watcherDone:       make(chan bool),
		rootkitSignatures: initializeRootkitSignatures(),
		networkBaseline: NetworkBaseline{
			DomainIPs: make(map[string][]net.IP),
		},
	}

	// Add all monitoring capabilities
	monitor.AddCapability(base_monitor.CapabilityRealTime)
	monitor.AddCapability(base_monitor.CapabilityAutomatedResponse)
	monitor.AddCapability(base_monitor.CapabilityThreatIntel)
	monitor.AddCapability("network_monitoring")
	monitor.AddCapability("rootkit_detection")
	monitor.AddCapability("firmware_monitoring")
	monitor.AddCapability("filesystem_realtime")

	return monitor
}

// Configure sets up the comprehensive monitoring system
func (sm *SentryMonitor) Configure(config map[string]interface{}) error {
	sm.LogEvent(zerolog.InfoLevel, "Configuring Comprehensive Sentry Monitor")

	// Parse all configuration sections
	if err := sm.parseConfig(config); err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}

	// Initialize components based on configuration
	if sm.config.RealTimeWatchingEnabled {
		if err := sm.initializeFilesystemWatcher(); err != nil {
			sm.LogEvent(zerolog.WarnLevel, "Failed to initialize filesystem watcher").Err(err)
		}
	}

	if sm.config.NetworkMonitoringEnabled {
		sm.initializeNetworkMonitoring()
	}

	if sm.config.FirmwareMonitoringEnabled {
		sm.initializeFirmwareMonitoring()
	}

	sm.LogEvent(zerolog.InfoLevel, "Comprehensive Sentry Monitor configured successfully")
	return nil
}

// Run executes comprehensive security monitoring
func (sm *SentryMonitor) Run(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Comprehensive Sentry Monitor: Starting security patrol...")
	sm.UpdateState("status", "active")
	sm.UpdateState("patrol_start", time.Now())

	// Initialize high-value targets
	sm.mu.RLock()
	targetsEmpty := len(sm.highValueTargets) == 0
	sm.mu.RUnlock()

	if targetsEmpty {
		sm.initializeHighValueTargets(ctx)
	}

	// Run all monitoring components concurrently
	var wg sync.WaitGroup

	// Core sentry monitoring
	wg.Add(1)
	go func() {
		defer wg.Done()
		sm.runCoreSentryMonitoring(ctx)
	}()

	// Network monitoring
	if sm.config.NetworkMonitoringEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runNetworkMonitoring(ctx)
		}()
	}

	// Filesystem monitoring (periodic checks)
	wg.Add(1)
	go func() {
		defer wg.Done()
		sm.runFilesystemMonitoring(ctx)
	}()

	// Rootkit detection
	if sm.config.RootkitDetectionEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runRootkitDetection(ctx)
		}()
	}

	// Firmware monitoring
	if sm.config.FirmwareMonitoringEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runFirmwareMonitoring(ctx)
		}()
	}

	// Real-time filesystem watching (if enabled)
	if sm.config.RealTimeWatchingEnabled && sm.fsWatcher != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.runRealtimeFilesystemWatching(ctx)
		}()
	}

	// Wait for all monitoring components to complete
	wg.Wait()

	// Assess overall threat level and update state
	sm.assessComprehensiveThreatLevel(ctx)
	sm.updateComprehensiveMetrics()

	sm.lastPatrol = time.Now()
	sm.LogEvent(zerolog.InfoLevel, "Comprehensive Sentry Monitor: Security patrol completed").
		Str("threat_level", string(sm.threatLevel)).
		Int("targets_monitored", len(sm.highValueTargets))
}

// Core sentry monitoring (original functionality enhanced)
func (sm *SentryMonitor) runCoreSentryMonitoring(ctx context.Context) {
	// Assess current threat level if enabled
	if sm.config.ThreatAssessmentEnabled {
		previousThreatLevel := sm.threatLevel
		sm.assessThreatLevel(ctx)
		if sm.threatLevel != previousThreatLevel {
			sm.PublishEvent(ctx, events.EventThreatDetected, "system_threat_level",
				fmt.Sprintf("Threat level changed from %s to %s", previousThreatLevel, sm.threatLevel),
				string(sm.threatLevel), map[string]interface{}{
					"previous_level": string(previousThreatLevel),
					"new_level":      string(sm.threatLevel),
				})
		}
	}

	// Monitor high-value targets
	sm.monitorHighValueTargets(ctx)

	// Perform integrity checks
	sm.performIntegrityChecks(ctx)
}

// Network monitoring implementation
func (sm *SentryMonitor) runNetworkMonitoring(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running network security monitoring...")

	// Initialize network baseline if needed
	if sm.networkBaseline.InitialTxBytes == 0 {
		netIOCounters, err := psnet.IOCounters(false)
		if err != nil {
			sm.LogEvent(zerolog.ErrorLevel, "Failed to get initial network IO counters").Err(err)
			return
		}
		if len(netIOCounters) > 0 {
			sm.networkBaseline.InitialTxBytes = netIOCounters[0].BytesSent
			sm.networkBaseline.BaselineTimestamp = time.Now()
			sm.lastTxBytes = netIOCounters[0].BytesSent
		}
	}

	// Monitor for large uploads
	sm.monitorLargeUploads(ctx)

	// Monitor file sharing connections
	sm.monitorFileSharingConnections(ctx)
}

// Filesystem monitoring implementation
func (sm *SentryMonitor) runFilesystemMonitoring(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running filesystem security monitoring...")

	// Monitor SUID/SGID files
	sm.monitorSuidFiles(ctx)

	// Monitor critical configuration files
	sm.monitorConfigFiles(ctx)

	// Check for rootkit artifacts in filesystem
	sm.checkRootkitArtifacts(ctx)

	// Monitor disk usage
	sm.monitorDiskUsage(ctx)
}

// Rootkit detection implementation
func (sm *SentryMonitor) runRootkitDetection(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running rootkit detection...")

	if sm.config.ManualChecksEnabled {
		sm.runManualRootkitChecks(ctx)
	}

	if sm.config.ChkrootkitEnabled {
		sm.runChkrootkit(ctx)
	}

	if sm.config.RkhunterEnabled {
		sm.runRkhunter(ctx)
	}
}

// Firmware monitoring implementation
func (sm *SentryMonitor) runFirmwareMonitoring(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running firmware security monitoring...")

	vendor := sm.readDMIFile("bios_vendor")
	version := sm.readDMIFile("bios_version")
	date := sm.readDMIFile("bios_date")

	currentFirmware := FirmwareInfo{
		BIOSVendor:  vendor,
		BIOSVersion: version,
		BIOSDate:    date,
		LastChecked: time.Now(),
	}

	// Compare with baseline
	if sm.firmwareBaseline.BIOSVendor != "" {
		if currentFirmware.BIOSVendor != sm.firmwareBaseline.BIOSVendor ||
			currentFirmware.BIOSVersion != sm.firmwareBaseline.BIOSVersion ||
			currentFirmware.BIOSDate != sm.firmwareBaseline.BIOSDate {
			sm.PublishEvent(ctx, events.EventFirmwareChange, "bios_change",
				"BIOS firmware change detected", "critical",
				map[string]interface{}{
					"previous_vendor":  sm.firmwareBaseline.BIOSVendor,
					"current_vendor":   currentFirmware.BIOSVendor,
					"previous_version": sm.firmwareBaseline.BIOSVersion,
					"current_version":  currentFirmware.BIOSVersion,
				})
		}
	}

	sm.firmwareBaseline = currentFirmware

	if vendor != "unknown" || version != "unknown" || date != "unknown" {
		sm.LogEvent(zerolog.InfoLevel, "BIOS information verified").
			Str("vendor", vendor).
			Str("version", version).
			Str("date", date)
	}
}

// Real-time filesystem watching implementation
func (sm *SentryMonitor) runRealtimeFilesystemWatching(ctx context.Context) {
	if sm.fsWatcher == nil {
		return
	}

	sm.LogEvent(zerolog.InfoLevel, "Starting real-time filesystem monitoring...")

	for {
		select {
		case event, ok := <-sm.fsWatcher.Events:
			if !ok {
				return
			}
			sm.handleFilesystemEvent(ctx, event)
		case err, ok := <-sm.fsWatcher.Errors:
			if !ok {
				return
			}
			sm.LogEvent(zerolog.ErrorLevel, "Filesystem watcher error").Err(err)
		case <-ctx.Done():
			sm.watcherDone <- true
			return
		}
	}
}

// Network monitoring helper methods
func (sm *SentryMonitor) monitorLargeUploads(ctx context.Context) {
	netIOCounters, err := psnet.IOCounters(false)
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get network IO counters").Err(err)
		return
	}

	if len(netIOCounters) == 0 {
		return
	}

	currentTxBytes := netIOCounters[0].BytesSent
	if currentTxBytes < sm.lastTxBytes {
		sm.lastTxBytes = currentTxBytes
		return
	}

	transmittedBytes := currentTxBytes - sm.lastTxBytes
	transmittedMB := transmittedBytes / (1024 * 1024)

	if transmittedMB > uint64(sm.config.UploadThresholdMB) {
		sm.PublishEvent(ctx, events.EventDataExfiltration, "large_upload",
			fmt.Sprintf("Large data upload detected: %d MB", transmittedMB),
			"high", map[string]interface{}{
				"transmitted_mb": transmittedMB,
				"threshold_mb":   sm.config.UploadThresholdMB,
			})
	}

	sm.lastTxBytes = currentTxBytes
}

func (sm *SentryMonitor) monitorFileSharingConnections(ctx context.Context) {
	connections, err := psnet.Connections("inet")
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to get network connections").Err(err)
		return
	}

	// Resolve domains if not cached
	for _, domain := range sm.config.FileSharingDomains {
		if _, exists := sm.networkBaseline.DomainIPs[domain]; !exists {
			if ips, err := net.LookupIP(domain); err == nil {
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
					sm.PublishEvent(ctx, events.EventSuspiciousNetwork, "file_sharing",
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

// Filesystem monitoring helper methods
func (sm *SentryMonitor) monitorSuidFiles(ctx context.Context) {
	cmd := exec.Command("find", "/", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print")
	output, err := cmd.Output()
	if err != nil {
		sm.LogEvent(zerolog.ErrorLevel, "Failed to find SUID/SGID files").Err(err)
		return
	}

	currentSuidFiles := strings.Split(strings.TrimSpace(string(output)), "\n")
	currentTime := time.Now()

	// Check for new SUID files
	for _, file := range currentSuidFiles {
		if file == "" {
			continue
		}
		if _, exists := sm.suidBaseline[file]; !exists {
			sm.PublishEvent(ctx, events.EventFileSystemChange, file,
				fmt.Sprintf("New SUID/SGID file detected: %s", file),
				"high", map[string]interface{}{
					"file_type": "suid_sgid",
					"action":    "created",
				})
			sm.suidBaseline[file] = currentTime
		}
	}

	// Check for removed SUID files
	currentSet := make(map[string]bool)
	for _, file := range currentSuidFiles {
		if file != "" {
			currentSet[file] = true
		}
	}

	for file := range sm.suidBaseline {
		if !currentSet[file] {
			sm.PublishEvent(ctx, events.EventFileSystemChange, file,
				fmt.Sprintf("SUID/SGID file removed: %s", file),
				"medium", map[string]interface{}{
					"file_type": "suid_sgid",
					"action":    "removed",
				})
			delete(sm.suidBaseline, file)
		}
	}
}

func (sm *SentryMonitor) monitorConfigFiles(ctx context.Context) {
	criticalConfigFiles := []string{
		"/etc/passwd", "/etc/shadow", "/etc/group",
		"/etc/sudoers", "/etc/hosts", "/etc/crontab",
	}

	for _, file := range criticalConfigFiles {
		currentHash, err := sm.calculateFileHash(file)
		if err != nil {
			continue
		}

		if baseline, exists := sm.configBaseline[file]; exists {
			if currentHash != baseline {
				sm.PublishEvent(ctx, events.EventFileSystemChange, file,
					fmt.Sprintf("Critical configuration file changed: %s", file),
					"critical", map[string]interface{}{
						"file_type":     "config",
						"expected_hash": baseline,
						"actual_hash":   currentHash,
					})
			}
		}
		sm.configBaseline[file] = currentHash
	}
}

func (sm *SentryMonitor) checkRootkitArtifacts(ctx context.Context) {
	rootkitFiles := []string{
		"/dev/shm/.hidden", "/tmp/.hidden", "/var/tmp/.hidden",
		"/usr/bin/..", "/usr/lib/.hidden", "/etc/.hidden",
	}

	for _, file := range rootkitFiles {
		if _, err := os.Stat(file); err == nil {
			sm.PublishEvent(ctx, events.EventRootkitDetected, file,
				fmt.Sprintf("Potential rootkit artifact: %s", file),
				"critical", map[string]interface{}{
					"artifact_type": "hidden_file",
					"location":      file,
				})
		}
	}
}

func (sm *SentryMonitor) monitorDiskUsage(ctx context.Context) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return
	}

	all := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := all - free
	diskUsagePercent := float64(used) / float64(all) * 100

	if diskUsagePercent > 90 {
		sm.PublishEvent(ctx, events.EventSystemAnomaly, "disk_usage",
			fmt.Sprintf("High disk usage: %.1f%%", diskUsagePercent),
			"medium", map[string]interface{}{
				"usage_percent": diskUsagePercent,
				"threshold":     90.0,
			})
	}

	sm.UpdateState("disk_usage_percent", diskUsagePercent)
}

// Rootkit detection helper methods
func (sm *SentryMonitor) runManualRootkitChecks(ctx context.Context) {
	// Check /dev for suspicious files
	sm.checkDevForSuspiciousFiles(ctx)

	// Check for promiscuous network interfaces
	sm.checkPromiscuousMode(ctx)

	// Check for immutable files
	sm.checkImmutableFiles(ctx)
}

func (sm *SentryMonitor) checkDevForSuspiciousFiles(ctx context.Context) {
	files, err := os.ReadDir("/dev")
	if err != nil {
		return
	}

	for _, file := range files {
		filePath := filepath.Join("/dev", file.Name())
		info, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		mode := info.Mode()
		if mode&os.ModeDevice == 0 && mode&os.ModeDir == 0 && mode&os.ModeSymlink == 0 {
			sm.PublishEvent(ctx, events.EventRootkitDetected, filePath,
				fmt.Sprintf("Suspicious file in /dev: %s", filePath),
				"high", map[string]interface{}{
					"file_mode": mode.String(),
					"location":  "/dev",
				})
		}
	}
}

func (sm *SentryMonitor) checkPromiscuousMode(ctx context.Context) {
	cmd := exec.Command("ip", "link")
	out, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "PROMISC") {
			sm.PublishEvent(ctx, events.EventRootkitDetected, "promiscuous_interface",
				fmt.Sprintf("Network interface in promiscuous mode: %s", line),
				"high", map[string]interface{}{
					"interface_info": line,
				})
		}
	}
}

func (sm *SentryMonitor) checkImmutableFiles(ctx context.Context) {
	criticalDirs := []string{"/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"}

	for _, dir := range criticalDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			cmd := exec.Command("lsattr", path)
			if attrOutput, err := cmd.Output(); err == nil {
				if strings.Contains(string(attrOutput), "----i---") {
					sm.PublishEvent(ctx, events.EventRootkitDetected, path,
						fmt.Sprintf("Immutable file detected: %s", path),
						"medium", map[string]interface{}{
							"attributes": strings.TrimSpace(string(attrOutput)),
						})
				}
			}
			return nil
		})
	}
}

func (sm *SentryMonitor) runChkrootkit(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running chkrootkit scan (placeholder)")
	// Implementation would execute chkrootkit and parse output
}

func (sm *SentryMonitor) runRkhunter(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Running rkhunter scan (placeholder)")
	// Implementation would execute rkhunter and parse output
}

// Filesystem event handling
func (sm *SentryMonitor) handleFilesystemEvent(ctx context.Context, event fsnotify.Event) {
	// Skip temporary files and common noise
	if sm.shouldSkipEvent(event) {
		return
	}

	// Check if path is excluded
	if sm.isPathExcluded(event.Name) {
		return
	}

	sm.LogEvent(zerolog.InfoLevel, "Filesystem event detected").
		Str("event", event.Op.String()).
		Str("file", event.Name)

	switch {
	case event.Op&fsnotify.Create == fsnotify.Create:
		sm.handleFileCreated(ctx, event.Name)
	case event.Op&fsnotify.Remove == fsnotify.Remove:
		sm.handleFileRemoved(ctx, event.Name)
	case event.Op&fsnotify.Write == fsnotify.Write:
		sm.handleFileModified(ctx, event.Name)
	case event.Op&fsnotify.Chmod == fsnotify.Chmod:
		sm.handlePermissionChange(ctx, event.Name)
	case event.Op&fsnotify.Rename == fsnotify.Rename:
		sm.handleFileRenamed(ctx, event.Name)
	}
}

func (sm *SentryMonitor) handleFileCreated(ctx context.Context, filePath string) {
	info, err := os.Stat(filePath)
	if err != nil {
		return
	}

	// Check for executable files
	if info.Mode().IsRegular() && (info.Mode().Perm()&0111) != 0 {
		sm.PublishEvent(ctx, events.EventFileSystemChange, filePath,
			fmt.Sprintf("New executable file created: %s", filePath),
			"medium", map[string]interface{}{
				"file_type": "executable",
				"action":    "created",
				"mode":      info.Mode().String(),
			})

		// Check for SUID/SGID
		if (info.Mode()&os.ModeSetuid != 0) || (info.Mode()&os.ModeSetgid != 0) {
			sm.PublishEvent(ctx, events.EventFileSystemChange, filePath,
				fmt.Sprintf("New SUID/SGID file created: %s", filePath),
				"high", map[string]interface{}{
					"file_type": "suid_sgid",
					"action":    "created",
					"mode":      info.Mode().String(),
				})
		}
	}

	// Check for hidden files in unusual locations
	if sm.config.MonitorHiddenFiles && strings.HasPrefix(filepath.Base(filePath), ".") {
		if !strings.HasPrefix(filePath, "/home/") {
			sm.PublishEvent(ctx, events.EventFileSystemChange, filePath,
				fmt.Sprintf("Hidden file created outside home directory: %s", filePath),
				"medium", map[string]interface{}{
					"file_type": "hidden",
					"action":    "created",
				})
		}
	}

	// Check file content for suspicious patterns
	sm.checkSuspiciousFileContent(ctx, filePath)
}

func (sm *SentryMonitor) checkSuspiciousFileContent(ctx context.Context, filePath string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	suspiciousPatterns := []struct {
		pattern     string
		description string
		severity    string
	}{
		{"nc -l", "netcat listener", "high"},
		{"/bin/sh", "shell execution", "medium"},
		{"python.*socket", "python network socket", "medium"},
		{"perl.*socket", "perl network socket", "medium"},
		{"wget|curl", "download utility", "low"},
		{"bash -i", "interactive bash shell", "high"},
		{"exec\\(", "code execution", "high"},
		{"system\\(", "system command execution", "high"},
	}

	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, string(content)); matched {
			sm.PublishEvent(ctx, events.EventMalwareDetected, filePath,
				fmt.Sprintf("Suspicious content detected in file: %s (%s)", filePath, pattern.description),
				pattern.severity, map[string]interface{}{
					"pattern":     pattern.pattern,
					"description": pattern.description,
					"file_size":   len(content),
				})
			break // Only report first match to avoid spam
		}
	}
}

func (sm *SentryMonitor) handleFileRemoved(ctx context.Context, filePath string) {
	sm.PublishEvent(ctx, events.EventFileSystemChange, filePath,
		fmt.Sprintf("File deleted: %s", filePath), "low", map[string]interface{}{
			"action": "deleted",
		})
}

func (sm *SentryMonitor) handleFileModified(ctx context.Context, filePath string) {
	// Check if it's a high-value target
	sm.mu.RLock()
	isHighValue := false
	for _, target := range sm.highValueTargets {
		if target.Path == filePath {
			isHighValue = true
			break
		}
	}
	sm.mu.RUnlock()

	severity := "low"
	if isHighValue {
		severity = "high"
	}

	sm.PublishEvent(ctx, events.EventFileSystemChange, filePath,
		fmt.Sprintf("File modified: %s", filePath), severity, map[string]interface{}{
			"action":            "modified",
			"high_value_target": isHighValue,
		})
}

func (sm *SentryMonitor) handlePermissionChange(ctx context.Context, filePath string) {
	info, err := os.Stat(filePath)
	if err != nil {
		return
	}

	perm := info.Mode().Perm()

	// Check for world-writable files
	if (perm & 0002) != 0 {
		sm.PublishEvent(ctx, events.EventFileSystemChange, filePath,
			fmt.Sprintf("World-writable file detected: %s", filePath),
			"medium", map[string]interface{}{
				"permissions": perm.String(),
				"action":      "permission_change",
			})
	}

	// Check for SUID/SGID changes
	if sm.config.AlertOnSuidChanges && ((info.Mode()&os.ModeSetuid != 0) || (info.Mode()&os.ModeSetgid != 0)) {
		sm.PublishEvent(ctx, events.EventFileSystemChange, filePath,
			fmt.Sprintf("SUID/SGID permissions detected: %s", filePath),
			"high", map[string]interface{}{
				"permissions": perm.String(),
				"action":      "suid_sgid_change",
			})
	}
}

func (sm *SentryMonitor) handleFileRenamed(ctx context.Context, filePath string) {
	sm.PublishEvent(ctx, events.EventFileSystemChange, filePath,
		fmt.Sprintf("File renamed/moved: %s", filePath), "low", map[string]interface{}{
			"action": "renamed",
		})
}

// Helper methods for filesystem event filtering
func (sm *SentryMonitor) shouldSkipEvent(event fsnotify.Event) bool {
	skipSuffixes := []string{".tmp", ".swp", "~", ".log"}
	skipPrefixes := []string{".#"}

	for _, suffix := range skipSuffixes {
		if strings.HasSuffix(event.Name, suffix) {
			return true
		}
	}

	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(filepath.Base(event.Name), prefix) {
			return true
		}
	}

	return false
}

func (sm *SentryMonitor) isPathExcluded(path string) bool {
	excludePaths := strings.Fields(sm.config.ExcludePaths)
	for _, excludePath := range excludePaths {
		if strings.HasPrefix(path, excludePath) {
			return true
		}
	}
	return false
}

// Comprehensive threat assessment
func (sm *SentryMonitor) assessComprehensiveThreatLevel(ctx context.Context) {
	var score int

	// Get metrics from event bus
	if sm.EventBus != nil {
		metrics := sm.EventBus.GetMetrics()

		// Weight different types of events
		score += metrics.EventsBySeverity["critical"] * 4
		score += metrics.EventsBySeverity["high"] * 2
		score += metrics.EventsBySeverity["medium"] * 1
	}

	// Additional scoring based on specific threats
	sm.mu.RLock()
	compromisedTargets := 0
	for _, target := range sm.highValueTargets {
		if target.Status == "compromised" || target.Status == "missing" {
			compromisedTargets++
		}
	}
	sm.mu.RUnlock()

	score += compromisedTargets * 3

	// Determine threat level
	previousLevel := sm.threatLevel
	switch {
	case score >= 20:
		sm.threatLevel = ThreatLevelRed
	case score >= 10:
		sm.threatLevel = ThreatLevelOrange
	case score >= 5:
		sm.threatLevel = ThreatLevelYellow
	default:
		sm.threatLevel = ThreatLevelGreen
	}

	if sm.threatLevel != previousLevel {
		sm.PublishEvent(ctx, events.EventThreatDetected, "comprehensive_threat_assessment",
			fmt.Sprintf("Comprehensive threat level changed from %s to %s (score: %d)",
				previousLevel, sm.threatLevel, score),
			string(sm.threatLevel), map[string]interface{}{
				"previous_level":      string(previousLevel),
				"new_level":           string(sm.threatLevel),
				"threat_score":        score,
				"compromised_targets": compromisedTargets,
			})
	}

	sm.UpdateState("comprehensive_threat_level", string(sm.threatLevel))
	sm.UpdateState("threat_score", score)
}

// Comprehensive metrics update
func (sm *SentryMonitor) updateComprehensiveMetrics() {
	sm.UpdateState("last_patrol", sm.lastPatrol)

	sm.mu.RLock()
	targetsCount := len(sm.highValueTargets)
	statusCounts := make(map[string]int)
	for _, target := range sm.highValueTargets {
		statusCounts[target.Status]++
	}
	sm.mu.RUnlock()

	sm.UpdateState("targets_count", targetsCount)
	sm.UpdateState("target_status_counts", statusCounts)
	sm.UpdateState("suid_baseline_count", len(sm.suidBaseline))
	sm.UpdateState("config_baseline_count", len(sm.configBaseline))
	sm.UpdateState("network_domains_monitored", len(sm.config.FileSharingDomains))
	sm.UpdateState("comprehensive_monitoring_active", true)

	// Component status
	componentStatus := map[string]bool{
		"network_monitoring":  sm.config.NetworkMonitoringEnabled,
		"rootkit_detection":   sm.config.RootkitDetectionEnabled,
		"firmware_monitoring": sm.config.FirmwareMonitoringEnabled,
		"realtime_watching":   sm.config.RealTimeWatchingEnabled && sm.fsWatcher != nil,
	}
	sm.UpdateState("component_status", componentStatus)
}

// Configuration parsing helpers
func (sm *SentryMonitor) parseConfig(config map[string]interface{}) error {
	// Parse high-value paths
	if highValuePaths, ok := config["high_value_paths"].([]interface{}); ok {
		sm.config.HighValuePaths = make([]string, len(highValuePaths))
		for i, path := range highValuePaths {
			if str, ok := path.(string); ok {
				sm.config.HighValuePaths[i] = str
			}
		}
	}

	// Parse file sharing domains
	if domains, ok := config["file_sharing_domains"].([]interface{}); ok {
		sm.config.FileSharingDomains = make([]string, len(domains))
		for i, domain := range domains {
			if str, ok := domain.(string); ok {
				sm.config.FileSharingDomains[i] = str
			}
		}
	}

	// Parse string configurations with defaults
	stringConfigs := map[string]*string{
		"response_mode":        &sm.config.ResponseMode,
		"response_threshold":   &sm.config.ResponseThreshold,
		"integrity_check_mode": &sm.config.IntegrityCheckMode,
		"patrol_interval":      &sm.config.PatrolInterval,
		"critical_paths":       &sm.config.CriticalPaths,
		"exclude_paths":        &sm.config.ExcludePaths,
		"suid_baseline_file":   &sm.config.SuidBaselineFile,
		"config_baseline_dir":  &sm.config.ConfigBaselineDir,
	}

	for key, ptr := range stringConfigs {
		if val, ok := config[key].(string); ok {
			*ptr = val
		}
	}

	// Parse integer configurations with defaults
	intConfigs := map[string]*int{
		"upload_threshold_mb": &sm.config.UploadThresholdMB,
		"suid_check_interval": &sm.config.SuidCheckInterval,
	}

	for key, ptr := range intConfigs {
		if val, ok := config[key].(int); ok {
			*ptr = val
		}
	}

	// Parse boolean configurations with defaults
	boolConfigs := map[string]*bool{
		"threat_assessment_enabled":   &sm.config.ThreatAssessmentEnabled,
		"network_monitoring_enabled":  &sm.config.NetworkMonitoringEnabled,
		"monitor_hidden_files":        &sm.config.MonitorHiddenFiles,
		"alert_on_suid_changes":       &sm.config.AlertOnSuidChanges,
		"realtime_watching_enabled":   &sm.config.RealTimeWatchingEnabled,
		"rootkit_detection_enabled":   &sm.config.RootkitDetectionEnabled,
		"chkrootkit_enabled":          &sm.config.ChkrootkitEnabled,
		"rkhunter_enabled":            &sm.config.RkhunterEnabled,
		"manual_checks_enabled":       &sm.config.ManualChecksEnabled,
		"firmware_monitoring_enabled": &sm.config.FirmwareMonitoringEnabled,
	}

	for key, ptr := range boolConfigs {
		if val, ok := config[key].(bool); ok {
			*ptr = val
		}
	}

	// Set defaults for missing values
	sm.setConfigDefaults()

	return nil
}

func (sm *SentryMonitor) setConfigDefaults() {
	if sm.config.ResponseMode == "" {
		sm.config.ResponseMode = "respond"
	}
	if sm.config.ResponseThreshold == "" {
		sm.config.ResponseThreshold = "medium"
	}
	if sm.config.IntegrityCheckMode == "" {
		sm.config.IntegrityCheckMode = "hash"
	}
	if sm.config.PatrolInterval == "" {
		sm.config.PatrolInterval = "30s"
	}
	if sm.config.UploadThresholdMB == 0 {
		sm.config.UploadThresholdMB = 100
	}
	if sm.config.SuidCheckInterval == 0 {
		sm.config.SuidCheckInterval = 300 // 5 minutes
	}
	if sm.config.SuidBaselineFile == "" {
		sm.config.SuidBaselineFile = "/var/lib/sentinel/suid_baseline.txt"
	}
	if sm.config.ConfigBaselineDir == "" {
		sm.config.ConfigBaselineDir = "/var/lib/sentinel/config_baselines"
	}
}

// Component initialization methods
func (sm *SentryMonitor) initializeFilesystemWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// Add critical paths to watcher
	paths := strings.Fields(sm.config.CriticalPaths)
	for _, path := range paths {
		if err := watcher.Add(path); err != nil {
			sm.LogEvent(zerolog.WarnLevel, "Failed to add path to watcher").
				Str("path", path).Err(err)
			continue
		}
		sm.LogEvent(zerolog.InfoLevel, "Added path to filesystem watcher").
			Str("path", path)
	}

	sm.fsWatcher = watcher
	return nil
}

func (sm *SentryMonitor) initializeNetworkMonitoring() {
	// Initialize network baseline
	sm.networkBaseline.BaselineTimestamp = time.Now()

	// Pre-resolve file sharing domains
	for _, domain := range sm.config.FileSharingDomains {
		if ips, err := net.LookupIP(domain); err == nil {
			sm.networkBaseline.DomainIPs[domain] = ips
		}
	}

	sm.LogEvent(zerolog.InfoLevel, "Network monitoring initialized").
		Int("domains_to_monitor", len(sm.config.FileSharingDomains))
}

func (sm *SentryMonitor) initializeFirmwareMonitoring() {
	sm.firmwareBaseline = FirmwareInfo{
		BIOSVendor:  sm.readDMIFile("bios_vendor"),
		BIOSVersion: sm.readDMIFile("bios_version"),
		BIOSDate:    sm.readDMIFile("bios_date"),
		LastChecked: time.Now(),
	}

	sm.LogEvent(zerolog.InfoLevel, "Firmware monitoring initialized").
		Str("vendor", sm.firmwareBaseline.BIOSVendor).
		Str("version", sm.firmwareBaseline.BIOSVersion)
}

// DMI file reading (from original firmware monitor)
func (sm *SentryMonitor) readDMIFile(fileName string) string {
	path := filepath.Join("/sys/class/dmi/id/", fileName)
	content, err := os.ReadFile(path)
	if err != nil {
		sm.LogEvent(zerolog.DebugLevel, "Failed to read DMI file").
			Str("file", path).Err(err)
		return "unknown"
	}
	return strings.TrimSpace(string(content))
}

// Rootkit signatures initialization
func initializeRootkitSignatures() []RootkitSignature {
	return []RootkitSignature{
		{"/dev/shm/.hidden", ".*", "Hidden file in shared memory", "high"},
		{"/tmp/.hidden", ".*", "Hidden file in temp directory", "medium"},
		{"/var/tmp/.hidden", ".*", "Hidden file in var temp", "medium"},
		{"/usr/bin/..", ".*", "Unusual double-dot directory in usr/bin", "high"},
		{"/usr/lib/.hidden", ".*", "Hidden file in usr/lib", "high"},
		{"/etc/.hidden", ".*", "Hidden file in etc", "critical"},
	}
}

// Core monitoring methods (reused from original implementation)
func (sm *SentryMonitor) initializeHighValueTargets(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Initializing high-value targets")

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Add configured paths
	for _, path := range sm.config.HighValuePaths {
		target := HighValueTarget{
			Path:        path,
			Type:        sm.determineTargetType(path),
			Criticality: sm.assessCriticality(path),
			LastChecked: time.Now(),
			Status:      "monitoring",
		}

		// Calculate initial hash if file exists
		if target.Type == "file" {
			if hash, err := sm.calculateFileHash(path); err == nil {
				target.Hash = hash
				sm.baseline[path] = hash
			}
		}

		sm.highValueTargets = append(sm.highValueTargets, target)
	}

	// Add system-critical paths
	systemCriticalPaths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/boot", "/etc/ssh", "/root/.ssh",
		"/var/log", "/etc/systemd",
	}

	for _, path := range systemCriticalPaths {
		if _, err := os.Stat(path); err == nil {
			target := HighValueTarget{
				Path:        path,
				Type:        sm.determineTargetType(path),
				Criticality: "critical",
				LastChecked: time.Now(),
				Status:      "monitoring",
			}

			if target.Type == "file" {
				if hash, err := sm.calculateFileHash(path); err == nil {
					target.Hash = hash
					sm.baseline[path] = hash
				}
			}

			sm.highValueTargets = append(sm.highValueTargets, target)
		}
	}

	sm.LogEvent(zerolog.InfoLevel, "High-value targets initialized").
		Int("count", len(sm.highValueTargets))
}

func (sm *SentryMonitor) determineTargetType(path string) string {
	if strings.HasPrefix(path, "proc:") {
		return "process"
	}

	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			return "directory"
		}
		return "file"
	}

	return "file"
}

func (sm *SentryMonitor) assessCriticality(path string) string {
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

	highPaths := []string{
		"/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
		"/home", "/var", "/opt",
	}

	for _, high := range highPaths {
		if strings.HasPrefix(path, high) {
			return "high"
		}
	}

	return "medium"
}

func (sm *SentryMonitor) calculateFileHash(filepath string) (string, error) {
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

func (sm *SentryMonitor) assessThreatLevel(ctx context.Context) {
	var score int

	// Check for recent security events
	if sm.state.EventsRaised > 10 {
		score += 2
	} else if sm.state.EventsRaised > 5 {
		score += 1
	}

	// Determine threat level based on score
	switch {
	case score >= 4:
		sm.threatLevel = ThreatLevelRed
	case score >= 3:
		sm.threatLevel = ThreatLevelOrange
	case score >= 1:
		sm.threatLevel = ThreatLevelYellow
	default:
		sm.threatLevel = ThreatLevelGreen
	}

	sm.UpdateState("threat_level", string(sm.threatLevel))
}

func (sm *SentryMonitor) monitorHighValueTargets(ctx context.Context) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for i := range sm.highValueTargets {
		target := &sm.highValueTargets[i]

		switch target.Type {
		case "file":
			sm.monitorFile(ctx, target)
		case "directory":
			sm.monitorDirectory(ctx, target)
		case "process":
			sm.monitorProcess(ctx, target)
		}

		target.LastChecked = time.Now()
	}
}

func (sm *SentryMonitor) monitorFile(ctx context.Context, target *HighValueTarget) {
	info, err := os.Stat(target.Path)
	if err != nil {
		if os.IsNotExist(err) {
			sm.handleFileNotFound(ctx, target)
		}
		return
	}

	// Integrity check
	if sm.config.IntegrityCheckMode == "hash" || sm.config.IntegrityCheckMode == "both" {
		if currentHash, err := sm.calculateFileHash(target.Path); err == nil {
			if baseline, exists := sm.baseline[target.Path]; exists {
				if currentHash != baseline {
					sm.handleIntegrityViolation(ctx, target, baseline, currentHash)
				}
			} else {
				sm.baseline[target.Path] = currentHash
				target.Hash = currentHash
			}
		}
	}

	target.Status = "verified"
}

func (sm *SentryMonitor) monitorDirectory(ctx context.Context, target *HighValueTarget) {
	info, err := os.Stat(target.Path)
	if err != nil {
		if os.IsNotExist(err) {
			sm.handleDirectoryNotFound(ctx, target)
		}
		return
	}

	if !info.IsDir() {
		sm.PublishEvent(ctx, events.EventFileSystemChange, target.Path,
			"High-value directory is no longer a directory", "high",
			map[string]interface{}{
				"criticality": target.Criticality,
				"target_type": target.Type,
			})
		return
	}

	target.Status = "verified"
}

func (sm *SentryMonitor) monitorProcess(ctx context.Context, target *HighValueTarget) {
	processName := strings.TrimPrefix(target.Path, "proc:")
	sm.LogEvent(zerolog.DebugLevel, "Monitoring process").Str("process", processName)
	target.Status = "running"
}

func (sm *SentryMonitor) performIntegrityChecks(ctx context.Context) {
	checkCount := 0
	violationCount := 0

	sm.mu.RLock()
	targets := make([]HighValueTarget, len(sm.highValueTargets))
	copy(targets, sm.highValueTargets)
	sm.mu.RUnlock()

	for _, target := range targets {
		if target.Type == "file" {
			checkCount++
			if currentHash, err := sm.calculateFileHash(target.Path); err == nil {
				sm.mu.RLock()
				baseline, exists := sm.baseline[target.Path]
				sm.mu.RUnlock()

				if exists && currentHash != baseline {
					violationCount++
				}
			}
		}
	}

	sm.UpdateState("integrity_checks_performed", checkCount)
	sm.UpdateState("integrity_violations_found", violationCount)
}

// Event handlers
func (sm *SentryMonitor) handleFileNotFound(ctx context.Context, target *HighValueTarget) {
	severity := "medium"
	if target.Criticality == "critical" {
		severity = "critical"
	} else if target.Criticality == "high" {
		severity = "high"
	}

	sm.PublishEvent(ctx, events.EventFileSystemChange, target.Path,
		fmt.Sprintf("High-value file not found: %s", target.Path),
		severity, map[string]interface{}{
			"criticality":  target.Criticality,
			"target_type":  target.Type,
			"last_checked": target.LastChecked,
		})

	target.Status = "missing"
}

func (sm *SentryMonitor) handleDirectoryNotFound(ctx context.Context, target *HighValueTarget) {
	severity := "high"
	if target.Criticality == "critical" {
		severity = "critical"
	}

	sm.PublishEvent(ctx, events.EventFileSystemChange, target.Path,
		fmt.Sprintf("High-value directory not found: %s", target.Path),
		severity, map[string]interface{}{
			"criticality":  target.Criticality,
			"target_type":  target.Type,
			"last_checked": target.LastChecked,
		})

	target.Status = "missing"
}

func (sm *SentryMonitor) handleIntegrityViolation(ctx context.Context, target *HighValueTarget, expectedHash, actualHash string) {
	severity := "high"
	if target.Criticality == "critical" {
		severity = "critical"
	}

	sm.PublishEvent(ctx, events.EventFileSystemChange, target.Path,
		fmt.Sprintf("Integrity violation detected for %s", target.Path),
		severity, map[string]interface{}{
			"criticality":   target.Criticality,
			"expected_hash": expectedHash,
			"actual_hash":   actualHash,
			"target_type":   target.Type,
			"check_time":    time.Now(),
		})

	target.Status = "compromised"
	target.Hash = actualHash
	sm.baseline[target.Path] = actualHash
}

// Cleanup method
func (sm *SentryMonitor) Cleanup() error {
	if sm.fsWatcher != nil {
		sm.fsWatcher.Close()
	}

	select {
	case <-sm.watcherDone:
		// Watcher goroutine has finished
	case <-time.After(5 * time.Second):
		// Timeout waiting for watcher to finish
		sm.LogEvent(zerolog.WarnLevel, "Timeout waiting for filesystem watcher to finish")
	}

	return nil
}

// Public API methods for external access
func (sm *SentryMonitor) GetThreatLevel() ThreatLevel {
	return sm.threatLevel
}

func (sm *SentryMonitor) GetHighValueTargets() []HighValueTarget {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	targets := make([]HighValueTarget, len(sm.highValueTargets))
	copy(targets, sm.highValueTargets)
	return targets
}

func (sm *SentryMonitor) GetConfig() *ComprehensiveSentryConfig {
	return sm.config
}

func (sm *SentryMonitor) GetNetworkBaseline() NetworkBaseline {
	return sm.networkBaseline
}

func (sm *SentryMonitor) GetFirmwareInfo() FirmwareInfo {
	return sm.firmwareBaseline
}
