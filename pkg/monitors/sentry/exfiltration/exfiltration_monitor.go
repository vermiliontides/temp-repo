package exfiltration

import (
	"context"
	"fmt"
	"net"

	"github.com/lucid-vigil/sentinel/pkg/monitors/base"
	"github.com/lucid-vigil/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
	psnet "github.com/shirou/gopsutil/v3/net"
)

// ExfiltrationMonitorConfig holds configuration for the ExfiltrationMonitor.
type ExfiltrationMonitorConfig struct {
	UploadThresholdMB  int      `mapstructure:"upload_threshold_mb"`
	FileSharingDomains []string `mapstructure:"file_sharing_domains"`
	RunInterval        int      `mapstructure:"run_interval"`
}

// ExfiltrationMonitor implements the scheduler.Monitor interface for exfiltration monitoring.
type ExfiltrationMonitor struct {
	*base.BaseMonitor
	config      *ExfiltrationMonitorConfig
	lastTxBytes uint64
}

// NewExfiltrationMonitor creates a new ExfiltrationMonitor.
func NewExfiltrationMonitor(logger zerolog.Logger) scheduler.Monitor {
	return &ExfiltrationMonitor{
		BaseMonitor: base.NewBaseMonitor("exfiltration_monitor", logger),
		config:      &ExfiltrationMonitorConfig{},
	}
}

// Run executes the exfiltration monitoring logic.
func (em *ExfiltrationMonitor) Run(ctx context.Context) {
	em.LogEvent(zerolog.InfoLevel, "Running Exfiltration Monitor...")

	// Initialize lastTxBytes on first run
	if em.lastTxBytes == 0 {
		netIOCounters, err := psnet.IOCounters(false)
		if err != nil {
			em.LogEvent(zerolog.ErrorLevel, "Failed to get initial network IO counters.").Err(err)
			return
		}
		if len(netIOCounters) > 0 {
			em.lastTxBytes = netIOCounters[0].BytesSent
		}
	}

	em.monitorLargeUploads()
	em.monitorFileSharingConnections()

	em.LogEvent(zerolog.InfoLevel, "Exfiltration Monitor finished.")
}

// monitorLargeUploads monitors for large data uploads.
func (em *ExfiltrationMonitor) monitorLargeUploads() {
	em.LogEvent(zerolog.InfoLevel, "Monitoring for large data uploads...")

	netIOCounters, err := psnet.IOCounters(false)
	if err != nil {
		em.LogEvent(zerolog.ErrorLevel, "Failed to get network IO counters.").Err(err)
		return
	}

	if len(netIOCounters) == 0 {
		em.LogEvent(zerolog.WarnLevel, "No network interfaces found for IO counters.")
		return
	}
	currentTxBytes := netIOCounters[0].BytesSent

	// Calculate transmitted data since last check
	if currentTxBytes < em.lastTxBytes {
		// Counter wrap-around, reset baseline
		em.lastTxBytes = currentTxBytes
		return
	}
	transmittedBytes := currentTxBytes - em.lastTxBytes
	transmittedMB := transmittedBytes / (1024 * 1024)

	em.LogEvent(zerolog.InfoLevel, "Data transmitted since last check.").Uint64("transmitted_mb", transmittedMB)

	if transmittedMB > uint64(em.config.UploadThresholdMB) {
		em.LogEvent(zerolog.WarnLevel, "Large data upload detected: possible data exfiltration.").
			Uint64("transmitted_mb", transmittedMB).
			Int("threshold_mb", em.config.UploadThresholdMB)
	}

	em.lastTxBytes = currentTxBytes // Update for next iteration
}

// monitorFileSharingConnections monitors for connections to known file sharing services.
func (em *ExfiltrationMonitor) monitorFileSharingConnections() {
	em.LogEvent(zerolog.InfoLevel, "Checking active connections for file sharing services...")

	connections, err := psnet.Connections("inet")
	if err != nil {
		em.LogEvent(zerolog.ErrorLevel, "Failed to get network connections.").Err(err)
		return
	}

	// Pre-resolve all domains for efficiency
	resolvedDomains := make(map[string][]net.IP)
	for _, domain := range em.config.FileSharingDomains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			em.LogEvent(zerolog.WarnLevel, "Failed to resolve file sharing domain.").Err(err).Str("domain", domain)
			continue
		}
		resolvedDomains[domain] = ips
	}

	for _, conn := range connections {
		remoteIP := net.ParseIP(conn.Raddr.IP)
		if remoteIP == nil {
			continue
		}

		localAddr := fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port)
		remoteAddr := fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port)

		for domain, ips := range resolvedDomains {
			for _, ip := range ips {
				if remoteIP.Equal(ip) {
					em.LogEvent(zerolog.WarnLevel, "Connection to file sharing service detected.").
						Str("domain", domain).
						Str("resolved_ip", ip.String()).
						Str("local_addr", localAddr).
						Str("remote_addr", remoteAddr)
				}
			}
		}
	}
}
