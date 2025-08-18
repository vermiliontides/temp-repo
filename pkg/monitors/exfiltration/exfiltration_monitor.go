package exfiltration

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/net"
)

// ExfiltrationMonitorConfig holds configuration for the ExfiltrationMonitor.
type ExfiltrationMonitorConfig struct {
	UploadThresholdMB   int      `mapstructure:"upload_threshold_mb"`
	FileSharingDomains []string `mapstructure:"file_sharing_domains"`
	RunInterval         int      `mapstructure:"run_interval"`
}

// ExfiltrationMonitor implements the scheduler.Monitor interface for exfiltration monitoring.
type ExfiltrationMonitor struct {
	Config ExfiltrationMonitorConfig
	lastTxBytes uint64
}

// Name returns the name of the monitor.
func (em *ExfiltrationMonitor) Name() string {
	return "exfiltration_monitor"
}

// Run executes the exfiltration monitoring logic.
func (em *ExfiltrationMonitor) Run(ctx context.Context) {
	log.Info().Msg("Running Exfiltration Monitor...")

	// Initialize lastTxBytes on first run
	if em.lastTxBytes == 0 {
		netIOCounters, err := net.IOCounters(nil)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get initial network IO counters for exfiltration monitoring.")
			return
		}
		for _, counter := range netIOCounters {
			em.lastTxBytes += counter.BytesSent
		}
	}

	em.monitorLargeUploads()
	em.monitorFileSharingConnections()

	log.Info().Msg("Exfiltration Monitor finished.")
}

// monitorLargeUploads monitors for large data uploads.
func (em *ExfiltrationMonitor) monitorLargeUploads() {
	log.Info().Msg("Monitoring for large data uploads...")

	netIOCounters, err := net.IOCounters(nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get network IO counters for large upload monitoring.")
		return
	}

	var currentTxBytes uint64
	for _, counter := range netIOCounters {
		currentTxBytes += counter.BytesSent
	}

	// Calculate transmitted data since last check
	transmittedBytes := currentTxBytes - em.lastTxBytes
	transmittedMB := transmittedBytes / (1024 * 1024)

	log.Info().Uint64("transmitted_mb", transmittedMB).Msg("Data transmitted since last check.")

	if transmittedMB > uint64(em.Config.UploadThresholdMB) {
		log.Warn().
			Uint64("transmitted_mb", transmittedMB).
			Int("threshold_mb", em.Config.UploadThresholdMB).
			Msg("Large data upload detected: possible data exfiltration.")
	}

	em.lastTxBytes = currentTxBytes // Update for next iteration
}

// monitorFileSharingConnections monitors for connections to known file sharing services.
func (em *ExfiltrationMonitor) monitorFileSharingConnections() {
	log.Info().Msg("Checking active connections for file sharing services...")

	connections, err := net.Connections("inet")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get network connections for file sharing monitoring.")
		return
	}

	for _, domain := range em.Config.FileSharingDomains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			log.Warn().Err(err).Str("domain", domain).Msg("Failed to resolve file sharing domain.")
			continue
		}
		for _, ip := range ips {
			for _, conn := range connections {
				if conn.Raddr.IP == ip.String() {
					log.Warn().
						Str("domain", domain).
						Str("resolved_ip", ip.String()).
						Str("local_addr", conn.Laddr.String()).
						Str("remote_addr", conn.Raddr.String()).
						Msg("Connection to file sharing service detected.")
				}
			}
		}
	}
}
