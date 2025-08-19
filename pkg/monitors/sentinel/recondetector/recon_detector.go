package recondetector

import (
	"context"

	"github.com/lucid-vigil/sentinel/pkg/monitors/base"
	"github.com/lucid-vigil/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
	"github.com/shirou/gopsutil/v3/net"
)

// ReconDetector implements the scheduler.Monitor interface for reconnaissance detection.
type ReconDetector struct {
	*base.BaseMonitor
	config *Config
}

// Config holds the configuration for the ReconDetector.
type Config struct {
	SynFloodThreshold int `mapstructure:"syn_flood_threshold"`
	PortScanThreshold int `mapstructure:"port_scan_threshold"`
}

// NewReconDetector creates a new ReconDetector monitor.
func NewReconDetector(logger zerolog.Logger) scheduler.Monitor {
	return &ReconDetector{
		BaseMonitor: base.NewBaseMonitor("recon_detector", logger),
		config:      &Config{},
	}
}

// Run executes the reconnaissance detection logic.
func (rd *ReconDetector) Run(ctx context.Context) {
	rd.LogEvent(zerolog.InfoLevel, "Running Reconnaissance Detector...")

	rd.detectPortScans()
	rd.detectSynFloods()

	rd.LogEvent(zerolog.InfoLevel, "Reconnaissance Detector finished.")
}

// detectPortScans detects port scans by analyzing SYN-RECV connections.
func (rd *ReconDetector) detectPortScans() {
	connections, err := net.Connections("tcp")
	if err != nil {
		rd.LogEvent(zerolog.ErrorLevel, "Failed to get TCP connections: "+err.Error())
		return
	}

	synRecvCounts := make(map[string]int)
	for _, conn := range connections {
		if conn.Status == "SYN_RECV" {
			synRecvCounts[conn.Raddr.IP]++
		}
	}

	for ip, count := range synRecvCounts {
		if count > rd.config.PortScanThreshold {
			rd.LogEvent(zerolog.WarnLevel, "Potential port scan detected from "+ip+" ("+string(count)+" SYN-RECV connections).")
		}
	}
}

// detectSynFloods detects SYN floods by checking overall SYN-RECV connections.
func (rd *ReconDetector) detectSynFloods() {
	connections, err := net.Connections("tcp")
	if err != nil {
		rd.LogEvent(zerolog.ErrorLevel, "Failed to get TCP connections: "+err.Error())
		return
	}

	synRecvCount := 0
	for _, conn := range connections {
		if conn.Status == "SYN_RECV" {
			synRecvCount++
		}
	}

	if synRecvCount > rd.config.SynFloodThreshold {
		rd.LogEvent(zerolog.WarnLevel, "Potential SYN flood attack detected ("+string(synRecvCount)+" SYN-RECV connections).")
	}
}
