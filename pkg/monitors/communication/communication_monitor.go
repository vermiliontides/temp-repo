package communication

import (
	"context"
	"fmt"
	"net"

	"github.com/lucid-vigil/sentinel/pkg/monitors/base"
	"github.com/lucid-vigil/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
	psnet "github.com/shirou/gopsutil/v3/net"
)

// CommunicationMonitorConfig holds configuration for the CommunicationMonitor.
type CommunicationMonitorConfig struct {
	IPBlocklist     []string `mapstructure:"ip_blocklist"`
	DomainBlocklist []string `mapstructure:"domain_blocklist"`
	RunInterval     int      `mapstructure:"run_interval"`
}

// CommunicationMonitor implements the scheduler.Monitor interface for communication monitoring.
type CommunicationMonitor struct {
	*base.BaseMonitor
	config *CommunicationMonitorConfig
}

// NewCommunicationMonitor creates a new CommunicationMonitor.
func NewCommunicationMonitor(logger zerolog.Logger) scheduler.Monitor {
	return &CommunicationMonitor{
		BaseMonitor: base.NewBaseMonitor("communication_monitor", logger),
		config:      &CommunicationMonitorConfig{},
	}
}

// Run executes the communication monitoring logic.
func (cm *CommunicationMonitor) Run(ctx context.Context) {
	cm.LogEvent(zerolog.InfoLevel, "Running Communication Monitor...")

	cm.checkCommunications()

	cm.LogEvent(zerolog.InfoLevel, "Communication Monitor finished.")
}

// checkCommunications checks active network connections against blocklists.
func (cm *CommunicationMonitor) checkCommunications() {
	cm.LogEvent(zerolog.InfoLevel, "Checking active network connections against blocklists...")

	connections, err := psnet.Connections("inet")
	if err != nil {
		cm.LogEvent(zerolog.ErrorLevel, "Failed to get network connections.").Err(err)
		return
	}

	// Pre-resolve all domains in the blocklist for efficiency
	resolvedBlocklist := make(map[string][]net.IP)
	for _, domain := range cm.config.DomainBlocklist {
		ips, err := net.LookupIP(domain)
		if err != nil {
			cm.LogEvent(zerolog.WarnLevel, "Failed to resolve blocked domain.").Err(err).Str("domain", domain)
			continue
		}
		resolvedBlocklist[domain] = ips
	}

	for _, conn := range connections {
		remoteIP := net.ParseIP(conn.Raddr.IP)
		if remoteIP == nil {
			continue
		}

		localAddr := fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port)
		remoteAddr := fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port)

		// Check against IP blocklist
		for _, blockedIP := range cm.config.IPBlocklist {
			if conn.Raddr.IP == blockedIP {
				cm.LogEvent(zerolog.WarnLevel, "Connection to malicious IP detected.").
					Str("type", "IP_BLOCKLIST").
					Str("blocked_ip", blockedIP).
					Str("local_addr", localAddr).
					Str("remote_addr", remoteAddr)
			}
		}

		// Check against resolved domain blocklist
		for domain, ips := range resolvedBlocklist {
			for _, ip := range ips {
				if remoteIP.Equal(ip) {
					cm.LogEvent(zerolog.WarnLevel, "Connection to malicious domain detected.").
						Str("type", "DOMAIN_BLOCKLIST").
						Str("blocked_domain", domain).
						Str("resolved_ip", ip.String()).
						Str("local_addr", localAddr).
						Str("remote_addr", remoteAddr)
				}
			}
		}
	}
}
