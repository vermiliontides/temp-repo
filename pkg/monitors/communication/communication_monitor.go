package communication

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/net"
)

// CommunicationMonitorConfig holds configuration for the CommunicationMonitor.
type CommunicationMonitorConfig struct {
	IPBlocklist    []string `mapstructure:"ip_blocklist"`
	DomainBlocklist []string `mapstructure:"domain_blocklist"`
	RunInterval    int      `mapstructure:"run_interval"`
}

// CommunicationMonitor implements the scheduler.Monitor interface for communication monitoring.
type CommunicationMonitor struct {
	Config CommunicationMonitorConfig
}

// Name returns the name of the monitor.
func (cm *CommunicationMonitor) Name() string {
	return "communication_monitor"
}

// Run executes the communication monitoring logic.
func (cm *CommunicationMonitor) Run(ctx context.Context) {
	log.Info().Msg("Running Communication Monitor...")

	cm.checkCommunications()

	log.Info().Msg("Communication Monitor finished.")
}

// checkCommunications checks active network connections against blocklists.
func (cm *CommunicationMonitor) checkCommunications() {
	log.Info().Msg("Checking active network connections against blocklists...")

	connections, err := net.Connections("inet")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get network connections.")
		return
	}

	// Check against IP blocklist
	for _, blockedIP := range cm.Config.IPBlocklist {
		for _, conn := range connections {
			if conn.Raddr.IP == blockedIP {
				log.Warn().
					Str("type", "IP_BLOCKLIST").
					Str("blocked_ip", blockedIP).
					Str("local_addr", conn.Laddr.String()).
					Str("remote_addr", conn.Raddr.String()).
					Msg("Connection to malicious IP detected.")
			}
		}
	}

	// Check against domain blocklist (requires DNS resolution)
	for _, blockedDomain := range cm.Config.DomainBlocklist {
		ips, err := net.LookupIP(blockedDomain)
		if err != nil {
			log.Warn().Err(err).Str("domain", blockedDomain).Msg("Failed to resolve blocked domain.")
			continue
		}
		for _, ip := range ips {
			for _, conn := range connections {
				if conn.Raddr.IP == ip.String() {
					log.Warn().
						Str("type", "DOMAIN_BLOCKLIST").
						Str("blocked_domain", blockedDomain).
						Str("resolved_ip", ip.String()).
						Str("local_addr", conn.Laddr.String()).
						Str("remote_addr", conn.Raddr.String()).
						Msg("Connection to malicious domain detected.")
				}
			}
		}
	}
}
