package network

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/net"
)

// NetworkMonitorConfig holds configuration for the NetworkMonitor.
type NetworkMonitorConfig struct {
	MaxConnections    int    `mapstructure:"max_connections"`
	SuspiciousPorts   string `mapstructure:"suspicious_ports"`
	MonitorInterval   int    `mapstructure:"monitor_interval"`
	CaptureSuspicious bool   `mapstructure:"capture_suspicious"`
	DNSWhitelist      string `mapstructure:"dns_whitelist"`
}

// NetworkMonitor implements the scheduler.Monitor interface for network activity monitoring.
type NetworkMonitor struct {
	Config NetworkMonitorConfig
}

// Name returns the name of the monitor.
func (nm *NetworkMonitor) Name() string {
	return "network_monitor"
}

// Run executes the network monitoring logic.
func (nm *NetworkMonitor) Run(ctx context.Context) {
	log.Info().Msg("Running Network Monitor...")

	nm.monitorConnections()
	nm.monitorDNS()
	nm.monitorBandwidth()
	// nm.detectPortScans()
	// nm.captureSuspiciousTraffic()

	log.Info().Msg("Network Monitor finished.")
}

// monitorConnections monitors active network connections.
func (nm *NetworkMonitor) monitorConnections() {
	connections, err := net.Connections("inet")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get network connections.")
		return
	}

	externalConnections := 0
	for _, conn := range connections {
		if conn.Status == "ESTABLISHED" && conn.Laddr.IP != "127.0.0.1" && conn.Laddr.IP != "::1" {
			externalConnections++
		}
	}

	listeningPorts, err := net.Connections("inet4") // Only IPv4 for listening ports for simplicity
	if err != nil {
		log.Error().Err(err).Msg("Failed to get listening ports.")
		return
	}

	numListeningPorts := 0
	for _, conn := range listeningPorts {
		if conn.Status == "LISTEN" {
			numListeningPorts++
		}
	}

	log.Info().
		Int("external_connections", externalConnections).
		Int("listening_ports", numListeningPorts).
		Int("total_connections", len(connections)).
		Msg("Network connections summary.")

	// Check for excessive connections
	if externalConnections > nm.Config.MaxConnections {
		log.Warn().
			Int("external_connections", externalConnections).
			Int("threshold", nm.Config.MaxConnections).
			Msg("Excessive external connections detected.")
	}

	// Check for suspicious ports
	suspiciousPorts := strings.Split(nm.Config.SuspiciousPorts, ",")
	for _, conn := range listeningPorts {
		if conn.Status == "LISTEN" {
			for _, sPort := range suspiciousPorts {
				port, err := strconv.Atoi(sPort)
				if err != nil {
					log.Error().Err(err).Str("port_string", sPort).Msg("Invalid suspicious port in config.")
					continue
				}
				if conn.Laddr.Port == uint32(port) {
					log.Warn().
						Uint32("port", conn.Laddr.Port).
						Str("process_pid", strconv.Itoa(int(conn.Pid))).
						Msg("Suspicious port open.")
				}
			}
		}
	}
}

// monitorDNS monitors DNS queries for suspicious patterns.
func (nm *NetworkMonitor) monitorDNS() {
	// This is a simplified implementation. A more robust solution would involve
	// integrating with a DNS logging system or using a more advanced packet capture library.
	cmd := exec.Command("tcpdump", "-i", "any", "port", "53", "-l", "-n", "-c", "100") // Capture 100 packets
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Error().Err(err).Msg("Failed to create stdout pipe for tcpdump.")
		return
	}
	if err := cmd.Start(); err != nil {
		log.Error().Err(err).Msg("Failed to start tcpdump.")
		return
	}

	scanner := bufio.NewScanner(stdout)
	domains := make(map[string]struct{})
	for scanner.Scan() {
		line := scanner.Text()
		// Basic regex to extract domain names from DNS queries
		re := regexp.MustCompile(`[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
		matches := re.FindAllString(line, -1)
		for _, match := range matches {
			domains[match] = struct{}{}
		}
	}
	cmd.Wait()

	log.Info().Int("unique_domains", len(domains)).Msg("DNS queries monitored.")

	// Check for suspicious domain patterns (e.g., DGA-like, free domains)
	suspiciousDomainPatterns := []string{
		`\.tkpackage network

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/net"
)

// NetworkMonitorConfig holds configuration for the NetworkMonitor.
type NetworkMonitorConfig struct {
	MaxConnections    int    `mapstructure:"max_connections"`
	SuspiciousPorts   string `mapstructure:"suspicious_ports"`
	MonitorInterval   int    `mapstructure:"monitor_interval"`
	CaptureSuspicious bool   `mapstructure:"capture_suspicious"`
	DNSWhitelist      string `mapstructure:"dns_whitelist"`
}

// NetworkMonitor implements the scheduler.Monitor interface for network activity monitoring.
type NetworkMonitor struct {
	Config NetworkMonitorConfig
}

// Name returns the name of the monitor.
func (nm *NetworkMonitor) Name() string {
	return "network_monitor"
}

// Run executes the network monitoring logic.
func (nm *NetworkMonitor) Run(ctx context.Context) {
	log.Info().Msg("Running Network Monitor...")

	, `\.mlpackage network

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/net"
)

// NetworkMonitorConfig holds configuration for the NetworkMonitor.
type NetworkMonitorConfig struct {
	MaxConnections    int    `mapstructure:"max_connections"`
	SuspiciousPorts   string `mapstructure:"suspicious_ports"`
	MonitorInterval   int    `mapstructure:"monitor_interval"`
	CaptureSuspicious bool   `mapstructure:"capture_suspicious"`
	DNSWhitelist      string `mapstructure:"dns_whitelist"`
}

// NetworkMonitor implements the scheduler.Monitor interface for network activity monitoring.
type NetworkMonitor struct {
	Config NetworkMonitorConfig
}

// Name returns the name of the monitor.
func (nm *NetworkMonitor) Name() string {
	return "network_monitor"
}

// Run executes the network monitoring logic.
func (nm *NetworkMonitor) Run(ctx context.Context) {
	log.Info().Msg("Running Network Monitor...")

	, `\.gapackage network

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/net"
)

// NetworkMonitorConfig holds configuration for the NetworkMonitor.
type NetworkMonitorConfig struct {
	MaxConnections    int    `mapstructure:"max_connections"`
	SuspiciousPorts   string `mapstructure:"suspicious_ports"`
	MonitorInterval   int    `mapstructure:"monitor_interval"`
	CaptureSuspicious bool   `mapstructure:"capture_suspicious"`
	DNSWhitelist      string `mapstructure:"dns_whitelist"`
}

// NetworkMonitor implements the scheduler.Monitor interface for network activity monitoring.
type NetworkMonitor struct {
	Config NetworkMonitorConfig
}

// Name returns the name of the monitor.
func (nm *NetworkMonitor) Name() string {
	return "network_monitor"
}

// Run executes the network monitoring logic.
func (nm *NetworkMonitor) Run(ctx context.Context) {
	log.Info().Msg("Running Network Monitor...")

	, `\.cfpackage network

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/net"
)

// NetworkMonitorConfig holds configuration for the NetworkMonitor.
type NetworkMonitorConfig struct {
	MaxConnections    int    `mapstructure:"max_connections"`
	SuspiciousPorts   string `mapstructure:"suspicious_ports"`
	MonitorInterval   int    `mapstructure:"monitor_interval"`
	CaptureSuspicious bool   `mapstructure:"capture_suspicious"`
	DNSWhitelist      string `mapstructure:"dns_whitelist"`
}

// NetworkMonitor implements the scheduler.Monitor interface for network activity monitoring.
type NetworkMonitor struct {
	Config NetworkMonitorConfig
}

// Name returns the name of the monitor.
func (nm *NetworkMonitor) Name() string {
	return "network_monitor"
}

// Run executes the network monitoring logic.
func (nm *NetworkMonitor) Run(ctx context.Context) {
	log.Info().Msg("Running Network Monitor...")

	, // Free domains
		`[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}`, // IP-like domains
		`[a-z]{10,}\.compackage network

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/net"
)

// NetworkMonitorConfig holds configuration for the NetworkMonitor.
type NetworkMonitorConfig struct {
	MaxConnections    int    `mapstructure:"max_connections"`
	SuspiciousPorts   string `mapstructure:"suspicious_ports"`
	MonitorInterval   int    `mapstructure:"monitor_interval"`
	CaptureSuspicious bool   `mapstructure:"capture_suspicious"`
	DNSWhitelist      string `mapstructure:"dns_whitelist"`
}

// NetworkMonitor implements the scheduler.Monitor interface for network activity monitoring.
type NetworkMonitor struct {
	Config NetworkMonitorConfig
}

// Name returns the name of the monitor.
func (nm *NetworkMonitor) Name() string {
	return "network_monitor"
}

// Run executes the network monitoring logic.
func (nm *NetworkMonitor) Run(ctx context.Context) {
	log.Info().Msg("Running Network Monitor...")

	, // DGA-like (simplified)
	}

	whitelist := make(map[string]struct{})
	for _, d := range strings.Split(nm.Config.DNSWhitelist, ",") {
		whitelist[strings.TrimSpace(d)] = struct{}{}
	}

	for domain := range domains {
		isSuspicious := false
		for _, pattern := range suspiciousDomainPatterns {
			if matched, _ := regexp.MatchString(pattern, domain); matched {
				isSuspicious = true
				break
			}
		}

		if isSuspicious {
			if _, ok := whitelist[domain]; !ok {
				log.Warn().Str("domain", domain).Msg("Suspicious domain detected.")
			}
		}
	}
}

// monitorBandwidth monitors bandwidth usage for anomalies.
func (nm *NetworkMonitor) monitorBandwidth() {
	// Get initial byte counts
	initialNetIOCounters, err := net.IOCounters(nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get initial network IO counters.")
		return
	}

	var initialRxBytes, initialTxBytes uint64
	for _, counter := range initialNetIOCounters {
		initialRxBytes += counter.BytesRecv
		initialTxBytes += counter.BytesSent
	}

	time.Sleep(5 * time.Second) // Wait for 5 seconds to calculate rate

	// Get final byte counts
	finalNetIOCounters, err := net.IOCounters(nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get final network IO counters.")
		return
	}

	var finalRxBytes, finalTxBytes uint64
	for _, counter := range finalNetIOCounters {
		finalRxBytes += counter.BytesRecv
		finalTxBytes += counter.BytesSent
	}

	// Calculate rates in bytes/sec
	rxRate := float64(finalRxBytes-initialRxBytes) / 5.0
	txRate := float64(finalTxBytes-initialTxBytes) / 5.0

	log.Info().
		Float64("rx_bytes_per_sec", rxRate).
		Float64("tx_bytes_per_sec", txRate).
		Msg("Bandwidth usage monitored.")

	// Alert on high upload rates (potential data exfiltration) - 1MB/sec threshold
	if txRate > 1048576 {
		log.Warn().Float64("tx_bytes_per_sec", txRate).Msg("High upload rate detected: possible data exfiltration.")
	}
}
