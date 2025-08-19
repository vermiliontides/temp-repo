package network

import (
	"context"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/lucid-vigil/sentinel/pkg/monitors/base"
	"github.com/lucid-vigil/sentinel/pkg/scheduler"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	psnet "github.com/shirou/gopsutil/v3/net"
)

// DNSEvent holds information about a captured DNS query or response.
type DNSEvent struct {
	SourceIP net.IP
	Domain   string
	IsQuery  bool
	IsNX     bool
}

// ClientStats holds DNS query statistics for a single IP address.
type ClientStats struct {
	TotalQueries  int
	NXDomainCount int
	LastSeen      time.Time
}

// DNSSuspicionScore holds the individual heuristic scores for a domain.
type DNSSuspicionScore struct {
	Entropy      float64
	Length       float64
	VowelRatio   float64
	DigitRatio   float64
	SpecialChars float64
	Total        float64
}

// NetworkMonitorConfig holds configuration for the NetworkMonitor.
type NetworkMonitorConfig struct {
	MaxConnections         int      `mapstructure:"max_connections"`
	SuspiciousPorts        []int    `mapstructure:"suspicious_ports"`
	DNSWhitelist           []string `mapstructure:"dns_whitelist"`
	BandwidthThresholdMBps float64  `mapstructure:"bandwidth_threshold_mbps"`
	NetworkInterface       string   `mapstructure:"network_interface"`

	// --- Suspicion Scoring Weights ---
	EntropyWeight      float64 `mapstructure:"entropy_weight"`
	LengthWeight       float64 `mapstructure:"length_weight"`
	VowelRatioWeight   float64 `mapstructure:"vowel_ratio_weight"`
	DigitRatioWeight   float64 `mapstructure:"digit_ratio_weight"`
	SpecialCharsWeight float64 `mapstructure:"special_chars_weight"`
	SuspicionThreshold float64 `mapstructure:"suspicion_threshold"`

	// --- Stateful Analysis ---
	EnableStatefulAnalysis bool          `mapstructure:"enable_stateful_analysis"`
	NXDomainThresholdRatio float64       `mapstructure:"nxdomain_threshold_ratio"`
	MinQueryCountForAlert  int           `mapstructure:"min_query_count_for_alert"`
	StatsCleanupInterval   time.Duration `mapstructure:"stats_cleanup_interval"`
}

// NetworkMonitor implements the scheduler.Monitor interface for network activity monitoring.
type NetworkMonitor struct {
	*base.BaseMonitor
	config        *NetworkMonitorConfig
	lastRxBytes   uint64
	lastTxBytes   uint64
	lastCheckTime time.Time
	dnsEvents     chan DNSEvent
	stopChan      chan struct{}
	clientStats   map[string]*ClientStats
	statsMutex    sync.RWMutex
}

// NewNetworkMonitor creates a new NetworkMonitor and starts its background processes.
func NewNetworkMonitor(logger zerolog.Logger) scheduler.Monitor {
	nm := &NetworkMonitor{
		BaseMonitor: base.NewBaseMonitor("network_monitor", logger),
		config:      &NetworkMonitorConfig{},
		dnsEvents:   make(chan DNSEvent, 256),
		stopChan:    make(chan struct{}),
		clientStats: make(map[string]*ClientStats),
	}
	go nm.startDNSPacketCapture()
	go nm.startStatefulAnalysis()
	return nm
}

// Run executes the network monitoring logic.
func (nm *NetworkMonitor) Run(ctx context.Context) {
	nm.LogEvent(zerolog.InfoLevel, "Running Network Monitor...")
	nm.monitorConnections(ctx)
	nm.monitorDNS(ctx)
	nm.monitorBandwidth(ctx)
	nm.LogEvent(zerolog.InfoLevel, "Network Monitor finished.")
}

// startDNSPacketCapture starts capturing DNS packets and sending them to the dnsEvents channel.
func (nm *NetworkMonitor) startDNSPacketCapture() {
	iface := "any"
	if nm.config.NetworkInterface != "" {
		iface = nm.config.NetworkInterface
	}

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		nm.LogEvent(zerolog.ErrorLevel, "Failed to open pcap handle.").Err(err).Str("interface", iface)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp and port 53"); err != nil {
		nm.LogEvent(zerolog.ErrorLevel, "Failed to set BPF filter.").Err(err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	nm.LogEvent(zerolog.InfoLevel, "Starting DNS packet capture.").Str("interface", iface)

	for {
		select {
		case packet := <-packetSource.Packets():
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			ip, _ := ipLayer.(*layers.IPv4)

			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				continue
			}
			udp, _ := udpLayer.(*layers.UDP)

			var dnsMsg dns.Msg
			if err := dnsMsg.Unpack(udp.Payload); err != nil {
				continue // Not a valid DNS message
			}

			if len(dnsMsg.Question) == 0 {
				continue
			}

			event := DNSEvent{
				Domain:  strings.TrimSuffix(dnsMsg.Question[0].Name, "."),
				IsQuery: !dnsMsg.Response,
				IsNX:    dnsMsg.Rcode == dns.RcodeNameError,
			}

			if event.IsQuery {
				event.SourceIP = ip.SrcIP
			} else {
				event.SourceIP = ip.DstIP // For responses, the querier is the destination
			}
			nm.dnsEvents <- event
		case <-nm.stopChan:
			nm.LogEvent(zerolog.InfoLevel, "Stopping DNS packet capture.")
			return
		}
	}
}

// startStatefulAnalysis runs a periodic check on client DNS stats for anomalies.
func (nm *NetworkMonitor) startStatefulAnalysis() {
	if !nm.config.EnableStatefulAnalysis {
		return
	}

	cleanupInterval := nm.config.StatsCleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = 1 * time.Hour
	}
	ticker := time.NewTicker(cleanupInterval / 2) // Analyze more frequently than we clean
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			nm.analyzeAndCleanClientStats()
		case <-nm.stopChan:
			return
		}
	}
}

// analyzeAndCleanClientStats checks for high NXDOMAIN ratios and removes old stats.
func (nm *NetworkMonitor) analyzeAndCleanClientStats() {
	nm.statsMutex.Lock()
	defer nm.statsMutex.Unlock()

	minQueries := nm.config.MinQueryCountForAlert
	if minQueries == 0 {
		minQueries = 20 // Default
	}
	nxRatio := nm.config.NXDomainThresholdRatio
	if nxRatio == 0 {
		nxRatio = 0.8 // Default
	}
	cleanupInterval := nm.config.StatsCleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = 1 * time.Hour
	}

	for ip, stats := range nm.clientStats {
		// Clean up old entries
		if time.Since(stats.LastSeen) > cleanupInterval {
			delete(nm.clientStats, ip)
			continue
		}

		// Analyze for high NXDOMAIN rate
		if stats.TotalQueries >= minQueries {
			ratio := float64(stats.NXDomainCount) / float64(stats.TotalQueries)
			if ratio >= nxRatio {
				nm.LogEvent(zerolog.WarnLevel, "High NXDOMAIN rate detected for client.").
					Str("client_ip", ip).
					Float64("nxdomain_ratio", ratio).
					Int("total_queries", stats.TotalQueries)
			}
		}
	}
}

// monitorDNS processes DNS events, updates stats, and scores queries for suspiciousness.
func (nm *NetworkMonitor) monitorDNS(ctx context.Context) {
	processedEvents := 0
	for len(nm.dnsEvents) > 0 {
		event := <-nm.dnsEvents
		processedEvents++

		// Update client stats for stateful analysis
		nm.updateClientStats(event)

		// Perform stateless analysis only on queries
		if !event.IsQuery {
			continue
		}

		whitelist := make(map[string]struct{})
		for _, d := range nm.config.DNSWhitelist {
			whitelist[strings.TrimSpace(d)] = struct{}{}
		}
		if _, isWhitelisted := whitelist[event.Domain]; isWhitelisted {
			continue
		}

		score := nm.calculateSuspicionScore(event.Domain)
		suspicionThreshold := nm.config.SuspicionThreshold
		if suspicionThreshold == 0 {
			suspicionThreshold = 100.0 // Default value
		}

		if score.Total > suspicionThreshold {
			nm.LogEvent(zerolog.WarnLevel, "Suspicious domain query detected.").
				Str("domain", event.Domain).
				Float64("total_score", score.Total).
				Str("source_ip", event.SourceIP.String()).
				Interface("score_breakdown", score)
		}
	}
	if processedEvents > 0 {
		nm.LogEvent(zerolog.InfoLevel, "Processed DNS events.").Int("count", processedEvents)
	}
}

// updateClientStats updates the statistics for a given client IP.
func (nm *NetworkMonitor) updateClientStats(event DNSEvent) {
	if !nm.config.EnableStatefulAnalysis {
		return
	}
	ipStr := event.SourceIP.String()

	nm.statsMutex.Lock()
	defer nm.statsMutex.Unlock()

	if _, ok := nm.clientStats[ipStr]; !ok {
		nm.clientStats[ipStr] = &ClientStats{}
	}

	stats := nm.clientStats[ipStr]
	stats.LastSeen = time.Now()
	if event.IsQuery {
		stats.TotalQueries++
	}
	if event.IsNX {
		stats.NXDomainCount++
	}
}

// monitorConnections monitors active network connections.
func (nm *NetworkMonitor) monitorConnections(ctx context.Context) {
	connections, err := psnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		nm.LogEvent(zerolog.ErrorLevel, "Failed to get network connections.").Err(err)
		return
	}

	externalConnections := 0
	for _, conn := range connections {
		if conn.Status == "ESTABLISHED" && conn.Raddr.IP != "" {
			ip := net.ParseIP(conn.Raddr.IP)
			if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
				externalConnections++
			}
		}
	}

	listeningPorts, err := psnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		nm.LogEvent(zerolog.ErrorLevel, "Failed to get listening ports.").Err(err)
		return
	}

	numListeningPorts := 0
	for _, conn := range listeningPorts {
		if conn.Status == "LISTEN" {
			numListeningPorts++
		}
	}

	nm.LogEvent(zerolog.InfoLevel, "Network connections summary.").
		Int("external_connections", externalConnections).
		Int("listening_ports", numListeningPorts).
		Int("total_connections", len(connections))

	if nm.config.MaxConnections > 0 && externalConnections > nm.config.MaxConnections {
		nm.LogEvent(zerolog.WarnLevel, "Excessive external connections detected.").
			Int("external_connections", externalConnections).
			Int("threshold", nm.config.MaxConnections)
	}

	for _, conn := range listeningPorts {
		if conn.Status == "LISTEN" {
			for _, sPort := range nm.config.SuspiciousPorts {
				if conn.Laddr.Port == uint32(sPort) {
					nm.LogEvent(zerolog.WarnLevel, "Suspicious port open.").
						Uint32("port", conn.Laddr.Port).
						Int32("pid", conn.Pid)
				}
			}
		}
	}
}

// monitorBandwidth monitors bandwidth usage for anomalies in a non-blocking way.
func (nm *NetworkMonitor) monitorBandwidth(ctx context.Context) {
	netIOCounters, err := psnet.IOCountersWithContext(ctx, false)
	if err != nil {
		nm.LogEvent(zerolog.ErrorLevel, "Failed to get network IO counters.").Err(err)
		return
	}
	if len(netIOCounters) == 0 {
		nm.LogEvent(zerolog.WarnLevel, "No network interfaces found for IO counters.")
		return
	}
	currentCounters := netIOCounters[0]

	now := time.Now()
	if !nm.lastCheckTime.IsZero() {
		duration := now.Sub(nm.lastCheckTime).Seconds()
		if duration > 0 {
			rxRate := float64(currentCounters.BytesRecv-nm.lastRxBytes) / duration
			txRate := float64(currentCounters.BytesSent-nm.lastTxBytes) / duration

			nm.LogEvent(zerolog.InfoLevel, "Bandwidth usage monitored.").
				Float64("rx_bytes_per_sec", rxRate).
				Float64("tx_bytes_per_sec", txRate)

			thresholdBytesPerSec := nm.config.BandwidthThresholdMBps * 1024 * 1024
			if nm.config.BandwidthThresholdMBps > 0 && txRate > thresholdBytesPerSec {
				nm.LogEvent(zerolog.WarnLevel, "High upload rate detected.").
					Float64("tx_bytes_per_sec", txRate).
					Float64("threshold_mbps", nm.config.BandwidthThresholdMBps)
			}
		}
	}

	nm.lastRxBytes = currentCounters.BytesRecv
	nm.lastTxBytes = currentCounters.BytesSent
	nm.lastCheckTime = now
}

// calculateSuspicionScore calculates a suspicion score for a domain based on multiple heuristics.
func (nm *NetworkMonitor) calculateSuspicionScore(domain string) DNSSuspicionScore {
	var score DNSSuspicionScore
	domainPart := getDomainPart(domain)

	// 1. Entropy Score
	score.Entropy = shannonEntropy(domainPart)

	// 2. Length Score
	if len(domainPart) > 20 { // Penalize long domains
		score.Length = float64(len(domainPart))
	}

	// 3. Vowel Ratio Score (very low or very high is suspicious)
	vowelRatio := calculateVowelRatio(domainPart)
	if vowelRatio < 0.1 || vowelRatio > 0.7 {
		score.VowelRatio = (1 - vowelRatio) * 20 // Arbitrary penalty
	}

	// 4. Digit Ratio Score
	digitRatio := calculateDigitRatio(domainPart)
	if digitRatio > 0.2 { // Penalize high digit ratio
		score.DigitRatio = digitRatio * 30
	}

	// 5. Special Character Score (hyphens)
	if strings.Contains(domainPart, "-") {
		score.SpecialChars = float64(strings.Count(domainPart, "-")) * 10
	}

	// Calculate weighted total score
	score.Total = (score.Entropy * nm.getWeight("entropy", 25.0)) +
		(score.Length * nm.getWeight("length", 1.5)) +
		(score.VowelRatio * nm.getWeight("vowel_ratio", 1.0)) +
		(score.DigitRatio * nm.getWeight("digit_ratio", 1.0)) +
		(score.SpecialChars * nm.getWeight("special_chars", 1.0))

	return score
}

// getWeight returns the configured weight for a heuristic, or a default value.
func (nm *NetworkMonitor) getWeight(heuristic string, defaultValue float64) float64 {
	switch heuristic {
	case "entropy":
		if nm.config.EntropyWeight != 0 {
			return nm.config.EntropyWeight
		}
	case "length":
		if nm.config.LengthWeight != 0 {
			return nm.config.LengthWeight
		}
	case "vowel_ratio":
		if nm.config.VowelRatioWeight != 0 {
			return nm.config.VowelRatioWeight
		}
	case "digit_ratio":
		if nm.config.DigitRatioWeight != 0 {
			return nm.config.DigitRatioWeight
		}
	case "special_chars":
		if nm.config.SpecialCharsWeight != 0 {
			return nm.config.SpecialCharsWeight
		}
	}
	return defaultValue
}

// --- Heuristic Helper Functions ---

func getDomainPart(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 1 {
		return parts[0]
	}
	return domain
}

func calculateVowelRatio(s string) float64 {
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

func calculateDigitRatio(s string) float64 {
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

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
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
