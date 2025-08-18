package networkids

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/kali-security-monitoring/sentinel/pkg/monitors/base"
	"github.com/kali-security-monitoring/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
)

// NetworkIDS implements the scheduler.Monitor interface for network intrusion detection.
type NetworkIDS struct {
	*base.BaseMonitor
	config *Config
}

// Config holds the configuration for the NetworkIDS.
type Config struct {
	Interface string   `mapstructure:"interface"`
	Rules     []string `mapstructure:"rules"`
}

// NewNetworkIDS creates a new NetworkIDS monitor.
func NewNetworkIDS(logger zerolog.Logger) scheduler.Monitor {
	return &NetworkIDS{
		BaseMonitor: base.NewBaseMonitor("network_ids", logger),
		config:      &Config{},
	}
}

// Run executes the network intrusion detection logic.
func (nids *NetworkIDS) Run(ctx context.Context) {
	nids.LogEvent(zerolog.InfoLevel, "Running Network IDS...")

	// Validate interface name
	if !isValidInterfaceName(nids.config.Interface) {
		nids.LogEvent(zerolog.ErrorLevel, fmt.Sprintf("Invalid network interface name: %s", nids.config.Interface))
		return
	}

	for _, rule := range nids.config.Rules {
		// Sanitize tcpdump rule to prevent command injection
		sanitizedRule := sanitizeTcpdumpRule(rule)
		if sanitizedRule == "" {
			nids.LogEvent(zerolog.WarnLevel, fmt.Sprintf("Skipping empty or invalid rule: %s", rule))
			continue
		}

		nids.LogEvent(zerolog.DebugLevel, "Applying rule: "+sanitizedRule)
		cmd := exec.CommandContext(ctx, "tcpdump", "-i", nids.config.Interface, "-c", "1", sanitizedRule)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// tcpdump exits with status 1 if no packets are captured, so we don't log that as an error.
			if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
				continue
			}
			nids.LogEvent(zerolog.ErrorLevel, "Failed to run tcpdump: "+err.Error())
			continue
		}

		if len(output) > 0 {
			nids.LogEvent(zerolog.WarnLevel, "Network IDS rule matched: "+sanitizedRule)
			nids.LogEvent(zerolog.WarnLevel, "Captured packet: "+string(output))
		}
	}

	nids.LogEvent(zerolog.InfoLevel, "Network IDS finished.")
}

// isValidInterfaceName checks if the given string is a valid network interface name.
// This is a basic validation and might need to be more comprehensive depending on OS.
func isValidInterfaceName(name string) bool {
	// Interface names typically consist of alphanumeric characters, hyphens, and underscores.
	// They should not contain spaces or shell metacharacters.
	return regexp.MustCompile(`^[a-zA-Z0-9_-]+).MatchString(name)
}

// sanitizeTcpdumpRule performs basic sanitization on a tcpdump rule string.
// This is not a full parser but aims to remove common dangerous characters.
func sanitizeTcpdumpRule(rule string) string {
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
