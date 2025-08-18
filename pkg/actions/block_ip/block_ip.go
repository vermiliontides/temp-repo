package block_ip

import (
	"context"
	"fmt"
	"net"
	"os/exec"

	"github.com/rs/zerolog/log"
)

// Implements Action interface

// BlockIPAction implements the actions.Action interface. It is responsible for
// blocking a given IP address using the system's firewall (iptables).
type BlockIPAction struct{}

// Name returns the unique name of the action.
func (bia *BlockIPAction) Name() string {
	return "block_ip"
}

// Execute runs the logic to block an IP address. It expects the data map to
// contain an "ip" key with the IP address string to be blocked. It uses `sudo iptables`
// to add a DROP rule to the INPUT chain.
func (bia *BlockIPAction) Execute(ctx context.Context, data map[string]interface{}) error {
	ip, ok := data["ip"].(string)
	if !ok || ip == "" {
		return fmt.Errorf("missing or invalid 'ip' in action data for block_ip action")
	}

	// Validate IP address format
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}

	log.Info().Str("ip", ip).Msg("Attempting to block IP using iptables...")

	// Command to add a rule to block the IP in the INPUT chain
	cmd := exec.CommandContext(ctx, "sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to block IP %s: %w\nOutput: %s", ip, err, string(out))
	}

	log.Info().Str("ip", ip).Msg("Successfully blocked IP using iptables.")
	return nil
}
