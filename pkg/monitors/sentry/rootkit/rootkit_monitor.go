package rootkit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lucid-vigil/sentinel/pkg/monitors/base"
	"github.com/lucid-vigil/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
)

// RootkitMonitorConfig holds configuration for the RootkitMonitor.
type RootkitMonitorConfig struct {
	RunInterval         int  `mapstructure:"run_interval"`
	ChkrootkitEnabled   bool `mapstructure:"chkrootkit_enabled"`
	RkhunterEnabled     bool `mapstructure:"rkhunter_enabled"`
	ManualChecksEnabled bool `mapstructure:"manual_checks_enabled"`
}

// RootkitMonitor implements the scheduler.Monitor interface for rootkit detection.
type RootkitMonitor struct {
	*base.BaseMonitor
	config *RootkitMonitorConfig
}

// NewRootkitMonitor creates a new RootkitMonitor.
func NewRootkitMonitor(logger zerolog.Logger) scheduler.Monitor {
	return &RootkitMonitor{
		BaseMonitor: base.NewBaseMonitor("rootkit_monitor", logger),
		config:      &RootkitMonitorConfig{},
	}
}

// Run executes the rootkit monitoring logic.
func (rm *RootkitMonitor) Run(ctx context.Context) {
	rm.LogEvent(zerolog.InfoLevel, "Running Rootkit Monitor...")

	if rm.config.ManualChecksEnabled {
		rm.runManualChecks()
	}

	// Placeholder for external tool integrations
	if rm.config.ChkrootkitEnabled {
		rm.runChkrootkit()
	}
	if rm.config.RkhunterEnabled {
		rm.runRkhunter()
	}

	rm.LogEvent(zerolog.InfoLevel, "Rootkit Monitor finished.")
}

// runChkrootkit is a placeholder for chkrootkit integration.
func (rm *RootkitMonitor) runChkrootkit() {
	rm.LogEvent(zerolog.InfoLevel, "Running chkrootkit scan (placeholder - requires external binary).")
	// In a real implementation, you would execute the chkrootkit binary
	// and parse its output.
	// Example: cmd := exec.Command("sudo", "chkrootkit", "-q")
}

// runRkhunter is a placeholder for rkhunter integration.
func (rm *RootkitMonitor) runRkhunter() {
	rm.LogEvent(zerolog.InfoLevel, "Running rkhunter scan (placeholder - requires external binary).")
	// In a real implementation, you would execute the rkhunter binary
	// and parse its output.
	// Example: cmd := exec.Command("sudo", "rkhunter", "--check")
}

// runManualChecks performs manual rootkit artifact checks.
func (rm *RootkitMonitor) runManualChecks() {
	rm.LogEvent(zerolog.InfoLevel, "Starting manual rootkit artifact checks...")

	// Check for suspicious files in /dev (non-device files)
	rm.checkDevForSuspiciousFiles()

	// Check for promiscuous mode on network interfaces
	rm.checkPromiscuousMode()

	// Check for immutable files in critical directories
	rm.checkImmutableFiles()

	rm.LogEvent(zerolog.InfoLevel, "Manual checks completed.")
}

// checkDevForSuspiciousFiles checks /dev for non-device files.
func (rm *RootkitMonitor) checkDevForSuspiciousFiles() {
	files, err := os.ReadDir("/dev")
	if err != nil {
		rm.LogEvent(zerolog.ErrorLevel, "Failed to read /dev directory.").Err(err)
		return
	}

	for _, file := range files {
		filePath := filepath.Join("/dev", file.Name())
		info, err := os.Stat(filePath)
		if err != nil {
			continue // Skip files that can't be stat'd
		}

		// In /dev, we expect device files, directories, and symlinks.
		// A regular file is highly suspicious.
		mode := info.Mode()
		if mode&os.ModeDevice == 0 && mode&os.ModeDir == 0 && mode&os.ModeSymlink == 0 {
			rm.LogEvent(zerolog.WarnLevel, "Suspicious non-device, non-directory file found in /dev.").
				Str("file", filePath).
				Str("mode", mode.String())
		}
	}
}

// checkPromiscuousMode checks for network interfaces in promiscuous mode.
func (rm *RootkitMonitor) checkPromiscuousMode() {
	cmd := exec.Command("ip", "link")
	out, err := cmd.Output()
	if err != nil {
		rm.LogEvent(zerolog.ErrorLevel, "Failed to run 'ip link'.").Err(err)
		return
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "PROMISC") {
			rm.LogEvent(zerolog.WarnLevel, "Network interface in promiscuous mode.").Str("interface_info", line)
		}
	}
}

// checkImmutableFiles checks for immutable files in critical directories.
func (rm *RootkitMonitor) checkImmutableFiles() {
	criticalDirs := []string{"/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"}

	for _, dir := range criticalDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Continue on errors
			}
			if !info.IsDir() {
				// Check for immutable attribute using lsattr
				cmd := exec.Command("lsattr", path)
				attrOutput, err := cmd.Output()
				if err == nil && strings.Contains(string(attrOutput), "----i---") {
					rm.LogEvent(zerolog.WarnLevel, "Immutable file detected.").Str("file", path)
				}
			}
			return nil
		})
	}
}
