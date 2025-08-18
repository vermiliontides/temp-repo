package persistence

import (
	"context"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kali-security-monitoring/sentinel/pkg/monitors/base"
	"github.com/kali-security-monitoring/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
)

// PersistenceMonitorConfig holds configuration for the PersistenceMonitor.
type PersistenceMonitorConfig struct {
	RunInterval       int  `mapstructure:"run_interval"`
	ScanCron          bool `mapstructure:"scan_cron"`
	ScanSystemd       bool `mapstructure:"scan_systemd"`
	ScanShellProfiles bool `mapstructure:"scan_shell_profiles"`
	ScanLdPreload     bool `mapstructure:"scan_ld_preload"`
}

// PersistenceMonitor implements the scheduler.Monitor interface for persistence mechanism scanning.
type PersistenceMonitor struct {
	*base.BaseMonitor
	config *PersistenceMonitorConfig
}

// NewPersistenceMonitor creates a new PersistenceMonitor.
func NewPersistenceMonitor(logger zerolog.Logger) scheduler.Monitor {
	return &PersistenceMonitor{
		BaseMonitor: base.NewBaseMonitor("persistence_monitor", logger),
		config:      &PersistenceMonitorConfig{},
	}
}

// Run executes the persistence monitoring logic.
func (pm *PersistenceMonitor) Run(ctx context.Context) {
	pm.LogEvent(zerolog.InfoLevel, "Running Persistence Monitor...")

	if pm.config.ScanCron {
		pm.scanCron()
	}
	if pm.config.ScanSystemd {
		pm.scanSystemd()
	}
	if pm.config.ScanShellProfiles {
		pm.scanShellProfiles()
	}
	if pm.config.ScanLdPreload {
		pm.scanLdPreload()
	}

	pm.LogEvent(zerolog.InfoLevel, "Persistence Monitor finished.")
}

// scanCron scans for cron-based persistence.
func (pm *PersistenceMonitor) scanCron() {
	pm.LogEvent(zerolog.InfoLevel, "Scanning for cron-based persistence...")

	// System-wide crontab
	pm.checkFileContent("/etc/crontab", "System crontab entry")

	// Cron directories
	cronDirs := []string{
		"/etc/cron.d",
		"/etc/cron.hourly",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
	}
	for _, dir := range cronDirs {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			pm.LogEvent(zerolog.DebugLevel, "Could not read cron directory.").Err(err).Str("dir", dir)
			continue
		}
		for _, file := range files {
			if !file.IsDir() {
				pm.checkFileContent(filepath.Join(dir, file.Name()), "Cron file entry")
			}
		}
	}

	// User crontabs (simplified - requires parsing /etc/passwd and running crontab -l as user)
	// This is complex to do purely in Go without elevated privileges or a more sophisticated approach.
	// For now, we'll log a warning if we can't check user crontabs.
	pm.LogEvent(zerolog.WarnLevel, "Automated scanning of user crontabs is not fully implemented in Go due to privilege requirements.")
}

// checkFileContent reads a file and logs its non-comment, non-empty lines.
func (pm *PersistenceMonitor) checkFileContent(filePath, logPrefix string) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		pm.LogEvent(zerolog.DebugLevel, "Could not read file.").Err(err).Str("file", filePath)
		return
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") {
			pm.LogEvent(zerolog.InfoLevel, logPrefix+": "+trimmedLine).Str("file", filePath)
		}
	}
}

// scanSystemd scans for systemd-based persistence.
func (pm *PersistenceMonitor) scanSystemd() {
	pm.LogEvent(zerolog.InfoLevel, "Scanning for systemd-based persistence...")

	// User-level services and timers
	userSystemdDirs := []string{
		filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user"),
		// Add other potential user systemd directories if needed
	}
	for _, dir := range userSystemdDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Continue on errors
			}
			if !info.IsDir() && (strings.HasSuffix(info.Name(), ".service") || strings.HasSuffix(info.Name(), ".timer")) {
				pm.LogEvent(zerolog.WarnLevel, "User systemd file found.").Str("file", path)
				// Optionally, read and log content
			}
			return nil
		})
	}

	// System-wide services and timers
	systemSystemdDir := "/etc/systemd/system"
	filepath.Walk(systemSystemdDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue on errors
		}
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".service") || strings.HasSuffix(info.Name(), ".timer")) {
			// Check if the file is not owned by any package (potential manual addition)
			// This requires querying the package manager (e.g., dpkg -S), which is OS-specific
			// and might require elevated privileges. Simplified for now.
			cmd := exec.Command("dpkg", "-S", path)
			_, err := cmd.Output()
			if err != nil { // dpkg -S returns non-zero if file is not owned by a package
				pm.LogEvent(zerolog.WarnLevel, "Systemd file not owned by any package.").Str("file", path)
				// Optionally, read and log content
			}
		}
		return nil
	})
}

// scanShellProfiles scans shell profiles for suspicious commands.
func (pm *PersistenceMonitor) scanShellProfiles() {
	pm.LogEvent(zerolog.InfoLevel, "Scanning shell profiles for persistence...")

	shellProfiles := []string{
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/zsh/zshrc",
	}

	// Add user-specific profiles (simplified - ideally iterate /etc/passwd)
	// For now, we'll just check common user home directories.
	userHomeDir, err := os.UserHomeDir()
	if err == nil {
		shellProfiles = append(shellProfiles, filepath.Join(userHomeDir, ".bashrc"))
		shellProfiles = append(shellProfiles, filepath.Join(userHomeDir, ".zshrc"))
		shellProfiles = append(shellProfiles, filepath.Join(userHomeDir, ".profile"))
	}

	suspiciousPatterns := []string{
		"nc", "netcat", "ncat", "socat", "python -c", "perl -e", "bash -c",
		"wget", "curl", "base64", "eval", "exec",
	}

	for _, profile := range shellProfiles {
		content, err := ioutil.ReadFile(profile)
		if err != nil {
			pm.LogEvent(zerolog.DebugLevel, "Could not read shell profile.").Err(err).Str("file", profile)
			continue
		}

		for _, pattern := range suspiciousPatterns {
			if matched, _ := regexp.MatchString(pattern, string(content)); matched {
				pm.LogEvent(zerolog.WarnLevel, "Suspicious entry in shell profile.").Str("file", profile).Str("pattern", pattern)
				break
			}
		}
	}
}

// scanLdPreload scans for LD_PRELOAD persistence.
func (pm *PersistenceMonitor) scanLdPreload() {
	pm.LogEvent(zerolog.InfoLevel, "Scanning for LD_PRELOAD persistence...")

	ldPreloadPath := "/etc/ld.so.preload"
	content, err := ioutil.ReadFile(ldPreloadPath)
	if err != nil {
		if os.IsNotExist(err) {
			pm.LogEvent(zerolog.InfoLevel, "LD_PRELOAD file does not exist.").Str("file", ldPreloadPath)
		} else {
			pm.LogEvent(zerolog.ErrorLevel, "Failed to read LD_PRELOAD file.").Err(err).Str("file", ldPreloadPath)
		}
		return
	}

	trippedContent := strings.TrimSpace(string(content))
	if trippedContent != "" {
		pm.LogEvent(zerolog.WarnLevel, "LD_PRELOAD is configured.").Str("file", ldPreloadPath).Str("content", trippedContent)
	}
}