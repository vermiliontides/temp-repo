package persistence

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

// LogCapture is a helper to capture zerolog output for testing.
type LogCapture struct {
	sync.Mutex
	logs []string
}

func (lc *LogCapture) Write(p []byte) (n int, err error) {
	lc.Lock()
	defer lc.Unlock()
	lc.logs = append(lc.logs, string(p))
	return len(p), nil
}

func (lc *LogCapture) GetLogs() []string {
	lc.Lock()
	defer lc.Unlock()
	return lc.logs
}

func (lc *LogCapture) ClearLogs() {
	lc.Lock()
	defer lc.Unlock()
	lc.logs = nil
}

// Mocking exec.Command for testing external tool calls
var execCommand = exec.Command

func TestPersistenceMonitor_Run(t *testing.T) {
	// Setup log capture
	lc := &LogCapture{}
	log.Logger = zerolog.New(lc).With().Timestamp().Logger()
	defer lc.ClearLogs()

	// Create monitor instance
	monitor := NewPersistenceMonitor(log.Logger)
	pm, ok := monitor.(*PersistenceMonitor)
	assert.True(t, ok)

	// Set config for testing
	pm.config = &PersistenceMonitorConfig{
		RunInterval:       1, // Short interval for testing
		ScanCron:          true,
		ScanSystemd:       true,
		ScanShellProfiles: true,
		ScanLdPreload:     true,
	}

	// --- Test Case 1: All scans enabled ---
	t.Run("AllScansEnabled", func(t *testing.T) {
		lc.ClearLogs()

		// Mock exec.Command for dpkg -S
		oldExecCommand := execCommand
		execCommand = func(name string, arg ...string) *exec.Cmd {
			if name == "dpkg" && arg[0] == "-S" {
				return exec.Command("false") // Simulate file not owned by package
			}
			return oldExecCommand(name, arg...)
		}
		defer func() { execCommand = oldExecCommand }()

		// Create dummy files for testing
		os.MkdirAll("/etc/cron.d", 0755)
		os.WriteFile("/etc/cron.d/test_cron", []byte("*/1 * * * * root echo hello"), 0644)
		os.MkdirAll("/etc/systemd/system", 0755)
		os.WriteFile("/etc/systemd/system/test.service", []byte("[Unit]\nDescription=Test"), 0644)
		os.WriteFile("/etc/profile", []byte("export PATH=/usr/local/bin:$PATH\nexec nc -l"), 0644)
		os.WriteFile("/etc/ld.so.preload", []byte("/tmp/malicious.so"), 0644)

		// Run the monitor
		pm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "Scanning for cron-based persistence...")
		assert.Contains(t, logs, "Scanning for systemd-based persistence...")
		assert.Contains(t, logs, "Scanning shell profiles for persistence...")
		assert.Contains(t, logs, "Scanning for LD_PRELOAD persistence...")
		assert.Contains(t, logs, "System crontab entry")
		assert.Contains(t, logs, "Systemd file not owned by any package")
		assert.Contains(t, logs, "Suspicious entry in shell profile.")
		assert.Contains(t, logs, "LD_PRELOAD is configured.")

		// Clean up dummy files
		os.Remove("/etc/cron.d/test_cron")
		os.Remove("/etc/systemd/system/test.service")
		os.Remove("/etc/profile")
		os.Remove("/etc/ld.so.preload")
	})

	// --- Test Case 2: No scans enabled ---
	t.Run("NoScansEnabled", func(t *testing.T) {
		lc.ClearLogs()
		pm.config.ScanCron = false
		pm.config.ScanSystemd = false
		pm.config.ScanShellProfiles = false
		pm.config.ScanLdPreload = false

		// Run the monitor
		pm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.NotContains(t, logs, "Scanning for cron-based persistence...")
		assert.NotContains(t, logs, "Scanning for systemd-based persistence...")
		assert.NotContains(t, logs, "Scanning shell profiles for persistence...")
		assert.NotContains(t, logs, "Scanning for LD_PRELOAD persistence...")
	})
}

func TestNewPersistenceMonitor(t *testing.T) {
	logger := zerolog.Nop()
	monitor := NewPersistenceMonitor(logger)

	assert.NotNil(t, monitor)
	assert.Equal(t, "persistence_monitor", monitor.Name())

	pm, ok := monitor.(*PersistenceMonitor)
	assert.True(t, ok)
	assert.NotNil(t, pm.BaseMonitor)
	assert.NotNil(t, pm.config)
}
