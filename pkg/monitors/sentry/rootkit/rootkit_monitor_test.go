package rootkit

import (
	"context"
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

func TestRootkitMonitor_Run(t *testing.T) {
	// Setup log capture
	lc := &LogCapture{}
	log.Logger = zerolog.New(lc).With().Timestamp().Logger()
	defer lc.ClearLogs()

	// Create monitor instance
	monitor := NewRootkitMonitor(log.Logger)
	rm, ok := monitor.(*RootkitMonitor)
	assert.True(t, ok)

	// Set config for testing
	rm.config = &RootkitMonitorConfig{
		RunInterval:         1, // Short interval for testing
		ChkrootkitEnabled:   true,
		RkhunterEnabled:     true,
		ManualChecksEnabled: true,
	}

	// --- Test Case 1: All checks enabled ---
	t.Run("AllChecksEnabled", func(t *testing.T) {
		lc.ClearLogs()

		// Mock exec.Command to simulate successful external tool runs
		oldExecCommand := execCommand
		execCommand = func(name string, arg ...string) *exec.Cmd {
			if name == "chkrootkit" || name == "rkhunter" {
				return exec.Command("echo", "simulated output")
			} else if name == "ip" && arg[0] == "link" {
				return exec.Command("echo", "eth0: <BROADCAST,MULTICAST,UP,LOWER_UP,PROMISC> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000")
			} else if name == "lsattr" {
				return exec.Command("echo", "----i---- /tmp/immutable_file")
			}
			return oldExecCommand(name, arg...)
		}
		defer func() { execCommand = oldExecCommand }()

		// Run the monitor
		rm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "Running Rootkit Monitor...")
		assert.Contains(t, logs, "Starting manual rootkit artifact checks...")
		assert.Contains(t, logs, "Running chkrootkit scan (placeholder")
		assert.Contains(t, logs, "Running rkhunter scan (placeholder")
		assert.Contains(t, logs, "Network interface in promiscuous mode.")
		assert.Contains(t, logs, "Immutable file detected.")
		assert.Contains(t, logs, "Rootkit Monitor finished.")
	})

	// --- Test Case 2: No checks enabled ---
	t.Run("NoChecksEnabled", func(t *testing.T) {
		lc.ClearLogs()
		rm.config.ChkrootkitEnabled = false
		rm.config.RkhunterEnabled = false
		rm.config.ManualChecksEnabled = false

		// Run the monitor
		rm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.NotContains(t, logs, "Starting manual rootkit artifact checks...")
		assert.NotContains(t, logs, "Running chkrootkit scan")
		assert.NotContains(t, logs, "Running rkhunter scan")
	})

	// --- Test Case 3: Error in external command ---
	t.Run("ExternalCommandError", func(t *testing.T) {
		lc.ClearLogs()
		rm.config.ManualChecksEnabled = true

		// Mock exec.Command to simulate an error
		oldExecCommand := execCommand
		execCommand = func(name string, arg ...string) *exec.Cmd {
			if name == "ip" && arg[0] == "link" {
				return exec.Command("false") // Command that always fails
			}
			return oldExecCommand(name, arg...)
		}
		defer func() { execCommand = oldExecCommand }()

		// Run the monitor
		rm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "Failed to run 'ip link'.")
	})
}

func TestNewRootkitMonitor(t *testing.T) {
	logger := zerolog.Nop()
	monitor := NewRootkitMonitor(logger)

	assert.NotNil(t, monitor)
	assert.Equal(t, "rootkit_monitor", monitor.Name())

	rm, ok := monitor.(*RootkitMonitor)
	assert.True(t, ok)
	assert.NotNil(t, rm.BaseMonitor)
	assert.NotNil(t, rm.config)
}
