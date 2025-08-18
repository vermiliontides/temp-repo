package firmware

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/kali-security-monitoring/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/host"
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

// Mocking the gopsutil functions
var (
	hostInfo = host.Info
)

func TestFirmwareMonitor_Run(t *testing.T) {
	// Setup log capture
	lc := &LogCapture{}
	log.Logger = zerolog.New(lc).With().Timestamp().Logger()
	defer lc.ClearLogs()

	// Create monitor instance
	monitor := NewFirmwareMonitor(log.Logger)
	fm, ok := monitor.(*FirmwareMonitor)
	assert.True(t, ok)

	// --- Test Case 1: Successful BIOS Info Retrieval ---
	t.Run("SuccessfulRetrieval", func(t *testing.T) {
		lc.ClearLogs()

		// Mock gopsutil functions to return sample BIOS data
		hostInfo = func() (*host.InfoStat, error) {
			return &host.InfoStat{
				BIOSVendor:  "Test BIOS Vendor",
				BIOSVersion: "1.2.3",
				BIOSDate:    "2025-01-01",
			}, nil
		}

		// Run the monitor
		fm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "BIOS Vendor: Test BIOS Vendor")
		assert.Contains(t, logs, "BIOS Version: 1.2.3")
		assert.Contains(t, logs, "BIOS Date: 2025-01-01")
	})

	// --- Test Case 2: Error getting BIOS info ---
	t.Run("InfoError", func(t *testing.T) {
		lc.ClearLogs()

		// Mock gopsutil functions to return an error
		hostInfo = func() (*host.InfoStat, error) {
			return nil, assert.AnError
		}

		// Run the monitor
		fm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "Failed to get BIOS information.")
	})

	// Restore original functions
	hostInfo = host.Info
}

func TestNewFirmwareMonitor(t *testing.T) {
	logger := zerolog.Nop()
	monitor := NewFirmwareMonitor(logger)

	assert.NotNil(t, monitor)
	assert.Equal(t, "firmware_monitor", monitor.Name())

	fm, ok := monitor.(*FirmwareMonitor)
	assert.True(t, ok)
	assert.NotNil(t, fm.BaseMonitor)
	assert.NotNil(t, fm.config)
}