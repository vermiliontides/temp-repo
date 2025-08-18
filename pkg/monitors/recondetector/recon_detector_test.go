package recondetector

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/net"
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
	netConnections = net.Connections
)

func TestReconDetector_Run(t *testing.T) {
	// Setup log capture
	lc := &LogCapture{}
	log.Logger = zerolog.New(lc).With().Timestamp().Logger()
	defer lc.ClearLogs()

	// Create monitor instance
	monitor := NewReconDetector(log.Logger)
	rd, ok := monitor.(*ReconDetector)
	assert.True(t, ok)

	// Set config for testing
	rd.config = &Config{
		SynFloodThreshold: 100,
		PortScanThreshold: 50,
	}

	// --- Test Case 1: Port Scan Detection ---
	t.Run("PortScanDetection", func(t *testing.T) {
		lc.ClearLogs()

		// Mock gopsutil functions to return port scan data
		netConnections = func(kind string) ([]net.ConnectionStat, error) {
			var connections []net.ConnectionStat
			for i := 0; i < 60; i++ {
				connections = append(connections, net.ConnectionStat{
					Status: "SYN_RECV",
					Raddr:  net.Addr{IP: "192.168.1.100"},
				})
			}
			return connections, nil
		}

		// Run the monitor
		rd.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "Potential port scan detected")
	})

	// --- Test Case 2: SYN Flood Detection ---
	t.Run("SynFloodDetection", func(t *testing.T) {
		lc.ClearLogs()

		// Mock gopsutil functions to return SYN flood data
		netConnections = func(kind string) ([]net.ConnectionStat, error) {
			var connections []net.ConnectionStat
			for i := 0; i < 120; i++ {
				connections = append(connections, net.ConnectionStat{
					Status: "SYN_RECV",
				})
			}
			return connections, nil
		}

		// Run the monitor
		rd.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "Potential SYN flood attack detected")
	})

	// Restore original functions
	netConnections = net.Connections
}

func TestNewReconDetector(t *testing.T) {
	logger := zerolog.Nop()
	monitor := NewReconDetector(logger)

	assert.NotNil(t, monitor)
	assert.Equal(t, "recon_detector", monitor.Name())

	rd, ok := monitor.(*ReconDetector)
	assert.True(t, ok)
	assert.NotNil(t, rd.BaseMonitor)
	assert.NotNil(t, rd.config)
}
