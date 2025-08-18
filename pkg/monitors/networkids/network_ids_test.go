package networkids

import (
	"context"
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

func TestNetworkIDS_Run(t *testing.T) {
	// Setup log capture
	lc := &LogCapture{}
	log.Logger = zerolog.New(lc).With().Timestamp().Logger()
	defer lc.ClearLogs()

	// Create monitor instance
	monitor := NewNetworkIDS(log.Logger)
	nids, ok := monitor.(*NetworkIDS)
	assert.True(t, ok)

	// Set config for testing
	nids.config = &Config{
		Interface: "lo", // Use loopback interface for testing
		Rules: []string{
			"icmp", // Rule to detect ICMP (ping) traffic
		},
	}

	// --- Test Case 1: Rule Match ---
	t.Run("RuleMatch", func(t *testing.T) {
		lc.ClearLogs()

		// In a real test, we would generate some ICMP traffic on the loopback interface.
		// For this example, we will just check that the monitor runs without errors.
		// A more advanced test would involve a library like gopacket to create and send packets.

		// Run the monitor
		nids.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		// We don't assert a rule match here because we are not generating traffic.
		// We just want to ensure the monitor runs without panicking.
		assert.Contains(t, logs, "Running Network IDS...")
		assert.Contains(t, logs, "Network IDS finished.")
	})
}

func TestNewNetworkIDS(t *testing.T) {
	logger := zerolog.Nop()
	monitor := NewNetworkIDS(logger)

	assert.NotNil(t, monitor)
	assert.Equal(t, "network_ids", monitor.Name())

	nids, ok := monitor.(*NetworkIDS)
	assert.True(t, ok)
	assert.NotNil(t, nids.BaseMonitor)
	assert.NotNil(t, nids.config)
}
