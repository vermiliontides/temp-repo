package thermal

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kali-security-monitoring/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/cpu"
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
	hostSensorsTemperatures = host.SensorsTemperatures
	cpuPercent              = cpu.Percent
)

func TestThermalMonitor_Run(t *testing.T) {
	// Setup log capture
	lc := &LogCapture{}
	log.Logger = zerolog.New(lc).With().Timestamp().Logger()
	defer lc.ClearLogs()

	// Create monitor instance
	monitor := NewThermalMonitor(log.Logger)
	tm, ok := monitor.(*ThermalMonitor)
	assert.True(t, ok)

	// Set config for testing
	tm.config = &Config{
		TempThreshold: 75.0,
		CPUThreshold:  20.0,
	}

	// --- Test Case 1: High Temperature, Low CPU (Anomaly) ---
	t.Run("AnomalyDetection", func(t *testing.T) {
		lc.ClearLogs()

		// Mock gopsutil functions to return anomaly data
		hostSensorsTemperatures = func() ([]host.TemperatureStat, error) {
			return []host.TemperatureStat{
				{SensorKey: "coretemp_core0", Temperature: 80.0},
			}, nil
		}
		cpuPercent = func(interval time.Duration, percpu bool) ([]float64, error) {
			return []float64{10.0}, nil
		}

		// Run the monitor
		tm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "THERMAL ANOMALY")
		assert.Contains(t, logs, "High temperature with low CPU usage")
	})

	// --- Test Case 2: High Temperature, High CPU (Normal High Temp) ---
	t.Run("HighTempNormal", func(t *testing.T) {
		lc.ClearLogs()

		// Mock gopsutil functions
		hostSensorsTemperatures = func() ([]host.TemperatureStat, error) {
			return []host.TemperatureStat{
				{SensorKey: "coretemp_core0", Temperature: 85.0},
			}, nil
		}
		cpuPercent = func(interval time.Duration, percpu bool) ([]float64, error) {
			return []float64{90.0}, nil
		}

		// Run the monitor
		tm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.NotContains(t, logs, "THERMAL ANOMALY")
		assert.Contains(t, logs, "High temperature detected")
	})

	// --- Test Case 3: Normal Temperature ---
	t.Run("NormalTemp", func(t *testing.T) {
		lc.ClearLogs()

		// Mock gopsutil functions
		hostSensorsTemperatures = func() ([]host.TemperatureStat, error) {
			return []host.TemperatureStat{
				{SensorKey: "coretemp_core0", Temperature: 50.0},
			}, nil
		}
		cpuPercent = func(interval time.Duration, percpu bool) ([]float64, error) {
			return []float64{15.0}, nil
		}

		// Run the monitor
		tm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.NotContains(t, logs, "THERMAL ANOMALY")
		assert.NotContains(t, logs, "High temperature detected")
	})

	// --- Test Case 4: Error getting temperature ---
	t.Run("TempError", func(t *testing.T) {
		lc.ClearLogs()

		// Mock gopsutil functions
		hostSensorsTemperatures = func() ([]host.TemperatureStat, error) {
			return nil, assert.AnError
		}
		cpuPercent = func(interval time.Duration, percpu bool) ([]float64, error) {
			return []float64{15.0}, nil
		}

		// Run the monitor
		tm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "Failed to get sensor temperatures")
	})

	// Restore original functions
	hostSensorsTemperatures = host.SensorsTemperatures
	cpuPercent = cpu.Percent
}

func TestNewThermalMonitor(t *testing.T) {
	logger := zerolog.Nop()
	monitor := NewThermalMonitor(logger)

	assert.NotNil(t, monitor)
	assert.Equal(t, "thermal_monitor", monitor.Name())

	tm, ok := monitor.(*ThermalMonitor)
	assert.True(t, ok)
	assert.NotNil(t, tm.BaseMonitor)
	assert.NotNil(t, tm.config)
}