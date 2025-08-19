package thermal

import (
	"context"
	"strconv"

	"github.com/lucid-vigil/sentinel/pkg/monitors/base"
	"github.com/lucid-vigil/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
)

// ThermalMonitor implements the scheduler.Monitor interface for thermal monitoring.
type ThermalMonitor struct {
	*base.BaseMonitor
	config *Config
}

// Config holds the configuration for the ThermalMonitor.
type Config struct {
	TempThreshold float64 `mapstructure:"temp_threshold"`
	CPUThreshold  float64 `mapstructure:"cpu_threshold"`
}

// NewThermalMonitor creates a new ThermalMonitor.
func NewThermalMonitor(logger zerolog.Logger) scheduler.Monitor {
	return &ThermalMonitor{
		BaseMonitor: base.NewBaseMonitor("thermal_monitor", logger),
		config:      &Config{},
	}
}

// Run executes the thermal monitoring logic.
func (tm *ThermalMonitor) Run(ctx context.Context) {
	tm.LogEvent(zerolog.InfoLevel, "Running Thermal Monitor...")

	temps, err := host.SensorsTemperatures()
	if err != nil {
		tm.LogEvent(zerolog.ErrorLevel, "Failed to get sensor temperatures.")
		return
	}

	cpuPercentages, err := cpu.Percent(0, false)
	if err != nil || len(cpuPercentages) == 0 {
		tm.LogEvent(zerolog.ErrorLevel, "Failed to get CPU usage.")
		return
	}
	avgCPUUsage := cpuPercentages[0]

	for _, temp := range temps {
		tm.LogEvent(zerolog.DebugLevel, "Current sensor temperature: "+temp.SensorKey+" "+strconv.FormatFloat(temp.Temperature, 'f', 2, 64))
		// Check for high temperature with low CPU usage anomaly
		if temp.Temperature > tm.config.TempThreshold && avgCPUUsage < tm.config.CPUThreshold {
			tm.LogEvent(zerolog.WarnLevel, "THERMAL ANOMALY: High temperature with low CPU usage - possible hidden process")
		}

		// Check for sustained high temperature
		if temp.Temperature > tm.config.TempThreshold {
			tm.LogEvent(zerolog.InfoLevel, "High temperature detected")
		}
	}

	tm.LogEvent(zerolog.InfoLevel, "Thermal Monitor finished.")
}
