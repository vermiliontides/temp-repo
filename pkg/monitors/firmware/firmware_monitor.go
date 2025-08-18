package firmware

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucid-vigil/sentinel/pkg/monitors/base"
	"github.com/lucid-vigil/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
)

// FirmwareMonitor implements the scheduler.Monitor interface for firmware scanning.
type FirmwareMonitor struct {
	*base.BaseMonitor
	config *Config
}

// Config holds the configuration for the FirmwareMonitor.
type Config struct {
	// Add any firmware-specific configuration here
}

// NewFirmwareMonitor creates a new FirmwareMonitor.
func NewFirmwareMonitor(logger zerolog.Logger) scheduler.Monitor {
	return &FirmwareMonitor{
		BaseMonitor: base.NewBaseMonitor("firmware_monitor", logger),
		config:      &Config{},
	}
}

// Run executes the firmware scanning logic.
func (fm *FirmwareMonitor) Run(ctx context.Context) {
	fm.LogEvent(zerolog.InfoLevel, "Running Firmware Monitor...")

	vendor := fm.readDMIFile("bios_vendor")
	version := fm.readDMIFile("bios_version")
	date := fm.readDMIFile("bios_date")

	if vendor != "unknown" || version != "unknown" || date != "unknown" {
		fm.LogEvent(zerolog.InfoLevel, "BIOS information").
			Str("vendor", vendor).
			Str("version", version).
			Str("date", date)
	} else {
		fm.LogEvent(zerolog.WarnLevel, "Could not retrieve complete BIOS information from DMI.")
	}

	// In a real implementation, you would compare this information against a database of known vulnerable firmware.

	fm.LogEvent(zerolog.InfoLevel, "Firmware Monitor finished.")
}

// readDMIFile reads a specific file from the /sys/class/dmi/id/ directory.
func (fm *FirmwareMonitor) readDMIFile(fileName string) string {
	path := filepath.Join("/sys/class/dmi/id/", fileName)
	content, err := os.ReadFile(path)
	if err != nil {
		fm.LogEvent(zerolog.ErrorLevel, "Failed to read DMI file.").Err(err).Str("file", path)
		return "unknown"
	}
	return strings.TrimSpace(string(content))
}
