package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file for testing
	testConfigContent := `
log_level: debug
api_port: "9090"
monitors:
  - name: test_monitor_1
    enabled: true
    interval: 5s
  - name: test_monitor_2
    enabled: false
    interval: 1m
`

	err := os.WriteFile("config.yaml", []byte(testConfigContent), 0644)
	assert.NoError(t, err)
	defer os.Remove("config.yaml") // Clean up the test config file

	cfg, err := LoadConfig()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "9090", cfg.APIPort)
	assert.Len(t, cfg.Monitors, 2)

	assert.Equal(t, "test_monitor_1", cfg.Monitors[0].Name)
	assert.True(t, cfg.Monitors[0].Enabled)
	assert.Equal(t, "5s", cfg.Monitors[0].Interval)

	assert.Equal(t, "test_monitor_2", cfg.Monitors[1].Name)
	assert.False(t, cfg.Monitors[1].Enabled)
	assert.Equal(t, "1m", cfg.Monitors[1].Interval)

	// Test with environment variable override
	os.Setenv("SENTINEL_API_PORT", "9091")
	defer os.Unsetenv("SENTINEL_API_PORT")

	cfg, err = LoadConfig()
	assert.NoError(t, err)
	assert.Equal(t, "9091", cfg.APIPort)
}
