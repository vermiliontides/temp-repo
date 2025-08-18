package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config is the top-level configuration struct for the application.
// It holds settings for logging, the API, and all monitor and action configurations.
// Tags are used by Viper to map YAML keys to struct fields.
type Config struct {
	LogLevel string          `mapstructure:"log_level"`
	APIPort  string          `mapstructure:"api_port"`
	Monitors []MonitorConfig `mapstructure:"monitors"`
	Actions  ActionsConfig   `mapstructure:"actions"`
}

// MonitorConfig defines the configuration for a single monitor.
// It includes the monitor's name, whether it's enabled, its run interval,
// and any actions it should trigger.
type MonitorConfig struct {
	Name     string   `mapstructure:"name"`
	Enabled  bool     `mapstructure:"enabled"`
	Interval string   `mapstructure:"interval"`
	Actions  []string `mapstructure:"actions"` // Actions to trigger for this monitor
}

// ActionsConfig holds the global configuration for all defensive actions.
type ActionsConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// LoadConfig reads the configuration from a YAML file (e.g., config.yaml) and
// environment variables. It uses Viper for robust configuration management,
// allowing for defaults and environment variable overrides.
func LoadConfig() (*Config, error) {
	v := viper.New()
	v.SetConfigName("config") // config.yaml
	v.SetConfigType("yaml")
	v.AddConfigPath(".") // Search in current directory
	v.AddConfigPath("/etc/sentinel/") // Search in /etc/sentinel/

	// Set default values
	v.SetDefault("log_level", "info")
	v.SetDefault("api_port", "8080") // Default API port
	v.SetDefault("actions.enabled", false) // Actions disabled by default

	// Read environment variables
	v.SetEnvPrefix("SENTINEL") // Look for SENTINEL_ prefix
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // Replace dots with underscores for nested keys
	v.AutomaticEnv() // Automatically bind environment variables to config keys

	// Read configuration file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			fmt.Println("Config file not found, using defaults and environment variables.")
		} else {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}
