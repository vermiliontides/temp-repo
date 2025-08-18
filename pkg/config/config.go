// Enhanced config.go to support monitor-specific configurations

package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config is the top-level configuration struct for the application.
type Config struct {
	LogLevel string          `mapstructure:"log_level"`
	APIPort  string          `mapstructure:"api_port"`
	Monitors []MonitorConfig `mapstructure:"monitors"`
	Actions  ActionsConfig   `mapstructure:"actions"`
}

// MonitorConfig defines the configuration for a single monitor.
type MonitorConfig struct {
	Name     string                 `mapstructure:"name"`
	Enabled  bool                   `mapstructure:"enabled"`
	Interval string                 `mapstructure:"interval"`
	Actions  []string               `mapstructure:"actions"`
	Config   map[string]interface{} `mapstructure:"config"` // Monitor-specific config
}

// ActionsConfig holds the global configuration for all defensive actions.
type ActionsConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// GetMonitorConfig returns the configuration for a specific monitor by name
func (c *Config) GetMonitorConfig(name string) *MonitorConfig {
	for i, monitor := range c.Monitors {
		if monitor.Name == name {
			return &c.Monitors[i]
		}
	}
	return nil
}

// LoadConfig reads the configuration from a YAML file and environment variables.
func LoadConfig() (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/sentinel/")

	// Set default values
	v.SetDefault("log_level", "info")
	v.SetDefault("api_port", "8080")
	v.SetDefault("actions.enabled", false)

	// Read environment variables
	v.SetEnvPrefix("SENTINEL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

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
