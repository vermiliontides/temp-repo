package scheduler

import (
	"context"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/config"
	"github.com/rs/zerolog/log"
)

// ConfigurableMonitor extends the Monitor interface to support configuration
type ConfigurableMonitor interface {
	Monitor
	Configure(config map[string]interface{}) error
}

// Monitor defines the interface for any monitor that can be scheduled.
type Monitor interface {
	Name() string
	Run(ctx context.Context)
}

// Scheduler manages the registration and execution of various monitors.
type Scheduler struct {
	monitors []Monitor
	config   *config.Config
}

// NewScheduler creates and returns a new Scheduler instance.
func NewScheduler(cfg *config.Config) *Scheduler {
	return &Scheduler{
		config: cfg,
	}
}

// RegisterMonitor adds a monitor to the scheduler's list.
func (s *Scheduler) RegisterMonitor(m Monitor) {
	// Check if monitor supports configuration
	if configurable, ok := m.(ConfigurableMonitor); ok {
		monitorConfig := s.config.GetMonitorConfig(m.Name())
		if monitorConfig != nil && monitorConfig.Config != nil {
			if err := configurable.Configure(monitorConfig.Config); err != nil {
				log.Error().Err(err).Msgf("Failed to configure monitor '%s'", m.Name())
				return
			}
			log.Info().Msgf("Monitor '%s' configured successfully.", m.Name())
		}
	}

	s.monitors = append(s.monitors, m)
	log.Info().Msgf("Monitor '%s' registered.", m.Name())
}

// Start launches all enabled monitors with their configured intervals.
func (s *Scheduler) Start(ctx context.Context) {
	log.Info().Msg("Scheduler starting...")

	for _, mon := range s.monitors {
		monitorConfig := s.getMonitorConfig(mon.Name())
		if monitorConfig == nil || !monitorConfig.Enabled {
			log.Info().Msgf("Monitor '%s' is disabled or not configured, skipping.", mon.Name())
			continue
		}

		duration, err := time.ParseDuration(monitorConfig.Interval)
		if err != nil {
			log.Error().Err(err).Msgf("Invalid interval for monitor '%s', skipping.", mon.Name())
			continue
		}

		log.Info().Msgf("Starting monitor '%s' with interval %s", mon.Name(), duration)
		go s.runMonitor(ctx, mon, duration)
	}

	log.Info().Msg("All configured monitors started.")
}

func (s *Scheduler) runMonitor(ctx context.Context, m Monitor, interval time.Duration) {
	// Run immediately on start
	log.Debug().Msgf("Running monitor '%s' for the first time.", m.Name())
	m.Run(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Debug().Msgf("Running monitor '%s'.", m.Name())
			m.Run(ctx)
		case <-ctx.Done():
			log.Info().Msgf("Monitor '%s' received shutdown signal.", m.Name())
			return
		}
	}
}

func (s *Scheduler) getMonitorConfig(name string) *config.MonitorConfig {
	return s.config.GetMonitorConfig(name)
}
