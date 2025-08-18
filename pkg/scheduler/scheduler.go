package scheduler

import (
	"context"
	"time"

	"github.com/kali-security-monitoring/sentinel/pkg/config"
	"github.com/rs/zerolog/log"
)

// Monitor defines the interface for any monitor that can be scheduled.
// Each monitor must provide a name for identification and a Run method for execution.
type Monitor interface {
	// Name returns the unique name of the monitor.
	Name() string
	// Run executes the monitor's logic. It is passed a context for cancellation.
	Run(ctx context.Context)
}

// Scheduler manages the registration and execution of various monitors based on the
// application configuration.
type Scheduler struct {
	monitors []Monitor
	config   *config.Config
}

// NewScheduler creates and returns a new Scheduler instance.
// It requires an application configuration to determine which monitors to run.
func NewScheduler(cfg *config.Config) *Scheduler {
	return &Scheduler{
		config: cfg,
	}
}

// RegisterMonitor adds a monitor to the scheduler's list of monitors to be run.
func (s *Scheduler) RegisterMonitor(m Monitor) {
	s.monitors = append(s.monitors, m)
	log.Info().Msgf("Monitor '%s' registered.", m.Name())
}

// Start iterates through the registered monitors, checks if they are enabled in the
// configuration, and if so, launches them in their own goroutine to run at the
// specified interval.
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
	for _, mc := range s.config.Monitors {
		if mc.Name == name {
			return &mc
		}
	}
	return nil
}
