package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/actions"
	"github.com/lucid-vigil/sentinel/pkg/config"
	"github.com/lucid-vigil/sentinel/pkg/errors"
	"github.com/lucid-vigil/sentinel/pkg/events"
	"github.com/lucid-vigil/sentinel/pkg/monitors/base_monitor"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// EnhancedMonitor extends the Monitor interface to work with BaseMonitor
type EnhancedMonitor interface {
	Monitor
	Configure(config map[string]interface{}) error
	GetClass() base_monitor.MonitorClass
	GetCapabilities() []base_monitor.Capability
	GetState() base_monitor.MonitorState
	SetActionDispatcher(dispatcher *actions.ActionDispatcher)
	SetConfiguredActions(actions []string)
	SetEventBus(eventBus *events.EventBus)
}

// ConfigurableMonitor extends the Monitor interface to support configuration
type ConfigurableMonitor interface {
	Monitor
	Configure(config map[string]interface{}) error
}

// Monitor defines the interface for any monitor that can be scheduled.
type Monitor interface {
	Name() string
	Run(ctx context.Context)
	IsEnabled() bool
	GetInterval() time.Duration
	SetInterval(d time.Duration)
	GetLastError() error
	GetLastExecutionTime() time.Time
	GetMetrics() map[string]interface{}
}

// MonitorStatus represents the current status of a monitor
type MonitorStatus struct {
	Name         string                 `json:"name"`
	Class        string                 `json:"class"`
	Enabled      bool                   `json:"enabled"`
	LastRun      time.Time              `json:"last_run"`
	NextRun      time.Time              `json:"next_run"`
	Interval     time.Duration          `json:"interval"`
	Status       string                 `json:"status"`
	EventsRaised int64                  `json:"events_raised"`
	LastError    error                  `json:"last_error,omitempty"`
	Capabilities []string               `json:"capabilities"`
	Metrics      map[string]interface{} `json:"metrics"`
}

// Scheduler manages the registration and execution of various monitors with enhanced capabilities.
type Scheduler struct {
	monitors         []Monitor
	config           *config.Config
	eventBus         *events.EventBus
	actionDispatcher *actions.ActionDispatcher
	errorHandler     *errors.ErrorHandler
	logger           zerolog.Logger
	running          bool
	mu               sync.RWMutex
	monitorContexts  map[string]context.CancelFunc
	shutdownChannel  chan struct{}
	wg               sync.WaitGroup
}

// NewScheduler creates and returns a new enhanced Scheduler instance.
func NewScheduler(cfg *config.Config, eventBus *events.EventBus, actionDispatcher *actions.ActionDispatcher, errorHandler *errors.ErrorHandler) *Scheduler {
	return &Scheduler{
		config:           cfg,
		eventBus:         eventBus,
		actionDispatcher: actionDispatcher,
		errorHandler:     errorHandler,
		logger:           log.With().Str("component", "scheduler").Logger(),
		monitorContexts:  make(map[string]context.CancelFunc),
		shutdownChannel:  make(chan struct{}),
	}
}

// RegisterMonitor adds a monitor to the scheduler's list with full configuration.
func (s *Scheduler) RegisterMonitor(m Monitor) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Configure the monitor if it supports configuration
	if configurable, ok := m.(ConfigurableMonitor); ok {
		monitorConfig := s.config.GetMonitorConfig(m.Name())
		if monitorConfig != nil && monitorConfig.Config != nil {
			if err := configurable.Configure(monitorConfig.Config); err != nil {
				s.logger.Error().Err(err).Msgf("Failed to configure monitor '%s'", m.Name())
				return fmt.Errorf("failed to configure monitor '%s': %w", m.Name(), err)
			}
			s.logger.Info().Msgf("Monitor '%s' configured successfully", m.Name())
		}
	}

	// Enhanced configuration for monitors that support it
	if enhanced, ok := m.(EnhancedMonitor); ok {
		// Set event bus
		if s.eventBus != nil {
			enhanced.SetEventBus(s.eventBus)
			s.logger.Debug().Msgf("Event bus configured for monitor '%s'", m.Name())
		}

		// Set action dispatcher
		if s.actionDispatcher != nil {
			enhanced.SetActionDispatcher(s.actionDispatcher)
			s.logger.Debug().Msgf("Action dispatcher configured for monitor '%s'", m.Name())
		}

		// Configure actions from monitor config
		monitorConfig := s.config.GetMonitorConfig(m.Name())
		if monitorConfig != nil && len(monitorConfig.Actions) > 0 {
			enhanced.SetConfiguredActions(monitorConfig.Actions)
			s.logger.Info().
				Strs("actions", monitorConfig.Actions).
				Msgf("Actions configured for monitor '%s'", m.Name())
		}

		// Set interval if configured
		if monitorConfig != nil && monitorConfig.Interval != "" {
			if duration, err := time.ParseDuration(monitorConfig.Interval); err == nil {
				enhanced.SetInterval(duration)
			}
		}
	}

	s.monitors = append(s.monitors, m)
	s.logger.Info().
		Str("monitor", m.Name()).
		Msgf("Monitor '%s' registered successfully", m.Name())

	// Publish registration event
	if s.eventBus != nil {
		event := events.SecurityEvent{
			Type:        events.EventSystemStatus,
			Source:      "scheduler",
			Target:      m.Name(),
			Severity:    "info",
			Description: fmt.Sprintf("Monitor '%s' registered", m.Name()),
			Data: map[string]interface{}{
				"monitor_name": m.Name(),
				"action":       "registered",
			},
			Tags: []string{"scheduler", "registration"},
		}
		s.eventBus.Publish(context.Background(), event)
	}

	return nil
}

// Start launches all enabled monitors with their configured intervals.
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("scheduler is already running")
	}

	s.logger.Info().Msg("Scheduler starting...")
	s.running = true

	for _, mon := range s.monitors {
		if !mon.IsEnabled() {
			s.logger.Info().Msgf("Monitor '%s' is disabled, skipping", mon.Name())
			continue
		}

		monitorConfig := s.getMonitorConfig(mon.Name())
		if monitorConfig == nil {
			s.logger.Warn().Msgf("No configuration found for monitor '%s', using defaults", mon.Name())
			// Use default interval if no config
			if mon.GetInterval() == 0 {
				mon.SetInterval(5 * time.Minute) // Default 5-minute interval
			}
		} else if !monitorConfig.Enabled {
			s.logger.Info().Msgf("Monitor '%s' is disabled in configuration, skipping", mon.Name())
			continue
		}

		interval := mon.GetInterval()
		if interval == 0 {
			s.logger.Error().Msgf("Invalid interval for monitor '%s', skipping", mon.Name())
			continue
		}

		s.logger.Info().
			Str("monitor", mon.Name()).
			Dur("interval", interval).
			Msgf("Starting monitor '%s' with interval %s", mon.Name(), interval)

		// Create a cancellable context for this monitor
		monitorCtx, cancel := context.WithCancel(ctx)
		s.monitorContexts[mon.Name()] = cancel

		s.wg.Add(1)
		go s.runMonitor(monitorCtx, mon, interval)
	}

	s.logger.Info().Int("count", len(s.monitors)).Msg("All configured monitors started")

	// Publish scheduler started event
	if s.eventBus != nil {
		event := events.SecurityEvent{
			Type:        events.EventSystemStatus,
			Source:      "scheduler",
			Target:      "system",
			Severity:    "info",
			Description: "Scheduler started successfully",
			Data: map[string]interface{}{
				"monitors_count": len(s.monitors),
				"action":         "started",
			},
			Tags: []string{"scheduler", "startup"},
		}
		s.eventBus.Publish(ctx, event)
	}

	return nil
}

// Stop gracefully shuts down the scheduler and all monitors.
func (s *Scheduler) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return fmt.Errorf("scheduler is not running")
	}

	s.logger.Info().Msg("Scheduler stopping...")

	// Cancel all monitor contexts
	for name, cancel := range s.monitorContexts {
		s.logger.Debug().Msgf("Stopping monitor '%s'", name)
		cancel()
	}

	// Wait for all monitors to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info().Msg("All monitors stopped gracefully")
	case <-ctx.Done():
		s.logger.Warn().Msg("Shutdown timeout reached, some monitors may not have stopped gracefully")
	}

	s.running = false
	close(s.shutdownChannel)

	// Publish scheduler stopped event
	if s.eventBus != nil {
		event := events.SecurityEvent{
			Type:        events.EventSystemStatus,
			Source:      "scheduler",
			Target:      "system",
			Severity:    "info",
			Description: "Scheduler stopped",
			Data: map[string]interface{}{
				"action": "stopped",
			},
			Tags: []string{"scheduler", "shutdown"},
		}
		s.eventBus.Publish(context.Background(), event)
	}

	return nil
}

// IsRunning returns whether the scheduler is currently running.
func (s *Scheduler) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetMonitorStatus returns the current status of all monitors.
func (s *Scheduler) GetMonitorStatus() []MonitorStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	statuses := make([]MonitorStatus, 0, len(s.monitors))

	for _, mon := range s.monitors {
		status := MonitorStatus{
			Name:      mon.Name(),
			Enabled:   mon.IsEnabled(),
			LastRun:   mon.GetLastExecutionTime(),
			Interval:  mon.GetInterval(),
			LastError: mon.GetLastError(),
			Metrics:   mon.GetMetrics(),
		}

		// Calculate next run time
		if !status.LastRun.IsZero() && status.Interval > 0 {
			status.NextRun = status.LastRun.Add(status.Interval)
		}

		// Get enhanced information if available
		if enhanced, ok := mon.(EnhancedMonitor); ok {
			state := enhanced.GetState()
			status.Class = string(enhanced.GetClass())
			status.Status = state.Status
			status.EventsRaised = state.EventsRaised

			capabilities := enhanced.GetCapabilities()
			status.Capabilities = make([]string, len(capabilities))
			for i, cap := range capabilities {
				status.Capabilities[i] = string(cap)
			}
		}

		statuses = append(statuses, status)
	}

	return statuses
}

// RestartMonitor stops and restarts a specific monitor.
func (s *Scheduler) RestartMonitor(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the monitor
	var targetMonitor Monitor
	for _, mon := range s.monitors {
		if mon.Name() == name {
			targetMonitor = mon
			break
		}
	}

	if targetMonitor == nil {
		return fmt.Errorf("monitor '%s' not found", name)
	}

	// Stop the monitor if it's running
	if cancel, exists := s.monitorContexts[name]; exists {
		s.logger.Info().Msgf("Stopping monitor '%s' for restart", name)
		cancel()
		delete(s.monitorContexts, name)
	}

	// Start it again
	if targetMonitor.IsEnabled() {
		monitorCtx, cancel := context.WithCancel(ctx)
		s.monitorContexts[name] = cancel

		s.wg.Add(1)
		go s.runMonitor(monitorCtx, targetMonitor, targetMonitor.GetInterval())

		s.logger.Info().Msgf("Monitor '%s' restarted", name)

		// Publish restart event
		if s.eventBus != nil {
			event := events.SecurityEvent{
				Type:        events.EventSystemStatus,
				Source:      "scheduler",
				Target:      name,
				Severity:    "info",
				Description: fmt.Sprintf("Monitor '%s' restarted", name),
				Data: map[string]interface{}{
					"monitor_name": name,
					"action":       "restarted",
				},
				Tags: []string{"scheduler", "restart"},
			}
			s.eventBus.Publish(ctx, event)
		}
	}

	return nil
}

// runMonitor executes a monitor on its scheduled interval with enhanced error handling.
func (s *Scheduler) runMonitor(ctx context.Context, m Monitor, interval time.Duration) {
	defer s.wg.Done()

	monitorLogger := s.logger.With().Str("monitor", m.Name()).Logger()

	// Run immediately on start
	monitorLogger.Debug().Msg("Running monitor for the first time")
	s.executeMonitor(ctx, m, monitorLogger)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			monitorLogger.Debug().Msg("Running monitor")
			s.executeMonitor(ctx, m, monitorLogger)
		case <-ctx.Done():
			monitorLogger.Info().Msg("Monitor received shutdown signal")
			return
		}
	}
}

// executeMonitor runs a single monitor execution with error handling and metrics.
func (s *Scheduler) executeMonitor(ctx context.Context, m Monitor, logger zerolog.Logger) {
	startTime := time.Now()

	defer func() {
		duration := time.Since(startTime)
		logger.Debug().
			Dur("duration", duration).
			Msg("Monitor execution completed")
	}()

	// Handle panics
	defer func() {
		if r := recover(); r != nil {
			logger.Error().
				Interface("panic", r).
				Msg("Monitor panicked during execution")

			// Publish panic event if event bus is available
			if s.eventBus != nil {
				event := events.SecurityEvent{
					Type:        events.EventSystemError,
					Source:      m.Name(),
					Target:      "system",
					Severity:    "critical",
					Description: fmt.Sprintf("Monitor '%s' panicked: %v", m.Name(), r),
					Data: map[string]interface{}{
						"monitor_name": m.Name(),
						"panic_value":  r,
						"error_type":   "panic",
					},
					Tags: []string{"monitor", "panic", "error"},
				}
				s.eventBus.Publish(context.Background(), event)
			}
		}
	}()

	// Execute the monitor
	m.Run(ctx)

	// Check for errors after execution
	if lastError := m.GetLastError(); lastError != nil {
		logger.Error().
			Err(lastError).
			Msg("Monitor execution completed with error")

		// Publish error event if event bus is available
		if s.eventBus != nil {
			event := events.SecurityEvent{
				Type:        events.EventSystemError,
				Source:      m.Name(),
				Target:      "system",
				Severity:    "medium",
				Description: fmt.Sprintf("Monitor '%s' error: %v", m.Name(), lastError),
				Data: map[string]interface{}{
					"monitor_name": m.Name(),
					"error":        lastError.Error(),
					"error_type":   "execution_error",
				},
				Tags: []string{"monitor", "error"},
			}
			s.eventBus.Publish(ctx, event)
		}
	}
}

// getMonitorConfig retrieves configuration for a specific monitor.
func (s *Scheduler) getMonitorConfig(name string) *config.MonitorConfig {
	return s.config.GetMonitorConfig(name)
}

// GetEventBus returns the event bus instance.
func (s *Scheduler) GetEventBus() *events.EventBus {
	return s.eventBus
}

// GetActionDispatcher returns the action dispatcher instance.
func (s *Scheduler) GetActionDispatcher() *actions.ActionDispatcher {
	return s.actionDispatcher
}

// WaitForShutdown blocks until the scheduler is shut down.
func (s *Scheduler) WaitForShutdown() {
	<-s.shutdownChannel
}
