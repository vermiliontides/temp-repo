package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/actions"
	"github.com/lucid-vigil/sentinel/pkg/api"
	"github.com/lucid-vigil/sentinel/pkg/config"
	"github.com/lucid-vigil/sentinel/pkg/logger"
	"github.com/lucid-vigil/sentinel/pkg/monitors/filesystem"
	"github.com/lucid-vigil/sentinel/pkg/monitors/firmware"
	"github.com/lucid-vigil/sentinel/pkg/monitors/network"
	"github.com/lucid-vigil/sentinel/pkg/monitors/networkids"
	"github.com/lucid-vigil/sentinel/pkg/monitors/persistence"
	"github.com/lucid-vigil/sentinel/pkg/monitors/process"
	"github.com/lucid-vigil/sentinel/pkg/monitors/recondetector"
	"github.com/lucid-vigil/sentinel/pkg/monitors/rootkit"
	"github.com/lucid-vigil/sentinel/pkg/monitors/scribe"
	"github.com/lucid-vigil/sentinel/pkg/monitors/thermal"
	"github.com/lucid-vigil/sentinel/pkg/scheduler"
	"github.com/rs/zerolog/log"
)

func main() {
	// Load configuration first
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Initialize logger based on config
	logger.InitLogger(cfg.LogLevel)

	log.Info().Msg("Lucid Vigil (Sentinel) application starting...")
	log.Info().Msgf("Configuration loaded: LogLevel=%s, APIPort=%s, ActionsEnabled=%t",
		cfg.LogLevel, cfg.APIPort, cfg.Actions.Enabled)

	// Create action dispatcher
	actionDispatcher := actions.NewActionDispatcher(cfg.Actions.Enabled)

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Set up a channel to listen for OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to handle graceful shutdown
	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal: %s. Shutting down gracefully...", sig)
		cancel()
	}()

	// Start API server in a goroutine
	go api.StartAPIServer(cfg.APIPort)

	// Initialize and start the scheduler
	sched := scheduler.NewScheduler(cfg)

	// Register monitors with action dispatcher support
	registerMonitorWithActions := func(monitor scheduler.Monitor, monitorConfig *config.MonitorConfig) {
		// Set up action integration if monitor supports it
		if baseMonitor, ok := monitor.(interface {
			SetActionDispatcher(*actions.ActionDispatcher)
			SetConfiguredActions([]string)
		}); ok {
			baseMonitor.SetActionDispatcher(actionDispatcher)
			if monitorConfig != nil {
				baseMonitor.SetConfiguredActions(monitorConfig.Actions)
			}
		}
		sched.RegisterMonitor(monitor)
	}

	// Register all monitors
	registerMonitorWithActions(&process.ProcessMonitor{}, cfg.GetMonitorConfig("process_monitor"))
	registerMonitorWithActions(filesystem.NewFilesystemMonitor(log.Logger), cfg.GetMonitorConfig("filesystem_monitor"))
	registerMonitorWithActions(&network.NetworkMonitor{}, cfg.GetMonitorConfig("network_monitor"))
	registerMonitorWithActions(persistence.NewPersistenceMonitor(log.Logger), cfg.GetMonitorConfig("persistence_monitor"))
	registerMonitorWithActions(rootkit.NewRootkitMonitor(log.Logger), cfg.GetMonitorConfig("rootkit_monitor"))
	registerMonitorWithActions(thermal.NewThermalMonitor(log.Logger), cfg.GetMonitorConfig("thermal_monitor"))
	registerMonitorWithActions(firmware.NewFirmwareMonitor(log.Logger), cfg.GetMonitorConfig("firmware_monitor"))
	registerMonitorWithActions(networkids.NewNetworkIDS(log.Logger), cfg.GetMonitorConfig("network_ids"))
	registerMonitorWithActions(recondetector.NewReconDetector(log.Logger), cfg.GetMonitorConfig("recon_detector"))
	registerMonitorWithActions(scribe.NewScribeMonitor(log.Logger), cfg.GetMonitorConfig("scribe"))

	// Start all configured monitors
	sched.Start(ctx)

	// Wait for shutdown signal
	<-ctx.Done()

	log.Info().Msg("Lucid Vigil (Sentinel) application stopped.")
	time.Sleep(1 * time.Second) // Give some time for cleanup
}
