package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kali-security-monitoring/sentinel/pkg/api"
	"github.com/kali-security-monitoring/sentinel/pkg/config"
	"github.com/kali-security-monitoring/sentinel/pkg/logger"
	"github.com/kali-security-monitoring/sentinel/pkg/monitors/filesystem"
	"github.com/kali-security-monitoring/sentinel/pkg/monitors/firmware"
	"github.com/kali-security-monitoring/sentinel/pkg/monitors/network"
	"github.com/kali-security-monitoring/sentinel/pkg/monitors/networkids"
	"github.com/kali-security-monitoring/sentinel/pkg/monitors/persistence"
	"github.com/kali-security-monitoring/sentinel/pkg/monitors/process"
	"github.com/kali-security-monitoring/sentinel/pkg/monitors/recondetector"
	"github.com/kali-security-monitoring/sentinel/pkg/monitors/rootkit"
	"github.com/kali-security-monitoring/sentinel/pkg/monitors/thermal"
	"github.com/kali-security-monitoring/sentinel/pkg/scheduler"
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

	log.Info().Msg("Sentinel application starting...")
	log.Info().Msgf("Configuration loaded: LogLevel=%s, APIPort=%s", cfg.LogLevel, cfg.APIPort)

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Set up a channel to listen for OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to handle graceful shutdown
	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal: %s. Shutting down gracefully...", sig)
		cancel() // Cancel the context to signal other goroutines to stop
	}()

	// Start API server in a goroutine
	go api.StartAPIServer(cfg.APIPort)

	// Initialize and start the scheduler
	sched := scheduler.NewScheduler(cfg)

	// Register monitors
	sched.RegisterMonitor(&process.ProcessMonitor{})
	sched.RegisterMonitor(&filesystem.FilesystemMonitor{})
	sched.RegisterMonitor(&network.NetworkMonitor{})
	sched.RegisterMonitor(&persistence.PersistenceMonitor{})
	sched.RegisterMonitor(&rootkit.RootkitMonitor{})
	sched.RegisterMonitor(thermal.NewThermalMonitor(log.Logger))
	sched.RegisterMonitor(firmware.NewFirmwareMonitor(log.Logger))
	sched.RegisterMonitor(networkids.NewNetworkIDS(log.Logger))
	sched.RegisterMonitor(recondetector.NewReconDetector(log.Logger))
	sched.RegisterMonitor(thermal.NewThermalMonitor(log.Logger))
	sched.RegisterMonitor(firmware.NewFirmwareMonitor(log.Logger))

	// Start all configured monitors
	sched.Start(ctx)

	// --- Application Logic Goes Here ---
	// For now, just a placeholder that waits for the context to be cancelled
	<-ctx.Done()

	log.Info().Msg("Sentinel application stopped.")
	time.Sleep(1 * time.Second) // Give some time for cleanup
}
