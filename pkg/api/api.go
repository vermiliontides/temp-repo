package api

import (
	"net/http"

	"github.com/rs/zerolog/log"
)

// StartAPIServer initializes and starts a simple HTTP server in a goroutine.
// It provides endpoints for health checks (/healthz) and Prometheus metrics (/metrics).
// The server will run until the application is terminated.
func StartAPIServer(port string) {
	http.HandleFunc("/healthz", healthzHandler)
	http.HandleFunc("/metrics", metricsHandler) // Placeholder for actual metrics

	log.Info().Msgf("API server starting on :%s", port)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("API server failed to start")
	}
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("# HELP sentinel_up Is the sentinel application up and running.\n# TYPE sentinel_up gauge\nsentinel_up 1\n"))
}
