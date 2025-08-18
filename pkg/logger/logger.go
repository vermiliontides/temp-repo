package logger

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitLogger initializes the zerolog logger with JSON output to stdout.
// It sets the log level based on the provided string (e.g., "info", "debug", "error").
func InitLogger(logLevel string) {
	log.Logger = log.Output(os.Stdout).With().Timestamp().Logger()

	switch logLevel {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel) // Default to info if invalid
	}

	log.Info().Msgf("Logger initialized with level: %s", zerolog.GlobalLevel().String())
}
