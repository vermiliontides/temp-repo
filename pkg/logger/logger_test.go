package logger

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestInitLogger(t *testing.T) {
	// Save original stdout and global log level
	oldStdout := os.Stdout
	oldGlobalLevel := zerolog.GlobalLevel()

	// Test cases for different log levels
	tests := []struct {
		name          string
		logLevel      string
		expectedLevel zerolog.Level
		expectOutput  bool // New field: whether to expect the initialization message in output
	}{
		{"Debug Level", "debug", zerolog.DebugLevel, true},
		{"Info Level", "info", zerolog.InfoLevel, true},
		{"Warn Level", "warn", zerolog.WarnLevel, false},
		{"Error Level", "error", zerolog.ErrorLevel, false},
		{"Fatal Level", "fatal", zerolog.FatalLevel, false},
		{"Panic Level", "panic", zerolog.PanicLevel, false},
		{"Default Level (unknown)", "unknown", zerolog.InfoLevel, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global log level for each test
			zerolog.SetGlobalLevel(zerolog.Disabled) // Ensure a clean state

			// Create new pipe for each test run
			r, w, _ := os.Pipe()
			os.Stdout = w

			InitLogger(tt.logLevel)
			assert.Equal(t, tt.expectedLevel, zerolog.GlobalLevel())

			// Close the write end of the pipe and read its output
			w.Close()
			out, _ := io.ReadAll(r)
			r.Close()

			logOutput := string(out)

			if tt.expectOutput {
				assert.True(t, strings.Contains(logOutput, "Logger initialized with level:"), "Expected initialization message in logs")
				assert.True(t, strings.Contains(logOutput, tt.expectedLevel.String()), "Expected log level in initialization message")
			} else {
				assert.False(t, strings.Contains(logOutput, "Logger initialized with level:"), "Did not expect initialization message in logs")
			}
		})
	}

	// Restore original stdout and global log level after all tests
	os.Stdout = oldStdout
	zerolog.SetGlobalLevel(oldGlobalLevel)
}