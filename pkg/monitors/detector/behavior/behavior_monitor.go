package behavior

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

// BehaviorMonitorConfig holds configuration for the BehaviorMonitor.
type BehaviorMonitorConfig struct {
	BehaviorRules []string `mapstructure:"behavior_rules"`
	RunInterval   int      `mapstructure:"run_interval"`
}

// BehaviorMonitor implements the scheduler.Monitor interface for behavior analysis.
type BehaviorMonitor struct {
	Config BehaviorMonitorConfig
}

// Name returns the name of the monitor.
func (bm *BehaviorMonitor) Name() string {
	return "behavior_monitor"
}

// Run executes the behavior monitoring logic.
func (bm *BehaviorMonitor) Run(ctx context.Context) {
	log.Info().Msg("Running Behavior Monitor...")

	bm.analyzeBehavior()

	log.Info().Msg("Behavior Monitor finished.")
}

// analyzeBehavior analyzes command history for suspicious behavior patterns.
func (bm *BehaviorMonitor) analyzeBehavior() {
	log.Info().Msg("Analyzing command history for suspicious behavior...")

	// IMPORTANT: Directly reading .bash_history has significant limitations:
	// - Only captures commands from bash interactive sessions.
	// - Does not capture commands from other shells (zsh, fish, etc.).
	// - History can be easily manipulated, cleared, or disabled by an attacker.
	// - Does not capture commands executed by non-interactive scripts or processes.
	// For a more robust solution, consider using auditd or other system auditing tools.

	// Attempt to find common history files for the current user.
	// A more comprehensive solution would iterate through all users in /etc/passwd.
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user home directory.")
		return
	}

	historyFiles := []string{
		filepath.Join(userHomeDir, ".bash_history"),
		filepath.Join(userHomeDir, ".zsh_history"),
		// Add other history files as needed
	}

	for _, historyFile := range historyFiles {
		if _, err := os.Stat(historyFile); os.IsNotExist(err) {
			continue // History file does not exist
		}

		file, err := os.Open(historyFile)
		if err != nil {
			log.Error().Err(err).Str("file", historyFile).Msg("Failed to open history file.")
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		var commands []string
		for scanner.Scan() {
			commands = append(commands, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			log.Error().Err(err).Str("file", historyFile).Msg("Error reading history file.")
			continue
		}

		log.Info().Str("file", historyFile).Msg("Analyzing history file.")

		for _, rule := range bm.Config.BehaviorRules {
			parts := strings.SplitN(rule, "|", 2)
			if len(parts) != 2 {
				log.Warn().Str("rule", rule).Msg("Invalid behavior rule format.")
				continue
			}
			sequenceStr := parts[0]
			alertMessage := parts[1]

			sequenceCommands := strings.Split(sequenceStr, "->")

			// Build a regex pattern to match the sequence of commands
			// This is a simplified approach and might need refinement for complex patterns.
			pattern := ".*" + strings.Join(sequenceCommands, ".*\\n.*") + ".*"
			re, err := regexp.Compile("(?s)" + pattern) // (?s) enables dotall mode for newline matching
			if err != nil {
				log.Error().Err(err).Str("pattern", pattern).Msg("Invalid regex pattern in behavior rule.")
				continue
			}

			fullHistory := strings.Join(commands, "\n")
			if re.MatchString(fullHistory) {
				log.Warn().
					Str("file", historyFile).
					Str("sequence", sequenceStr).
					Msgf("Behavior rule match: %s", alertMessage)
			}
		}
	}
}
