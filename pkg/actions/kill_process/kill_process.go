package kill_process

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/rs/zerolog/log"
)

// Implments Action interface

// KillProcessAction implements the actions.Action interface. It is responsible for
// terminating a process given its Process ID (PID).
type KillProcessAction struct{}

// Name returns the unique name of the action.
func (kpa *KillProcessAction) Name() string {
	return "kill_process"
}

// Execute runs the logic to kill a process. It expects the data map to contain
// a "pid" key with the integer PID. It first attempts a graceful termination with
// SIGTERM, followed by a forceful SIGKILL if the first signal fails.
func (kpa *KillProcessAction) Execute(ctx context.Context, data map[string]interface{}) error {
	pidVal, ok := data["pid"]
	if !ok {
		return fmt.Errorf("missing 'pid' in action data for kill_process action")
	}

	var pid int
	switch v := pidVal.(type) {
	case int:
		pid = v
	case float64: // JSON unmarshals numbers to float64 by default
		pid = int(v)
	case string:
		intPid, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid pid format: %w", err)
		}
		pid = intPid
	default:
		return fmt.Errorf("unsupported pid type: %T", pidVal)
	}

	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process with PID %d: %w", pid, err)
	}

	// Send SIGTERM first for graceful shutdown
	err = process.Signal(syscall.SIGTERM)
	if err != nil {
		log.Warn().Err(err).Int("pid", pid).Msg("Failed to send SIGTERM, attempting SIGKILL.")
		// If SIGTERM fails, try SIGKILL
		err = process.Signal(syscall.SIGKILL)
		if err != nil {
			return fmt.Errorf("failed to send SIGKILL to process %d: %w", pid, err)
		}
	}

	log.Info().Int("pid", pid).Msg("Successfully sent signal to process.")
	return nil
}
