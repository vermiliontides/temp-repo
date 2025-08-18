package actions

import (
	"context"
)

// Action defines the interface for any defensive action Sentinel can take.
// Each action must have a name and an execution method.
type Action interface {
	// Name returns the unique name of the action.
	Name() string
	// Execute performs the action. It is passed a context for cancellation and a
	// map of data that can contain any relevant information (e.g., IP to block, PID to kill).
	Execute(ctx context.Context, data map[string]interface{}) error
}
