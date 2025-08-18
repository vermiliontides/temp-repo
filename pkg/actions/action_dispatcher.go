package actions

import (
	"context"
	"fmt"
	"sync"

	"github.com/lucid-vigil/sentinel/pkg/actions/block_ip"
	"github.com/lucid-vigil/sentinel/pkg/actions/kill_process"
	"github.com/rs/zerolog/log"
)

// Manages and executes actions

// ActionDispatcher manages and executes defensive actions
type ActionDispatcher struct {
	actions map[string]Action
	enabled bool
	mu      sync.RWMutex
}

// NewActionDispatcher creates a new action dispatcher
func NewActionDispatcher(enabled bool) *ActionDispatcher {
	dispatcher := &ActionDispatcher{
		actions: make(map[string]Action),
		enabled: enabled,
	}

	// Register built-in actions
	dispatcher.RegisterAction(&block_ip.BlockIPAction{})
	dispatcher.RegisterAction(&kill_process.KillProcessAction{})

	return dispatcher
}

// RegisterAction registers a new action with the dispatcher
func (ad *ActionDispatcher) RegisterAction(action Action) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.actions[action.Name()] = action
	log.Info().Msgf("Action '%s' registered.", action.Name())
}

// Execute runs the specified action with the given data
func (ad *ActionDispatcher) Execute(ctx context.Context, actionName string, data map[string]interface{}) error {
	if !ad.enabled {
		log.Info().Str("action", actionName).Msg("Actions are disabled, skipping execution.")
		return nil
	}

	ad.mu.RLock()
	action, exists := ad.actions[actionName]
	ad.mu.RUnlock()

	if !exists {
		return fmt.Errorf("action '%s' not found", actionName)
	}

	log.Info().Str("action", actionName).Msg("Executing defensive action...")

	if err := action.Execute(ctx, data); err != nil {
		log.Error().Err(err).Str("action", actionName).Msg("Action execution failed.")
		return err
	}

	log.Info().Str("action", actionName).Msg("Action executed successfully.")
	return nil
}

// ExecuteActions runs multiple actions for a monitor
func (ad *ActionDispatcher) ExecuteActions(ctx context.Context, actionNames []string, data map[string]interface{}) {
	for _, actionName := range actionNames {
		if err := ad.Execute(ctx, actionName, data); err != nil {
			log.Error().Err(err).Str("action", actionName).Msg("Failed to execute action.")
		}
	}
}

// IsEnabled returns whether actions are enabled
func (ad *ActionDispatcher) IsEnabled() bool {
	return ad.enabled
}

// SetEnabled enables or disables action execution
func (ad *ActionDispatcher) SetEnabled(enabled bool) {
	ad.enabled = enabled
	log.Info().Bool("enabled", enabled).Msg("Action execution status changed.")
}
