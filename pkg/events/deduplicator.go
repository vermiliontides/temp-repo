// pkg/events/deduplicator.go
package events

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// EventDeduplicator prevents duplicate events within a time window
type EventDeduplicator struct {
	seen          map[string]time.Time
	window        time.Duration
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// NewEventDeduplicator creates a new event deduplicator
func NewEventDeduplicator(window time.Duration) *EventDeduplicator {
	ed := &EventDeduplicator{
		seen:        make(map[string]time.Time),
		window:      window,
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup goroutine
	ed.cleanupTicker = time.NewTicker(window / 2)
	go ed.cleanupLoop()

	return ed
}

// IsDuplicate checks if event is a duplicate within the time window
func (ed *EventDeduplicator) IsDuplicate(event SecurityEvent) bool {
	hash := ed.eventHash(event)

	ed.mu.RLock()
	lastSeen, exists := ed.seen[hash]
	ed.mu.RUnlock()

	if !exists {
		ed.mu.Lock()
		ed.seen[hash] = time.Now()
		ed.mu.Unlock()
		return false
	}

	// Check if within deduplication window
	if time.Since(lastSeen) < ed.window {
		return true
	}

	// Update timestamp
	ed.mu.Lock()
	ed.seen[hash] = time.Now()
	ed.mu.Unlock()

	return false
}

// eventHash creates a hash for event deduplication
func (ed *EventDeduplicator) eventHash(event SecurityEvent) string {
	// Hash based on type, source, target, and severity
	data := fmt.Sprintf("%s:%s:%s:%s:%s",
		event.Type, event.Source, event.Target, event.Severity, event.Description)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// cleanupLoop removes old entries
func (ed *EventDeduplicator) cleanupLoop() {
	for {
		select {
		case <-ed.cleanupTicker.C:
			ed.cleanup()
		case <-ed.stopCleanup:
			ed.cleanupTicker.Stop()
			return
		}
	}
}

// cleanup removes expired entries
func (ed *EventDeduplicator) cleanup() {
	ed.mu.Lock()
	defer ed.mu.Unlock()

	cutoff := time.Now().Add(-ed.window)
	for hash, timestamp := range ed.seen {
		if timestamp.Before(cutoff) {
			delete(ed.seen, hash)
		}
	}
}

// Stop stops the deduplicator
func (ed *EventDeduplicator) Stop() {
	close(ed.stopCleanup)
}
