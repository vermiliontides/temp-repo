package filesystem

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// LogCapture is a helper to capture zerolog output for testing.
type LogCapture struct {
	sync.Mutex
	logs []string
}

func (lc *LogCapture) Write(p []byte) (n int, err error) {
	lc.Lock()
	defer lc.Unlock()
	lc.logs = append(lc.logs, string(p))
	return len(p), nil
}

func (lc *LogCapture) GetLogs() []string {
	lc.Lock()
	defer lc.Unlock()
	return lc.logs
}

func (lc *LogCapture) ClearLogs() {
	lc.Lock()
	defer lc.Unlock()
	lc.logs = nil
}

// Mocks for testing
var (
	execCommand   = exec.Command
	osStat        = os.Stat
	filepathWalk  = filepath.Walk
	syscallStatfs = syscall.Statfs
)

func TestFilesystemMonitor_Run(t *testing.T) {
	// Setup log capture
	lc := &LogCapture{}
	log.Logger = zerolog.New(lc).With().Timestamp().Logger()
	defer lc.ClearLogs()

	// Create monitor instance
	monitor := NewFilesystemMonitor(log.Logger)
	fm, ok := monitor.(*FilesystemMonitor)
	assert.True(t, ok)

	// Create a temporary directory for testing
	testDir, err := os.MkdirTemp("", "fs_monitor_test")
	require.NoError(t, err)
	defer os.RemoveAll(testDir)

	// Set config for testing
	fm.config = &FilesystemMonitorConfig{
		CriticalPaths:      testDir,
		ExcludePaths:       "",
		SuidCheckInterval:  1, // Run periodic checks quickly
		MonitorHiddenFiles: true,
		AlertOnSuidChanges: true,
		SuidBaselineFile:   filepath.Join(testDir, "baseline_suid.txt"),
		ConfigBaselineDir:  filepath.Join(testDir, "config_baselines"),
	}

	// Mock syscall.Statfs for predictable disk usage results
	oldSyscallStatfs := syscallStatfs
	syscallStatfs = func(path string, buf *syscall.Statfs_t) (err error) {
		buf.Blocks = 1000 // Total blocks
		buf.Bsize = 1024  // Block size
		buf.Bfree = 100   // Free blocks (10% free, 90% used)
		buf.Files = 1000  // Total inodes
		buf.Ffree = 100   // Free inodes (10% free, 90% used)
		return nil
	}
	defer func() { syscallStatfs = oldSyscallStatfs }()

	// Mock exec.Command for `find` and `lsattr`
	oldExecCommand := execCommand
	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "find" && strings.Contains(strings.Join(arg, " "), "-perm -4000") {
			return &exec.Cmd{
				Path: "/bin/bash",
				Args: []string{"bash", "-c", "printf \"/usr/bin/sudo\\n/usr/bin/passwd\\n\""},
			}
		} else if name == "lsattr" {
			return &exec.Cmd{
				Path: "/bin/bash",
				Args: []string{"bash", "-c", "echo \"----i-----\""},
			}
		}
		return oldExecCommand(name, arg...)
	}
	defer func() { execCommand = oldExecCommand }()

	// Create a context with a timeout to stop the monitor gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run the monitor in a goroutine
	go fm.Run(ctx)

	// Give the monitor some time to start and run periodic checks
	time.Sleep(1500 * time.Millisecond)

	// --- Simulate a file event ---
	dummyFile := filepath.Join(testDir, "dummy.txt")
	err = os.WriteFile(dummyFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Give time for fsnotify to pick up the event
	time.Sleep(500 * time.Millisecond)

	// Assertions
	logs := strings.Join(lc.GetLogs(), "")
	assert.Contains(t, logs, "Running Filesystem Monitor...")
	assert.Contains(t, logs, "Monitoring filesystem path.")
	assert.Contains(t, logs, "Running periodic filesystem checks...")
	assert.Contains(t, logs, "High disk usage detected.")
	assert.Contains(t, logs, "High inode usage detected.")
	assert.Contains(t, logs, "New SUID/SGID files detected.")
	assert.Contains(t, logs, "File created.")

	// Ensure the monitor stops gracefully
	cancel()
	time.Sleep(500 * time.Millisecond) // Give time for shutdown
	assert.Contains(t, strings.Join(lc.GetLogs(), ""), "Filesystem Monitor finished.")
}

func TestNewFilesystemMonitor(t *testing.T) {
	logger := zerolog.Nop()
	monitor := NewFilesystemMonitor(logger)

	assert.NotNil(t, monitor)
	assert.Equal(t, "filesystem_monitor", monitor.Name())

	fm, ok := monitor.(*FilesystemMonitor)
	assert.True(t, ok)
	assert.NotNil(t, fm.BaseMonitor)
	assert.NotNil(t, fm.config)
}
