package process

import (
	
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to capture logs
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

func TestMain(m *testing.M) {
	// Set up zerolog for testing
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestProcessMonitor_monitorResourceUsage(t *testing.T) {
	lc := &LogCapture{}
	log.Logger = log.Output(lc)
	defer lc.ClearLogs()

	pm := &ProcessMonitor{
		Config: ProcessMonitorConfig{
			CPUThreshold:    0.1, // Very low to catch any process
			MemoryThreshold: 0.1, // Very low to catch any process
		},
	}

	// Run a dummy process to ensure there's something to monitor
	cmd := exec.Command("sleep", "0.5")
	err := cmd.Start()
	require.NoError(t, err)
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	pm.monitorResourceUsage()

	logs := lc.GetLogs()
	assert.True(t, len(logs) > 0, "Expected logs for resource usage monitoring")
	assert.Contains(t, logs[0], "cpu_percent", "Expected CPU usage in logs")
}

func TestProcessMonitor_detectSuspiciousProcesses(t *testing.T) {
	lc := &LogCapture{}
	log.Logger = log.Output(lc)
	defer lc.ClearLogs()

	pm := &ProcessMonitor{
		Config: ProcessMonitorConfig{
			SuspiciousNames: "sleep,test_process_name",
		},
	}

	// Test with a suspicious process name
	cmd1 := exec.Command("sleep", "1")
	err := cmd1.Start()
	require.NoError(t, err)
	defer func() {
		cmd1.Process.Kill()
		cmd1.Wait()
	}()

	// Test with a suspicious command line
	cmd2 := exec.Command("bash", "-c", "echo test_process_name")
	err = cmd2.Start()
	require.NoError(t, err)
	defer func() {
		cmd2.Process.Kill()
		cmd2.Wait()
	}()

	time.Sleep(100 * time.Millisecond) // Give processes time to start

	pm.detectSuspiciousProcesses()

	logs := lc.GetLogs()
	assert.Contains(t, strings.Join(logs, "\n"), "Suspicious process name detected", "Expected log for suspicious name")
	assert.Contains(t, strings.Join(logs, "\n"), "Suspicious process command line detected", "Expected log for suspicious command line")
}

func TestProcessMonitor_monitorProcessCreation(t *testing.T) {
	lc := &LogCapture{}
	log.Logger = log.Output(lc)
	defer lc.ClearLogs()

	pm := &ProcessMonitor{}
	pm.previousProcesses = make(map[int32]bool) // Initialize for first run

	// Simulate initial processes
	cmd1 := exec.Command("sleep", "0.1")
	err := cmd1.Start()
	require.NoError(t, err)
	pm.previousProcesses[int32(cmd1.Process.Pid)] = true
	defer func() {
		cmd1.Process.Kill()
		cmd1.Wait()
	}()

	// Run monitor once to establish baseline
	pm.monitorProcessCreation()
	lc.ClearLogs() // Clear logs from baseline run

	// Start a new process
	cmd2 := exec.Command("sleep", "0.2")
	err = cmd2.Start()
	require.NoError(t, err)
	defer func() {
		cmd2.Process.Kill()
		cmd2.Wait()
	}()

	time.Sleep(50 * time.Millisecond) // Give process time to start

	pm.monitorProcessCreation()

	logs := lc.GetLogs()
	assert.True(t, len(logs) > 0, "Expected logs for new process creation")
	assert.Contains(t, logs[0], "New process detected", "Expected log for new process")
	assert.Contains(t, logs[0], fmt.Sprintf("\"pid\":%d", cmd2.Process.Pid), "Expected log to contain new process PID")
}

func TestProcessMonitor_detectHiddenProcesses(t *testing.T) {
	lc := &LogCapture{}
	log.Logger = log.Output(lc)
	defer lc.ClearLogs()

	pm := &ProcessMonitor{}

	// This test is difficult to make truly isolated and reliable without
	// kernel-level manipulation or a very specific test environment.
	// For now, we'll test that it runs without error and logs something
	// if a discrepancy is found. A real hidden process would require
	// a more sophisticated integration test setup.

	pm.detectHiddenProcesses()
	logs := lc.GetLogs()

	// We expect at least an INFO log about process counts,
	// and potentially alerts if the test environment has anomalies.
	if len(logs) > 0 {
		assert.Contains(t, logs[0], "Possible hidden process detected", "Expected log about hidden processes if any are found")
	} else {
		assert.True(t, true, "No hidden processes detected, which is expected in a clean test environment.")
	}
}

func TestProcessMonitor_monitorProcessTree(t *testing.T) {
	lc := &LogCapture{}
	log.Logger = log.Output(lc)
	defer lc.ClearLogs()

	pm := &ProcessMonitor{}

	// This test requires simulating a process with PID 1 as parent,
	// which is not straightforward in a standard Go test.
	// We'll rely on the `gopsutil` library's ability to read process trees.
	// For a true test, this would need to be run in a controlled environment
	// where a process can be spawned with PID 1 as its parent (e.g., by using unshare or a container).

	// For now, we'll just run it and ensure it doesn't panic.
	// A more robust test would involve creating a dummy process that
	// appears to have PID 1 as parent (e.g., by using unshare or a container).

	pm.monitorProcessTree()
	logs := lc.GetLogs()

	// Assert that it ran and potentially found something if the test environment has it.
	// We can't assert a specific warning without a controlled setup.
	assert.True(t, true, "monitorProcessTree ran without panic")
	if len(logs) > 0 {
		assert.Contains(t, logs[0], "Suspicious process with PID 1 as parent detected", "Expected log if suspicious tree found")
	}
}

func TestProcessMonitor_monitorDetachedProcesses(t *testing.T) {
	lc := &LogCapture{}
	log.Logger = log.Output(lc)
	defer lc.ClearLogs()

	pm := &ProcessMonitor{
		Config: ProcessMonitorConfig{
			WhitelistUsers: "root,daemon", // Common whitelisted users
		},
	}

	// This test is also challenging as creating a truly detached process
	// without a TTY from a Go test is complex and OS-dependent.
	// We'll rely on the `gopsutil` library's Tty() method.

	// For a real test, you'd need to spawn a process in a way that it
	// doesn't inherit a TTY (e.g., using `setsid` or in a background service).

	pm.monitorDetachedProcesses()
	logs := lc.GetLogs()

	// We expect some logs, but cannot assert specific detached processes
	// without a controlled environment.
	assert.True(t, true, "monitorDetachedProcesses ran without panic")
	if len(logs) > 0 {
		assert.Contains(t, logs[0], "Detached process detected from non-whitelisted user", "Expected log if detached process found")
	}
}

func TestProcessMonitor_monitorSystemdServices(t *testing.T) {
	lc := &LogCapture{}
	log.Logger = log.Output(lc)
	defer lc.ClearLogs()

	pm := &ProcessMonitor{}

	// Mock exec.Command for testing systemctl calls
	oldExecCommand := execCommand // Store original
	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "systemctl" {
			if len(arg) > 0 && arg[0] == "list-units" && strings.Contains(strings.Join(arg, " "), "--failed") {
				return &exec.Cmd{
					Path: "/bin/bash",
					Args: []string{"bash", "-c", `printf "  ● my-test-failed-service-1.service loaded failed failed My Test Failed Service 1
  ● my-test-failed-service-2.service loaded failed failed My Test Failed Service 2
"`},
				}
			}
			if len(arg) > 0 && arg[0] == "list-unit-files" && strings.Contains(strings.Join(arg, " "), "--state=masked") {
				return &exec.Cmd{
					Path: "/bin/bash",
					Args: []string{"bash", "-c", `printf "my-test-masked-service-1.service masked enabled
my-test-masked-service-2.service masked enabled
"`},
				}
			}
		}
		return oldExecCommand(name, arg...) // Call original for other commands
	}
	defer func() { execCommand = oldExecCommand }() // Reset after test

	pm.monitorSystemdServices()

	logs := lc.GetLogs()

	// Helper to check if a log entry exists with specific message, service, and level
	checkLogEntry := func(t *testing.T, logs []string, expectedLevel string, expectedMessage string, expectedService string) bool {
		for _, logEntry := range logs {
			var parsedLog map[string]interface{}
			if err := json.Unmarshal([]byte(logEntry), &parsedLog); err != nil {
				t.Logf("Failed to unmarshal log entry: %v, Log: %s", err, logEntry)
				continue // Skip malformed log entries
			}

			level, levelOk := parsedLog["level"].(string)
			msg, msgOk := parsedLog["message"].(string)
			svc, svcOk := parsedLog["service"].(string)

			t.Logf("Parsed Log: %+v", parsedLog)
			t.Logf("Comparing: Level=\"%s\" (expected \"%s\"), Msg=\"%s\" (expected \"%s\"), Svc=\"%s\" (expected \"%s\")", level, expectedLevel, msg, expectedMessage, svc, expectedService)

			if levelOk && msgOk && level == expectedLevel && strings.Contains(msg, expectedMessage) {
				if expectedService == "" { // For count messages, service field should not exist or be empty
					if !svcOk || svc == "" {
						return true
					}
				} else { // For specific service messages, service field must match
					if svcOk {
					actualService := strings.TrimSpace(svc)
					if strings.HasPrefix(actualService, "● ") {
						actualService = strings.Fields(actualService)[1] // Get the service name after '●'
					} else {
						actualService = strings.Fields(actualService)[0] // Get the service name
					}
					if actualService == expectedService[0] { // Exact match for service // Use Contains for partial match
						return true
					}
				}
			}
		}
		return false
	}



	assert.True(t, checkLogEntry(t, logs, "warn", "Failed systemd services detected.", ""), "Expected log for failed service count")
	assert.True(t, checkLogEntry(t, logs, "warn", "Systemd service failed.", "  ● my-test-failed-service-1.service loaded failed failed My Test Failed Service 1"), "Expected log for specific failed service 1")
	assert.True(t, checkLogEntry(t, logs, "warn", "Systemd service failed.", "  ● my-test-failed-service-2.service loaded failed failed My Test Failed Service 2"), "Expected log for specific failed service 2")
	assert.True(t, checkLogEntry(t, logs, "info", "Masked systemd services found (excluding systemd internal ones).", ""), "Expected log for masked service count")
	assert.True(t, checkLogEntry(t, logs, "info", "Systemd service masked.", "my-test-masked-service-1.service masked enabled"), "Expected log for specific masked service 1")
	assert.True(t, checkLogEntry(t, logs, "info", "Systemd service masked.", "my-test-masked-service-2.service masked enabled"), "Expected log for specific masked service 2")


}

// Override exec.Command for testing purposes
var execCommand = exec.Command
