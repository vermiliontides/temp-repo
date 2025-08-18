package process

import (
	"context"
	"fmt"
	"io/ioutil"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/process"
)

// ProcessMonitorConfig holds configuration for the ProcessMonitor.
// It defines thresholds for resource usage and lists of suspicious process names.
type ProcessMonitorConfig struct {
	CPUThreshold    float64 `mapstructure:"cpu_threshold"`
	MemoryThreshold float64 `mapstructure:"memory_threshold"`
	MonitorInterval int     `mapstructure:"monitor_interval"`
	SuspiciousNames string  `mapstructure:"suspicious_names"`
	WhitelistUsers  string  `mapstructure:"whitelist_users"`
}

// ProcessMonitor implements the scheduler.Monitor interface. It is responsible for
// monitoring running processes for high resource consumption, suspicious names,
// and other anomalies like hidden processes or unusual parent-child relationships.
type ProcessMonitor struct {
	Config            ProcessMonitorConfig
	previousProcesses map[int32]bool
}

// Name returns the unique name of the monitor.
func (pm *ProcessMonitor) Name() string {
	return "process_monitor"
}

// Run is the main entry point for the monitor's execution loop. It calls
// various sub-functions to perform specific checks.
func (pm *ProcessMonitor) Run(ctx context.Context) {
	log.Info().Msg("Running Process Monitor...")

	// Initialize previousProcesses on first run
	if pm.previousProcesses == nil {
		pm.previousProcesses = make(map[int32]bool)
		procs, err := process.Processes()
		if err != nil {
			log.Error().Err(err).Msg("Failed to get initial process list for creation monitoring.")
			return
		}
		for _, p := range procs {
			pm.previousProcesses[p.Pid] = true
		}
	}

	pm.monitorResourceUsage()
	pm.detectSuspiciousProcesses()
	pm.monitorProcessCreation()
	pm.detectHiddenProcesses()
	pm.monitorProcessTree()
	pm.monitorDetachedProcesses()
	pm.monitorSystemdServices()

	log.Info().Msg("Process Monitor finished.")
}

// monitorResourceUsage monitors resource-intensive processes.
func (pm *ProcessMonitor) monitorResourceUsage() {
	procs, err := process.Processes()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get process list for resource usage monitoring.")
		return
	}

	for _, p := range procs {
		cpuPercent, err := p.CPUPercent()
		if err != nil {
			// log.Debug().Err(err).Int32("pid", p.Pid).Msg("Failed to get CPU percent for process.")
			continue
		}
		memPercent, err := p.MemoryPercent()
		if err != nil {
			// log.Debug().Err(err).Int32("pid", p.Pid).Msg("Failed to get memory percent for process.")
			continue
		}

		if cpuPercent > pm.Config.CPUThreshold {
			name, _ := p.Name()
			cmdline, _ := p.Cmdline()
			log.Warn().
				Int32("pid", p.Pid).
				Str("name", name).
				Str("cmdline", cmdline).
				Float64("cpu_percent", cpuPercent).
				Msg("High CPU usage detected.")
		}

		if float64(memPercent) > pm.Config.MemoryThreshold {
			name, _ := p.Name()
			cmdline, _ := p.Cmdline()
			log.Warn().
				Int32("pid", p.Pid).
				Str("name", name).
				Str("cmdline", cmdline).
				Float64("memory_percent", float64(memPercent)).
				Msg("High memory usage detected.")
		}
	}
}

// detectSuspiciousProcesses detects processes with suspicious names.
func (pm *ProcessMonitor) detectSuspiciousProcesses() {
	suspiciousPatterns := strings.Split(pm.Config.SuspiciousNames, ",")
	procs, err := process.Processes()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get process list for suspicious process detection.")
		return
	}

	for _, p := range procs {
		name, _ := p.Name()
		cmdline, _ := p.Cmdline()

		for _, pattern := range suspiciousPatterns {
			if pattern == "" {
				continue
			}
			matched, err := regexp.MatchString("(?i)"+regexp.QuoteMeta(pattern), name) // Case-insensitive match
			if err != nil {
				log.Error().Err(err).Str("pattern", pattern).Msg("Invalid regex pattern.")
				continue
			}
			if matched {
				log.Error().
					Int32("pid", p.Pid).
					Str("name", name).
					Str("cmdline", cmdline).
					Str("pattern", pattern).
					Msg("Suspicious process name detected.")
			}

			matched, err = regexp.MatchString("(?i)"+regexp.QuoteMeta(pattern), cmdline) // Case-insensitive match
			if err != nil {
				log.Error().Err(err).Str("pattern", pattern).Msg("Invalid regex pattern.")
				continue
			}
			if matched {
				log.Error().
					Int32("pid", p.Pid).
					Str("name", name).
					Str("cmdline", cmdline).
					Str("pattern", pattern).
					Msg("Suspicious process command line detected.")
			}
		}
	}
}

// monitorProcessCreation detects newly created processes.
func (pm *ProcessMonitor) monitorProcessCreation() {
	currentProcesses := make(map[int32]bool)
	procs, err := process.Processes()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get current process list for creation monitoring.")
		return
	}

	for _, p := range procs {
		currentProcesses[p.Pid] = true
		if _, exists := pm.previousProcesses[p.Pid]; !exists {
			name, _ := p.Name()
			cmdline, _ := p.Cmdline()
			username, _ := p.Username()
			log.Info().
				Int32("pid", p.Pid).
				Str("name", name).
				Str("cmdline", cmdline).
				Str("username", username).
				Msg("New process detected.")
		}
	}
	pm.previousProcesses = currentProcesses // Update for next iteration
}

// detectHiddenProcesses detects processes that are in /proc but not shown by ps (gopsutil).
func (pm *ProcessMonitor) detectHiddenProcesses() {
	procDirs, err := ioutil.ReadDir("/proc")
	if err != nil {
		log.Error().Err(err).Msg("Failed to read /proc directory for hidden process detection.")
		return
	}

	procPIDs := make(map[int32]bool)
	for _, dir := range procDirs {
		if dir.IsDir() {
			pid, err := strconv.ParseInt(dir.Name(), 10, 32)
			if err == nil {
				procPIDs[int32(pid)] = true
			}
		}
	}

	gopsutilPIDs := make(map[int32]bool)
	procs, err := process.Processes()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get process list from gopsutil for hidden process detection.")
		return
	}
	for _, p := range procs {
		gopsutilPIDs[p.Pid] = true
	}

	hiddenCount := 0
	for pid := range procPIDs {
		if _, exists := gopsutilPIDs[pid]; !exists {
			hiddenCount++
			// Try to get command name from /proc/<pid>/comm
			commPath := fmt.Sprintf("/proc/%d/comm", pid)
			comm, readErr := ioutil.ReadFile(commPath)
			commStr := "unknown"
			if readErr == nil {
				commStr = strings.TrimSpace(string(comm))
			}
			log.Warn().
				Int32("pid", pid).
				Str("comm", commStr).
				Msg("Possible hidden process detected (in /proc but not by gopsutil).")
		}
	}

	if hiddenCount > 0 {
		log.Warn().Int("hidden_count", hiddenCount).Msg("Summary: Hidden processes detected.")
	}
}

// monitorProcessTree monitors unusual parent-child relationships.
func (pm *ProcessMonitor) monitorProcessTree() {
	procs, err := process.Processes()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get process list for process tree monitoring.")
		return
	}

	for _, p := range procs {
		ppid, err := p.Ppid()
		if err != nil {
			continue // Cannot get parent, skip
		}
		name, _ := p.Name()
		cmdline, _ := p.Cmdline()

		// Check for shells/interpreters with init (PID 1) as parent
		if ppid == 1 {
			isSuspicious := false
			if strings.Contains(name, "sh") || strings.Contains(name, "bash") || strings.Contains(name, "dash") {
				isSuspicious = true
			} else if strings.Contains(name, "python") || strings.Contains(name, "perl") || strings.Contains(name, "ruby") {
				isSuspicious = true
			}

			if isSuspicious {
				log.Warn().
					Int32("pid", p.Pid).
					Int32("ppid", ppid).
					Str("name", name).
					Str("cmdline", cmdline).
					Msg("Suspicious process with PID 1 as parent detected (shell/interpreter).")
			}
		}
	}
}

// monitorDetachedProcesses checks for processes without a TTY.
func (pm *ProcessMonitor) monitorDetachedProcesses() {
	whitelistUsers := strings.Split(pm.Config.WhitelistUsers, ",")
	procs, err := process.Processes()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get process list for detached process monitoring.")
		return
	}

	for _, p := range procs {
		tty, err := p.Terminal()
		if err != nil {
			// log.Debug().Err(err).Int32("pid", p.Pid).Msg("Failed to get TTY for process.")
			continue
		}

		if tty == "" { // No TTY
			username, err := p.Username()
			if err != nil {
				// log.Debug().Err(err).Int32("pid", p.Pid).Msg("Failed to get username for process.")
				continue
			}

			isWhitelisted := false
			for _, wu := range whitelistUsers {
				if wu == username {
					isWhitelisted = true
					break
				}
			}

			if !isWhitelisted {
				name, _ := p.Name()
				cmdline, _ := p.Cmdline()
				log.Info().
					Int32("pid", p.Pid).
					Str("username", username).
					Str("name", name).
					Str("cmdline", cmdline).
					Msg("Detached process detected from non-whitelisted user.")
			}
		}
	}
}

// monitorSystemdServices monitors systemd services for failures or unexpected masks.
func (pm *ProcessMonitor) monitorSystemdServices() {
	// Check failed services
	cmdFailed := exec.Command("systemctl", "list-units", "--failed", "--no-legend")
	outputFailed, err := cmdFailed.Output()
	if err != nil {
		log.Error().Err(err).Msg("Failed to run 'systemctl list-units --failed'.")
	} else {
		failedServices := strings.Split(strings.TrimSpace(string(outputFailed)), "\n")
		if len(failedServices) > 0 && failedServices[0] != "" {
			log.Warn().Int("count", len(failedServices)).Msg("Failed systemd services detected.")
			for _, service := range failedServices {
				log.Warn().Str("service", service).Msg("Systemd service failed.")
			}
		}
	}

	// Check masked services (excluding systemd internal ones)
	cmdMasked := exec.Command("systemctl", "list-unit-files", "--state=masked", "--no-legend")
	outputMasked, err := cmdMasked.Output()
	if err != nil {
		log.Error().Err(err).Msg("Failed to run 'systemctl list-unit-files --state=masked'.")
	} else {
		maskedServices := []string{}
		for _, line := range strings.Split(strings.TrimSpace(string(outputMasked)), "\n") {
			if !strings.Contains(line, "systemd-") && strings.TrimSpace(line) != "" {
				maskedServices = append(maskedServices, line)
			}
		}
		if len(maskedServices) > 0 {
			log.Info().Int("count", len(maskedServices)).Msg("Masked systemd services found (excluding systemd internal ones).")
			for _, service := range maskedServices {
				log.Info().Str("service", service).Msg("Systemd service masked.")
			}
		}
	}
}