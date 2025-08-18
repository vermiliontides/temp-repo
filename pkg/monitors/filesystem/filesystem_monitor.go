package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kali-security-monitoring/sentinel/pkg/monitors/base"
	"github.com/kali-security-monitoring/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
)

// FilesystemMonitorConfig holds configuration for the FilesystemMonitor.
// It defines paths to watch, paths to exclude, and settings for various checks.
type FilesystemMonitorConfig struct {
	CriticalPaths      string `mapstructure:"critical_paths"`
	ExcludePaths       string `mapstructure:"exclude_paths"`
	SuidCheckInterval  int    `mapstructure:"suid_check_interval"`
	MonitorHiddenFiles bool   `mapstructure:"monitor_hidden_files"`
	AlertOnSuidChanges bool   `mapstructure:"alert_on_suid_changes"`
	SuidBaselineFile   string `mapstructure:"suid_baseline_file"`
	ConfigBaselineDir  string `mapstructure:"config_baseline_dir"`
}

// FilesystemMonitor implements the scheduler.Monitor interface. It is responsible for
// monitoring filesystem events in real-time (using fsnotify) and running periodic
// checks for things like SUID/SGID binaries and critical file integrity.
type FilesystemMonitor struct {
	*base.BaseMonitor
	config *FilesystemMonitorConfig
}

// NewFilesystemMonitor creates a new FilesystemMonitor instance.
func NewFilesystemMonitor(logger zerolog.Logger) scheduler.Monitor {
	return &FilesystemMonitor{
		BaseMonitor: base.NewBaseMonitor("filesystem_monitor", logger),
		config:      &FilesystemMonitorConfig{},
	}
}

// Run is the main entry point for the monitor. It sets up the filesystem watcher
// and starts a ticker for periodic checks.
func (fm *FilesystemMonitor) Run(ctx context.Context) {
	fm.LogEvent(zerolog.InfoLevel, "Running Filesystem Monitor...")

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fm.LogEvent(zerolog.ErrorLevel, "Failed to create fsnotify watcher.")
		return
	}
	defer watcher.Close()

	// Add critical paths to watcher
	paths := strings.Fields(fm.config.CriticalPaths)
	for _, path := range paths {
		err = watcher.Add(path)
		if err != nil {
			fm.LogEvent(zerolog.ErrorLevel, "Failed to add path to watcher.")
			continue
		}
		fm.LogEvent(zerolog.InfoLevel, "Monitoring filesystem path.")
	}

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				fm.handleFilesystemEvent(event)
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fm.LogEvent(zerolog.ErrorLevel, "Filesystem watcher error.")
			case <-ctx.Done():
				done <- true
				return
			}
		}
	}()

	// Placeholder for periodic checks
	go func() {
		ticker := time.NewTicker(time.Duration(fm.config.SuidCheckInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fm.LogEvent(zerolog.InfoLevel, "Running periodic filesystem checks...")
				fm.monitorSuidFiles()
				fm.monitorConfigFiles()
				fm.checkRootkitArtifacts()
				fm.monitorDiskUsage()
			case <-ctx.Done():
				return
			}
		}
	}()

	<-done
	fm.LogEvent(zerolog.InfoLevel, "Filesystem Monitor finished.")
}

// handleFilesystemEvent processes a single fsnotify event.
func (fm *FilesystemMonitor) handleFilesystemEvent(event fsnotify.Event) {
	// Skip temporary files and common noise to reduce false positives
	if strings.HasSuffix(event.Name, ".tmp") ||
		strings.HasSuffix(event.Name, ".swp") ||
		strings.HasSuffix(event.Name, "~") ||
		strings.HasPrefix(event.Name, ".#") ||
		strings.HasSuffix(event.Name, ".log") {
		return
	}

	// Check if the path is in the exclude list
	excludePaths := strings.Fields(fm.config.ExcludePaths)
	for _, excludePath := range excludePaths {
		if strings.HasPrefix(event.Name, excludePath) {
			fm.LogEvent(zerolog.DebugLevel, "Excluded path, skipping event.")
			return
		}
	}

	fm.LogEvent(zerolog.InfoLevel).Str("event", event.Op.String()).Str("file", event.Name).Msg("Filesystem event detected.")

	switch {
	case event.Op&fsnotify.Create == fsnotify.Create:
		fm.LogEvent(zerolog.InfoLevel, "File created.").Str("file_path", event.Name)
		fm.checkNewFile(event.Name)
	case event.Op&fsnotify.Remove == fsnotify.Remove:
		fm.LogEvent(zerolog.WarnLevel, "File deleted.").Str("file_path", event.Name)
	case event.Op&fsnotify.Write == fsnotify.Write:
		fm.LogEvent(zerolog.InfoLevel, "File modified.").Str("file_path", event.Name)
		// TODO: Implement checkModifiedFile(event.Name) - for critical files
	case event.Op&fsnotify.Chmod == fsnotify.Chmod:
		fm.LogEvent(zerolog.InfoLevel, "Permissions changed.").Str("file_path", event.Name)
		fm.checkPermissionChange(event.Name)
	case event.Op&fsnotify.Rename == fsnotify.Rename:
		fm.LogEvent(zerolog.WarnLevel, "File renamed/moved.").Str("file_path", event.Name)
	}
}

// checkNewFile checks newly created files for suspicious characteristics.
func (fm *FilesystemMonitor) checkNewFile(filePath string) {
	info, err := os.Stat(filePath)
	if err != nil {
		fm.LogEvent(zerolog.DebugLevel, "Could not stat new file.").Err(err).Str("file_path", filePath)
		return
	}

	if info.IsDir() {
		return // Skip directories for now
	}

	// Check if file is executable
	if info.Mode().IsRegular() && (info.Mode().Perm()&0111) != 0 {
		fm.LogEvent(zerolog.WarnLevel, "New executable file detected.").Str("file_path", filePath)

		// Check if it's SUID/SGID
		if (info.Mode()&os.ModeSetuid != 0) || (info.Mode()&os.ModeSetgid != 0) {
			fm.LogEvent(zerolog.ErrorLevel, "New SUID/SGID file created.").Str("file_path", filePath)
		}
	}

	// Check for hidden files in unusual locations
	if fm.config.MonitorHiddenFiles && strings.HasPrefix(filepath.Base(filePath), ".") {
		if !strings.HasPrefix(filePath, "/home/") {
			fm.LogEvent(zerolog.WarnLevel, "Hidden file created outside home directory.").Str("file_path", filePath)
		}
	}

	// Check file content for suspicious patterns (e.g., shell commands, network tools)
	if info.Mode().IsRegular() {
		content, err := os.ReadFile(filePath)
		if err != nil {
			fm.LogEvent(zerolog.DebugLevel, "Could not read file content for suspicious pattern check.").Err(err).Str("file_path", filePath)
			return
		}
		// Example patterns: nc -l, /bin/sh, python socket, perl socket, wget, curl
		suspiciousContentPatterns := []string{
			"nc -l", "/bin/sh", "python.*socket", "perl.*socket", "wget", "curl",
		}
		for _, pattern := range suspiciousContentPatterns {
			if matched, _ := regexp.MatchString(pattern, string(content)); matched {
				fm.LogEvent(zerolog.ErrorLevel, "Suspicious content detected in new file.").Str("file_path", filePath).Str("pattern", pattern)
				break
			}
		}
	}
}

// checkPermissionChange checks for suspicious permission changes.
func (fm *FilesystemMonitor) checkPermissionChange(filePath string) {
	info, err := os.Stat(filePath)
	if err != nil {
		fm.LogEvent(zerolog.DebugLevel, "Could not stat file for permission change check.").Err(err).Str("file_path", filePath)
		return
	}

	// Check for world-writable files
	perm := info.Mode().Perm()
	if (perm&0002) != 0 {
		fm.LogEvent(zerolog.WarnLevel, "World-writable file detected.").Str("file_path", filePath).Str("permissions", perm.String())
	}

	// Check for SUID/SGID changes
	if fm.config.AlertOnSuidChanges && ((info.Mode()&os.ModeSetuid != 0) || (info.Mode()&os.ModeSetgid != 0)) {
		fm.LogEvent(zerolog.WarnLevel, "SUID/SGID permissions detected.").Str("file_path", filePath).Str("permissions", perm.String())
	}

	// Check for files owned by unexpected users in critical directories
	// This requires getting file owner, which is OS-specific and not directly in os.FileInfo
	// For Linux, we can use syscall.Stat_t to get uid/gid
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := stat.Uid
		gid := stat.Gid

		// Example: Check if owned by nobody/www-data/apache in critical dirs
		if (uid == 65534 || gid == 65534) && (strings.HasPrefix(filePath, "/bin/") || strings.HasPrefix(filePath, "/sbin/") || strings.HasPrefix(filePath, "/usr/bin/") || strings.HasPrefix(filePath, "/usr/sbin/")) {
			fm.LogEvent(zerolog.ErrorLevel, "Critical binary owned by unexpected service user.").Str("file_path", filePath).Uint32("uid", uid).Uint32("gid", gid)
		}
	}
}

// monitorSuidFiles monitors SUID/SGID files for changes from a baseline.
func (fm *FilesystemMonitor) monitorSuidFiles() {
	cmd := exec.Command("find", "/", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print")
	output, err := cmd.Output()
	if err != nil {
		fm.LogEvent(zerolog.ErrorLevel, "Failed to find SUID/SGID files.").Err(err)
		return
	}

	currentSuidFiles := strings.Split(strings.TrimSpace(string(output)), "\n")
	sort.Strings(currentSuidFiles)

	baselineContent, err := os.ReadFile(fm.config.SuidBaselineFile)
	if os.IsNotExist(err) {
		// Baseline doesn't exist, create it
		err = os.WriteFile(fm.config.SuidBaselineFile, []byte(strings.Join(currentSuidFiles, "\n")), 0644)
		if err != nil {
			fm.LogEvent(zerolog.ErrorLevel, "Failed to create SUID/SGID baseline file.").Err(err)
			return
		}
		fm.LogEvent(zerolog.InfoLevel, "Created SUID/SGID baseline.").Int("count", len(currentSuidFiles))
		return
	} else if err != nil {
		fm.LogEvent(zerolog.ErrorLevel, "Failed to read SUID/SGID baseline file.").Err(err)
		return
	}

	baselineSuidFiles := strings.Split(strings.TrimSpace(string(baselineContent)), "\n")
	sort.Strings(baselineSuidFiles)

	// Find new SUID/SGID files
	newSuid := difference(currentSuidFiles, baselineSuidFiles)
	if len(newSuid) > 0 {
		fm.LogEvent(zerolog.WarnLevel, "New SUID/SGID files detected.").Strs("files", newSuid)
	}

	// Find removed SUID/SGID files
	removedSuid := difference(baselineSuidFiles, currentSuidFiles)
	if len(removedSuid) > 0 {
		fm.LogEvent(zerolog.WarnLevel, "SUID/SGID files removed.").Strs("files", removedSuid)
	}

	// Update baseline
	err = os.WriteFile(fm.config.SuidBaselineFile, []byte(strings.Join(currentSuidFiles, "\n")), 0644)
	if err != nil {
		fm.LogEvent(zerolog.ErrorLevel, "Failed to update SUID/SGID baseline file.").Err(err)
	}
}

// difference returns the elements in `a` that are not in `b`.
func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}?
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

// monitorConfigFiles monitors critical system configuration files for changes using hashes.
func (fm *FilesystemMonitor) monitorConfigFiles() {
	criticalConfigFiles := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/sudoers",
		"/etc/hosts",
		"/etc/crontab",
	}

	// Ensure baseline directory exists
	if _, err := os.Stat(fm.config.ConfigBaselineDir); os.IsNotExist(err) {
		err = os.MkdirAll(fm.config.ConfigBaselineDir, 0755)
		if err != nil {
			fm.LogEvent(zerolog.ErrorLevel, "Failed to create config baseline directory.").Err(err).Str("dir", fm.config.ConfigBaselineDir)
			return
		}
	}

	for _, file := range criticalConfigFiles {
		currentHash, err := calculateFileHash(file)
		if err != nil {
			fm.LogEvent(zerolog.ErrorLevel, "Failed to calculate hash for config file.").Err(err).Str("file", file)
			continue
		}

		baselineFile := filepath.Join(fm.config.ConfigBaselineDir, filepath.Base(file)+".hash")
		baselineHash, err := os.ReadFile(baselineFile)
		if os.IsNotExist(err) {
			// Baseline doesn't exist, create it
			err = os.WriteFile(baselineFile, []byte(currentHash), 0644)
			if err != nil {
				fm.LogEvent(zerolog.ErrorLevel, "Failed to create config baseline hash file.").Err(err).Str("file", baselineFile)
				continue
			}
			fm.LogEvent(zerolog.InfoLevel, "Created baseline hash for config file.").Str("file", file)
		} else if err != nil {
			fm.LogEvent(zerolog.ErrorLevel, "Failed to read config baseline hash file.").Err(err).Str("file", baselineFile)
			continue
		}

		if currentHash != string(baselineHash) {
			fm.LogEvent(zerolog.ErrorLevel, "Critical configuration file changed.").Str("file", file)
			// Update baseline after change
			err = os.WriteFile(baselineFile, []byte(currentHash), 0644)
			if err != nil {
				fm.LogEvent(zerolog.ErrorLevel, "Failed to update config baseline hash file after change.").Err(err).Str("file", baselineFile)
			}
		}
	}
}

// calculateFileHash calculates the SHA256 hash of a file.
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// checkRootkitArtifacts checks for common rootkit artifacts (hidden files, unusual locations).
func (fm *FilesystemMonitor) checkRootkitArtifacts() {
	rootkitFiles := []string{
		"/dev/shm/.hidden",
		"/tmp/.hidden",
		"/var/tmp/.hidden",
		"/usr/bin/..", // Example of unusual path
		"/usr/lib/.hidden",
		"/etc/.hidden",
	}

	for _, file := range rootkitFiles {
		if _, err := os.Stat(file); err == nil {
			fm.LogEvent(zerolog.ErrorLevel, "Potential rootkit artifact found.").Str("file", file)
		}
	}

	// Check for unusual files (e.g., hidden files) in system binaries directories
	systemDirs := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin"}
	for _, dir := range systemDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Continue on errors
			}
			if !info.IsDir() && strings.HasPrefix(info.Name(), ".") {
				fm.LogEvent(zerolog.WarnLevel, "Hidden file found in system directory.").Str("file", path)
			}
			return nil
		})
	}
}

// monitorDiskUsage monitors disk space and inode usage for anomalies.
func (fm *FilesystemMonitor) monitorDiskUsage() {
	// Get disk usage for root partition
	var stat syscall.Statfs_t
	err := syscall.Statfs("/", &stat)
	if err != nil {
		fm.LogEvent(zerolog.ErrorLevel, "Failed to get disk usage stats.").Err(err)
		return
	}

	all := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := all - free

	diskUsagePercent := float64(used) / float64(all) * 100
	fm.LogEvent(zerolog.InfoLevel, "Disk usage monitored.").Float64("disk_usage_percent", diskUsagePercent)

	if diskUsagePercent > 90 {
		fm.LogEvent(zerolog.WarnLevel, "High disk usage detected.").Float64("disk_usage_percent", diskUsagePercent)
	}

	// Inode usage
	var inodeStat syscall.Statfs_t
	err = syscall.Statfs("/", &inodeStat)
	if err != nil {
		fm.LogEvent(zerolog.ErrorLevel, "Failed to get inode usage stats.").Err(err)
		return
	}

	// Avoid division by zero if there are no inodes
	if inodeStat.Files == 0 {
		fm.LogEvent(zerolog.DebugLevel, "No inodes reported for root partition.")
		return
	}

	inodeUsagePercent := float64(inodeStat.Files - inodeStat.Ffree) / float64(inodeStat.Files) * 100
	fm.LogEvent(zerolog.InfoLevel, "Inode usage monitored.").Float64("inode_usage_percent", inodeUsagePercent)

	if inodeUsagePercent > 90 {
		fm.LogEvent(zerolog.WarnLevel, "High inode usage detected.").Float64("inode_usage_percent", inodeUsagePercent)
	}
}