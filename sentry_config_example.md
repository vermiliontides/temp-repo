# Sentry Monitor - Comprehensive Configuration Guide

## Overview

The Sentry Monitor integrates all security monitoring capabilities from the individual monitors into a unified, comprehensive security system. It provides:

- **High-value target protection** with integrity checking
- **Network security monitoring** for data exfiltration and suspicious connections
- **Real-time filesystem monitoring** with fsnotify integration
- **Rootkit detection** with manual checks and external tool integration
- **Firmware security monitoring** for BIOS/hardware changes
- **Comprehensive threat assessment** across all monitored components

## Configuration Structure

```yaml
monitors:
  enhanced_sentry:
    enabled: true
    
    # Core Sentry Configuration
    high_value_paths:
      - "/etc/passwd"
      - "/etc/shadow" 
      - "/etc/sudoers"
      - "/root/.ssh"
      - "/home/admin/.ssh"
      - "/var/log/auth.log"
      - "/opt/sensitive_data"
    
    critical_processes:
      - "proc:sshd"
      - "proc:nginx" 
      - "proc:mysql"
      - "proc:docker"
    
    response_mode: "respond"              # "monitor", "respond", "aggressive"
    response_threshold: "medium"          # "low", "medium", "high", "critical"
    integrity_check_mode: "hash"          # "hash", "timestamp", "both"
    patrol_interval: "30s"                # How often to run comprehensive checks
    threat_assessment_enabled: true       # Enable dynamic threat level assessment
    
    # Network Security Monitoring
    network_monitoring_enabled: true
    upload_threshold_mb: 100              # Alert on uploads larger than this
    file_sharing_domains:
      - "dropbox.com"
      - "drive.google.com"
      - "onedrive.live.com"
      - "mega.nz"
      - "wetransfer.com"
      - "sendspace.com"
    
    # Filesystem Monitoring
    realtime_watching_enabled: true       # Enable fsnotify real-time monitoring
    critical_paths: "/etc /bin /sbin /usr/bin /usr/sbin /root /home/admin"
    exclude_paths: "/tmp /var/tmp /proc /sys /dev"
    monitor_hidden_files: true            # Monitor creation of hidden files
    alert_on_suid_changes: true           # Alert on SUID/SGID permission changes
    suid_check_interval: 300              # Check SUID files every 5 minutes
    suid_baseline_file: "/var/lib/sentinel/suid_baseline.txt"
    config_baseline_dir: "/var/lib/sentinel/config_baselines"
    
    # Rootkit Detection
    rootkit_detection_enabled: true
    manual_checks_enabled: true           # Enable manual rootkit artifact checks
    chkrootkit_enabled: false            # Enable if chkrootkit is installed
    rkhunter_enabled: false              # Enable if rkhunter is installed
    
    # Firmware Monitoring
    firmware_monitoring_enabled: true    # Monitor BIOS/firmware changes
    
    # Advanced Configuration
    run_interval: 60                     # Main patrol interval in seconds
```

## Component Breakdown

### 1. High-Value Target Protection

Monitors critical files and directories for unauthorized changes:

```yaml
high_value_paths:
  # System authentication files
  - "/etc/passwd"
  - "/etc/shadow"
  - "/etc/group"
  - "/etc/sudoers"
  
  # SSH configuration and keys
  - "/etc/ssh"
  - "/root/.ssh"
  - "/home/admin/.ssh"
  
  # Critical system directories
  - "/boot"
  - "/etc/systemd"
  
  # Application-specific paths
  - "/opt/myapp/config"
  - "/var/lib/mysql"
  - "/etc/nginx"
  
  # Log files
  - "/var/log/auth.log"
  - "/var/log/secure"
```

### 2. Network Security Monitoring

Detects data exfiltration and suspicious network activity:

```yaml
network_monitoring_enabled: true
upload_threshold_mb: 50                   # Lower threshold for sensitive environments

# Expand file sharing domains based on your threat model
file_sharing_domains:
  - "dropbox.com"
  - "box.com" 
  - "drive.google.com"
  - "onedrive.live.com"
  - "icloud.com"
  - "mega.nz"
  - "wetransfer.com"
  - "sendspace.com"
  - "mediafire.com"
  - "4shared.com"
  - "rapidshare.com"
  - "uploadfiles.io"
```

### 3. Real-Time Filesystem Monitoring

Uses fsnotify for immediate detection of filesystem changes:

```yaml
realtime_watching_enabled: true

# Paths to monitor in real-time
critical_paths: "/etc /bin /sbin /usr/bin /usr/sbin /root /home/admin /opt"

# Paths to exclude from monitoring (reduces noise)
exclude_paths: "/tmp /var/tmp /proc /sys /dev /var/log"

# Detection settings
monitor_hidden_files: true
alert_on_suid_changes: true
```

### 4. Rootkit Detection

Comprehensive rootkit detection using multiple methods:

```yaml
rootkit_detection_enabled: true
manual_checks_enabled: true

# External tool integration (requires installation)
chkrootkit_enabled: true                  # Set to true if chkrootkit installed
rkhunter_enabled: true                    # Set to true if rkhunter installed
```

### 5. Firmware Monitoring

Monitors BIOS and firmware for unauthorized changes:

```yaml
firmware_monitoring_enabled: true
# No additional configuration needed - reads from /sys/class/dmi/id/
```

## Environment-Specific Configurations

### High-Security Environment

```yaml
monitors:
  enhanced_sentry:
    enabled: true
    response_mode: "aggressive"
    response_threshold: "low"
    patrol_interval: "15s"
    upload_threshold_mb: 25
    suid_check_interval: 120              # Check every 2 minutes
    integrity_check_mode: "both"          # Use both hash and timestamp
    
    # Monitor more paths
    critical_paths: "/etc /bin /sbin /usr /root /home /opt /var/lib"
    exclude_paths: "/tmp /var/tmp"        # Minimal exclusions
    
    # Enable all detection methods
    rootkit_detection_enabled: true
    manual_checks_enabled: true
    chkrootkit_enabled: true
    rkhunter_enabled: true
    firmware_monitoring_enabled: true
```

### Development Environment

```yaml
monitors:
  enhanced_sentry:
    enabled: true
    response_mode: "monitor"
    response_threshold: "medium"
    patrol_interval: "60s"
    upload_threshold_mb: 500
    
    # Focus on critical system files only
    critical_paths: "/etc /bin /sbin"
    exclude_paths: "/tmp /var/tmp /proc /sys /dev /home/dev"
    
    # Reduced monitoring to avoid development noise
    monitor_hidden_files: false
    suid_check_interval: 600              # Check every 10 minutes
    rootkit_detection_enabled: false     # May interfere with dev tools
```

### Production Server

```yaml
monitors:
  enhanced_sentry:
    enabled: true
    response_mode: "respond"
    response_threshold: "medium"
    patrol_interval: "30s"
    upload_threshold_mb: 100
    
    # Application-specific monitoring
    high_value_paths:
      - "/etc/passwd"
      - "/etc/shadow"
      - "/etc/sudoers" 
      - "/etc/nginx"
      - "/var/www"
      - "/opt/myapp"
      - "/var/lib/mysql"
    
    critical_processes:
      - "proc:nginx"
      - "proc:mysql"
      - "proc:php-fpm"
      - "proc:redis"
    
    # Full monitoring suite
    network_monitoring_enabled: true
    realtime_watching_enabled: true
    rootkit_detection_enabled: true
    firmware_monitoring_enabled: true
```

## Integration with Event System

The Enhanced Sentry Monitor publishes various event types:

### Event Types Generated

```go
// Core sentry events
events.EventFileSystemChange     // File/directory changes
events.EventThreatDetected      // Threat level changes
events.EventHighValueAccess     // High-value target access

// Network security events  
events.EventDataExfiltration    // Large uploads detected
events.EventSuspiciousNetwork   // File sharing connections

// Malware/rootkit events
events.EventMalwareDetected     // Suspicious file content
events.EventRootkitDetected     // Rootkit artifacts found

// System events
events.EventSystemAnomaly       // Disk usage, performance issues
events.EventFirmwareChange      // BIOS/firmware changes
```

### Event Severity Levels

- **critical**: System compromise, firmware changes, high-value target compromise
- **high**: SUID changes, large uploads, rootkit artifacts, integrity violations  
- **medium**: Permission changes, hidden files, file sharing connections
- **low**: Normal file operations, routine checks

## Monitoring and Alerting

### State Information Available

```go
// Access current state via monitor API
state := monitor.GetState()

// Key state fields:
state["threat_level"]                    // Current threat level (green/yellow/orange/red)
state["targets_count"]                   // Number of high-value targets
state["target_status_counts"]            // Count by status (verified/compromised/missing)
state["integrity_checks_performed"]      // Number of integrity checks run
state["integrity_violations_found"]      // Number of violations detected
state["disk_usage_percent"]             // Current disk usage
state["component_status"]               // Status of each monitoring component
```

### Metrics for Monitoring

```yaml
# Prometheus-style metrics that could be exported:
sentinel_threat_level{monitor="enhanced_sentry"}
sentinel_high_value_targets_total{monitor="enhanced_sentry"}  
sentinel_integrity_violations_total{monitor="enhanced_sentry"}
sentinel_network_uploads_suspicious_total{monitor="enhanced_sentry"}
sentinel_rootkit_artifacts_detected_total{monitor="enhanced_sentry"}
sentinel_firmware_changes_detected_total{monitor="enhanced_sentry"}
```

## Performance Considerations

### Resource Usage

- **CPU**: Moderate - periodic scans and real-time file monitoring
- **Memory**: Low-Medium - maintains baselines and file hashes in memory
- **I/O**: Medium - frequent file system checks and hash calculations
- **Network**: Low - only DNS lookups for file sharing domains

### Optimization Tips

1. **Adjust patrol intervals** based on environment needs
2. **Exclude noisy paths** from real-time monitoring  
3. **Limit high-value targets** to truly critical resources
4. **Use selective rootkit detection** - disable external tools if not needed
5. **Configure appropriate thresholds** for your network patterns

### Scaling Considerations

For large environments:

```yaml
# Distribute monitoring across multiple instances
monitors:
  enhanced_sentry_critical:
    high_value_paths: ["/etc", "/root", "/boot"]
    patrol_interval: "15s"
    
  enhanced_sentry_applications:  
    high_value_paths: ["/opt", "/var/www", "/var/lib"]
    patrol_interval: "60s"
    
  enhanced_sentry_network:
    network_monitoring_enabled: true
    # Disable other components
    rootkit_detection_enabled: false
    firmware_monitoring_enabled: false
```

## Troubleshooting

### Common Issues

1. **High CPU usage**: Reduce patrol frequency, exclude more paths
2. **False positives**: Adjust thresholds, add exclusions
3. **Missing events**: Check file permissions, verify paths exist
4. **Network monitoring not working**: Verify network interface access
5. **Rootkit tools failing**: Install chkrootkit/rkhunter or disable

### Debug Configuration

```yaml
# Enable debug logging for troubleshooting
monitors:
  enhanced_sentry:
    enabled: true
    debug: true                          # Enable verbose logging
    patrol_interval: "10s"               # Faster intervals for testing
    
    # Minimal configuration for testing
    high_value_paths: ["/tmp/test_file"]
    network_monitoring_enabled: false
    rootkit_detection_enabled: false
```

This comprehensive enhanced sentry monitor provides enterprise-grade security monitoring by integrating all the capabilities from the individual monitors into a unified, efficient system.