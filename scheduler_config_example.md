# Scheduler - Comprehensive Configuration Guide

## Overview

The Scheduler is the orchestration engine of the Lucid Vigil security system. It provides centralized monitor management, lifecycle control, and operational visibility across all security monitors. The scheduler handles:

- **Monitor registration and configuration** with automatic capability detection
- **Lifecycle management** with graceful startup, shutdown, and restart capabilities
- **Real-time status monitoring** with comprehensive health and performance metrics
- **Event-driven operations** with integrated event bus publishing
- **Error handling and recovery** with structured error reporting
- **Action coordination** through integrated action dispatcher
- **Production-ready operations** with thread safety and resource management

## Configuration Structure

```yaml
scheduler:
  enabled: true
  
  # Core Scheduler Configuration
  startup_timeout: "60s"                     # Maximum time to wait for all monitors to start
  shutdown_timeout: "30s"                    # Maximum time to wait for graceful shutdown
  monitor_restart_delay: "5s"                # Delay before restarting failed monitors
  max_restart_attempts: 3                    # Maximum restart attempts per monitor
  
  # Health Check Configuration
  health_check_enabled: true                 # Enable periodic health checks
  health_check_interval: "60s"               # How often to check monitor health
  unhealthy_threshold: 3                     # Consecutive failures before marking unhealthy
  
  # Event Publishing Configuration
  event_publishing_enabled: true             # Enable scheduler event publishing
  event_buffer_size: 1000                    # Event buffer size for batching
  
  # Performance Monitoring
  performance_monitoring_enabled: true       # Enable performance metrics collection
  metrics_collection_interval: "30s"         # How often to collect metrics
  slow_execution_threshold: "30s"            # Threshold for slow monitor execution
  
  # Default Monitor Configuration
  default_monitor_settings:
    timeout: "300s"                          # Default monitor execution timeout
    max_memory_mb: 512                       # Default memory limit per monitor
    retry_attempts: 2                        # Default retry attempts for failed executions
    
  # Advanced Configuration
  concurrent_monitors: 0                     # 0 = unlimited, >0 = limit concurrent monitors
  resource_monitoring_enabled: true         # Monitor resource usage
  debug_mode: false                         # Enable debug logging and detailed metrics

# Monitor-specific configurations
monitors:
  # Enhanced Sentry Monitor
  enhanced_sentry:
    enabled: true
    interval: "30s"
    timeout: "60s"
    priority: 1                             # Higher priority monitors start first
    dependencies: []                        # No dependencies
    restart_policy: "always"                # "always", "on_failure", "never"
    max_memory_mb: 256
    actions:
      - "isolate_threat"
      - "send_alert"
      - "update_threat_intel"
    config:
      response_mode: "respond"
      response_threshold: "medium"
      patrol_interval: "30s"
      high_value_paths:
        - "/etc/passwd"
        - "/etc/shadow"
        - "/root/.ssh"
  
  # Enhanced Analyzer Monitor  
  enhanced_analyzer:
    enabled: true
    interval: "60s"
    timeout: "120s"
    priority: 2
    dependencies: ["enhanced_sentry"]        # Wait for sentry to start first
    restart_policy: "on_failure"
    max_memory_mb: 1024                     # Analyzer needs more memory
    actions:
      - "generate_report"
      - "update_threat_model"
      - "request_containment"
    config:
      analysis_interval: "60s"
      threat_score_threshold: 5.0
      pattern_learning_enabled: true
      anomaly_detection_enabled: true
      
  # Custom Monitor Example
  network_monitor:
    enabled: false                          # Disabled by default
    interval: "45s"
    timeout: "90s"
    priority: 3
    dependencies: []
    restart_policy: "on_failure"
    max_memory_mb: 128
    actions:
      - "block_suspicious_connection"
      - "log_network_event"
    config:
      interface: "eth0"
      suspicious_ports: [22, 3389, 5900]
      connection_threshold: 100
```

## Core Scheduler Features

### 1. Monitor Lifecycle Management

Complete control over monitor startup, execution, and shutdown:

```yaml
# Startup sequence based on priority and dependencies
startup_timeout: "60s"
monitor_restart_delay: "5s"
max_restart_attempts: 3

# The scheduler handles:
# - Priority-based startup (priority 1 monitors start first)
# - Dependency resolution (monitors wait for dependencies)
# - Graceful shutdown with timeout handling
# - Automatic restart on failure (based on restart_policy)
# - Resource limit enforcement
```

### 2. Health Monitoring and Recovery

Continuous health assessment with automatic recovery:

```yaml
health_check_enabled: true
health_check_interval: "60s"
unhealthy_threshold: 3

# Health indicators monitored:
# - Monitor execution success rate
# - Response time trends
# - Memory and CPU usage
# - Error frequency and patterns
# - Event publishing success
# - Action execution success

# Recovery strategies:
# - Automatic restart for transient failures
# - Resource limit adjustments
# - Graceful degradation for persistent issues
# - Administrator notification for critical failures
```

### 3. Event-Driven Operations

Comprehensive event publishing for operational visibility:

```yaml
event_publishing_enabled: true
event_buffer_size: 1000

# Events published by scheduler:
# - scheduler_started: System startup
# - scheduler_stopped: System shutdown
# - monitor_registered: Monitor added to scheduler
# - monitor_started: Monitor execution began
# - monitor_stopped: Monitor execution stopped
# - monitor_failed: Monitor execution failed
# - monitor_restarted: Monitor recovered from failure
# - monitor_unhealthy: Monitor marked as unhealthy
# - monitor_recovered: Monitor returned to healthy state
# - resource_limit_exceeded: Monitor exceeded resource limits
# - dependency_failure: Monitor dependency failed
```

### 4. Performance Monitoring

Real-time performance metrics and optimization insights:

```yaml
performance_monitoring_enabled: true
metrics_collection_interval: "30s"
slow_execution_threshold: "30s"

# Performance metrics collected:
# - Monitor execution duration
# - Memory usage per monitor
# - CPU utilization trends
# - Event publishing latency
# - Action execution timing
# - Queue depths and processing rates
# - Error rates and patterns
```

## Environment-Specific Configurations

### High-Security Production Environment

```yaml
scheduler:
  enabled: true
  
  # Aggressive monitoring and recovery
  startup_timeout: "30s"
  shutdown_timeout: "15s"
  monitor_restart_delay: "2s"
  max_restart_attempts: 5
  
  # Frequent health checks
  health_check_enabled: true
  health_check_interval: "30s"
  unhealthy_threshold: 2
  
  # Enhanced performance monitoring
  performance_monitoring_enabled: true
  metrics_collection_interval: "15s"
  slow_execution_threshold: "15s"
  
  # Resource constraints
  concurrent_monitors: 10
  default_monitor_settings:
    timeout: "120s"
    max_memory_mb: 256
    retry_attempts: 3
  
  # Full event tracking
  event_publishing_enabled: true
  event_buffer_size: 2000

monitors:
  enhanced_sentry:
    enabled: true
    interval: "15s"                         # More frequent monitoring
    priority: 1
    restart_policy: "always"
    max_memory_mb: 512
    
  enhanced_analyzer:
    enabled: true
    interval: "30s"                         # Faster analysis
    priority: 2
    restart_policy: "always"
    max_memory_mb: 2048                     # More memory for complex analysis
```

### Development Environment

```yaml
scheduler:
  enabled: true
  
  # Relaxed timeouts for debugging
  startup_timeout: "120s"
  shutdown_timeout: "60s"
  monitor_restart_delay: "10s"
  max_restart_attempts: 1                   # Don't auto-restart for debugging
  
  # Basic health monitoring
  health_check_enabled: true
  health_check_interval: "120s"
  unhealthy_threshold: 5
  
  # Debug-friendly settings
  debug_mode: true
  resource_monitoring_enabled: true
  concurrent_monitors: 3                    # Limit for development machine
  
  # Reduced event publishing
  event_publishing_enabled: true
  event_buffer_size: 100

monitors:
  enhanced_sentry:
    enabled: true
    interval: "60s"                         # Less frequent for dev
    priority: 1
    restart_policy: "never"                 # Manual restart for debugging
    max_memory_mb: 128
    
  enhanced_analyzer:
    enabled: false                          # Often disabled in dev
```

### Enterprise Production Environment

```yaml
scheduler:
  enabled: true
  
  # Enterprise-scale settings
  startup_timeout: "180s"                   # More monitors need more time
  shutdown_timeout: "60s"
  monitor_restart_delay: "10s"
  max_restart_attempts: 3
  
  # Comprehensive monitoring
  health_check_enabled: true
  health_check_interval: "45s"
  unhealthy_threshold: 3
  
  # Full performance tracking
  performance_monitoring_enabled: true
  metrics_collection_interval: "30s"
  slow_execution_threshold: "60s"
  
  # Enterprise resource management
  concurrent_monitors: 50                   # Higher limits for enterprise hardware
  resource_monitoring_enabled: true
  
  # High-volume event handling
  event_publishing_enabled: true
  event_buffer_size: 5000

monitors:
  # Multiple sentry instances for different zones
  sentry_dmz:
    enabled: true
    interval: "30s"
    priority: 1
    restart_policy: "always"
    
  sentry_internal:
    enabled: true
    interval: "45s"
    priority: 1
    restart_policy: "always"
    
  sentry_database:
    enabled: true
    interval: "15s"                         # Critical systems monitored more frequently
    priority: 1
    restart_policy: "always"
    
  # Centralized analyzer
  master_analyzer:
    enabled: true
    interval: "120s"                        # Less frequent but more comprehensive
    priority: 3
    restart_policy: "always"
    max_memory_mb: 4096                     # Large memory for enterprise analysis
    dependencies: ["sentry_dmz", "sentry_internal", "sentry_database"]
```

## Integration with Lucid Vigil Components

### Event Bus Integration

The scheduler publishes operational events to the event bus:

```yaml
# Event types published:
events.EventSystemStatus:
  - source: "scheduler"
  - targets: ["system", "monitor_name"]
  - severities: ["info", "warning", "error", "critical"]
  - descriptions: [
      "Scheduler started successfully",
      "Monitor 'enhanced_sentry' registered", 
      "Monitor 'enhanced_analyzer' failed to start",
      "System shutdown initiated"
    ]

events.EventSystemError:
  - source: "scheduler" 
  - targets: ["monitor_name", "system"]
  - severities: ["medium", "high", "critical"]
  - descriptions: [
      "Monitor 'network_monitor' exceeded memory limit",
      "Failed to restart monitor after 3 attempts",
      "Scheduler dependency resolution failed"
    ]
```

### Action Dispatcher Integration

Coordinates actions across monitors and responds to system events:

```yaml
# Built-in scheduler actions:
restart_monitor:
  description: "Restart a specific monitor"
  parameters: ["monitor_name"]
  
stop_monitor:
  description: "Stop a specific monitor"
  parameters: ["monitor_name"]
  
start_monitor:
  description: "Start a specific monitor"  
  parameters: ["monitor_name"]
  
emergency_shutdown:
  description: "Emergency shutdown of all monitors"
  parameters: ["reason"]
  
adjust_monitor_interval:
  description: "Dynamically adjust monitor execution interval"
  parameters: ["monitor_name", "new_interval"]
```

### Error Handler Integration

Structured error handling with escalation and recovery:

```yaml
# Error categories handled:
monitor_execution_error:
  severity: "medium"
  recovery_actions: ["restart_monitor", "adjust_resources"]
  
dependency_failure:
  severity: "high"
  recovery_actions: ["restart_dependencies", "notify_admin"]
  
resource_exhaustion:
  severity: "critical"
  recovery_actions: ["emergency_shutdown", "alert_operations"]
  
configuration_error:
  severity: "high"
  recovery_actions: ["stop_monitor", "notify_admin", "log_configuration"]
```

## API Endpoints and Management

### Status and Control API

The scheduler exposes these management interfaces:

```go
// GET /scheduler/status
{
  "running": true,
  "uptime": "2h15m30s",
  "monitors_total": 3,
  "monitors_running": 3,
  "monitors_failed": 0,
  "last_health_check": "2025-08-21T10:30:00Z",
  "performance_summary": {
    "avg_execution_time": "1.2s",
    "total_events_published": 1247,
    "total_actions_executed": 89
  }
}

// GET /scheduler/monitors
[
  {
    "name": "enhanced_sentry",
    "class": "sentry", 
    "enabled": true,
    "status": "running",
    "last_run": "2025-08-21T10:29:45Z",
    "next_run": "2025-08-21T10:30:15Z",
    "interval": "30s",
    "events_raised": 45,
    "last_error": null,
    "capabilities": ["real_time", "automated_response"],
    "metrics": {
      "execution_count": 120,
      "avg_duration": "0.8s",
      "memory_usage_mb": 128
    }
  }
]

// POST /scheduler/monitors/{name}/restart
{
  "action": "restart",
  "monitor_name": "enhanced_analyzer",
  "timestamp": "2025-08-21T10:30:00Z",
  "status": "success"
}

// POST /scheduler/shutdown
{
  "action": "shutdown",
  "timeout": "30s",
  "force": false
}
```

### Configuration Management

Dynamic configuration updates without restart:

```yaml
# Runtime configuration changes:
# - Monitor interval adjustments
# - Resource limit modifications  
# - Enable/disable monitors
# - Update monitor configurations
# - Modify health check parameters

# Configuration validation ensures:
# - Dependency consistency
# - Resource limit validity
# - Action availability
# - Event bus connectivity
```

## Monitoring and Observability

### Key Metrics to Monitor

```yaml
# System-level metrics:
scheduler_uptime_seconds
scheduler_monitors_total{status="running|stopped|failed"}
scheduler_restarts_total{monitor="name", reason="failure|manual|config"}
scheduler_events_published_total{type="system|monitor|error"}

# Performance metrics:
scheduler_monitor_execution_duration_seconds{monitor="name"}
scheduler_monitor_memory_usage_bytes{monitor="name"} 
scheduler_health_check_duration_seconds
scheduler_action_execution_duration_seconds{action="name"}

# Error metrics:
scheduler_monitor_failures_total{monitor="name", error_type="timeout|memory|dependency"}
scheduler_dependency_failures_total{monitor="name", dependency="name"}
scheduler_event_publishing_failures_total
```

### Health Check Indicators

```yaml
# Green (Healthy):
- All monitors running within resource limits
- Event publishing latency < 100ms
- No failed restarts in last hour
- Health check success rate > 99%

# Yellow (Warning):  
- 1-2 monitor restarts in last hour
- Event publishing latency 100-500ms
- Memory usage > 80% of limits
- Health check success rate 95-99%

# Orange (Degraded):
- Multiple monitor failures
- Event publishing latency 500ms-2s  
- Memory usage > 90% of limits
- Health check success rate 90-95%

# Red (Critical):
- Scheduler unable to start monitors
- Event publishing failures > 5%
- Resource exhaustion
- Health check success rate < 90%
```

## Troubleshooting

### Common Issues and Solutions

1. **Monitors failing to start**
   ```yaml
   # Check logs for:
   - Configuration validation errors
   - Dependency resolution failures
   - Resource limit conflicts
   - Permission issues
   
   # Solutions:
   - Verify monitor configurations
   - Check dependency ordering
   - Increase resource limits
   - Validate file permissions
   ```

2. **High memory usage**
   ```yaml
   # Investigate:
   - Monitor memory limits vs actual usage
   - Memory leak patterns in logs
   - Event buffer sizes
   - Metric collection frequency
   
   # Solutions:
   - Reduce monitor memory limits
   - Adjust metric collection intervals
   - Optimize monitor implementations
   - Increase system memory
   ```

3. **Slow monitor execution**
   ```yaml
   # Analyze:
   - Monitor execution duration trends
   - Resource contention patterns
   - Concurrent execution limits
   - I/O bottlenecks
   
   # Solutions:
   - Increase execution timeouts
   - Reduce concurrent monitor limits
   - Optimize monitor algorithms
   - Add SSD storage for better I/O
   ```

### Debug Configuration

```yaml
scheduler:
  enabled: true
  debug_mode: true                        # Enable verbose logging
  
  # Faster intervals for testing
  health_check_interval: "10s"
  metrics_collection_interval: "5s"
  
  # Relaxed limits for debugging
  startup_timeout: "300s"
  shutdown_timeout: "120s"
  max_restart_attempts: 0                 # Disable auto-restart for debugging
  
  # Enhanced monitoring
  resource_monitoring_enabled: true
  performance_monitoring_enabled: true

monitors:
  test_monitor:
    enabled: true
    interval: "5s"                        # Fast execution for testing
    timeout: "30s"
    restart_policy: "never"               # Manual control during debugging
    max_memory_mb: 64
    config:
      debug: true
```

### Performance Tuning

```yaml
# For high-throughput environments:
scheduler:
  concurrent_monitors: 20                 # Allow more parallel execution
  event_buffer_size: 10000               # Larger event buffer
  metrics_collection_interval: "60s"      # Less frequent metrics collection
  
  default_monitor_settings:
    timeout: "60s"                        # Shorter timeouts
    max_memory_mb: 256                    # Standardized memory limits
    
# For resource-constrained environments:
scheduler:
  concurrent_monitors: 3                  # Limit parallel execution
  event_buffer_size: 100                  # Smaller buffer
  performance_monitoring_enabled: false   # Reduce overhead
  
  default_monitor_settings:
    timeout: "300s"                       # Longer timeouts
    max_memory_mb: 128                    # Lower memory limits
```

## Security Considerations

### Access Control and Authentication

```yaml
# The scheduler enforces security through:
# - API authentication for management endpoints
# - Role-based access control for monitor operations
# - Audit logging of all configuration changes
# - Encrypted communication with event bus
# - Secure credential management for external integrations
```

### Operational Security

```yaml
# Security best practices:
# - Monitor configurations stored encrypted at rest
# - API keys and credentials managed through secrets management
# - All scheduler operations logged for audit trail
# - Resource limits prevent denial-of-service attacks
# - Event publishing includes security context
# - Failed authentication attempts trigger security events
```

## Compliance and Reporting

### Compliance Framework Support

The scheduler supports compliance requirements through:

```yaml
# SOC 2 Type II:
- Continuous monitoring and alerting
- Audit trail of all system changes
- Access control and authentication
- Incident response coordination

# ISO 27001:
- Risk-based monitoring prioritization  
- Information security event management
- Continuous improvement through metrics
- Security control effectiveness monitoring

# PCI-DSS:
- Real-time fraud detection support
- Secure configuration management
- Access logging and monitoring
- Network security monitoring coordination
```

### Automated Reporting

```yaml
# Daily operational reports:
- Monitor uptime and performance statistics
- Error rates and failure analysis  
- Resource utilization trends
- Security event summaries

# Weekly trend analysis:
- Performance optimization recommendations
- Capacity planning insights
- Security posture assessments
- Compliance status reports

# Monthly executive summaries:
- System reliability metrics
- Security incident statistics
- Operational efficiency analysis
- Budget and resource recommendations
```

The Enhanced Scheduler serves as the central nervous system of the Lucid Vigil security platform, providing enterprise-grade orchestration, monitoring, and operational control for all security monitors while maintaining the flexibility to scale from small deployments to large enterprise environments.