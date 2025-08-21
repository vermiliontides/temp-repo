# Analyzer Monitor - Comprehensive Configuration Guide

## Overview

The Analyzer Monitor is the intelligence center of the Lucid Vigil security system. It provides advanced threat analysis, pattern recognition, behavioral anomaly detection, and automated containment planning. The monitor uses machine learning and AI integration to:

- **Analyze security events** and categorize threats by sophistication, intent, and impact
- **Recognize attack patterns** and learn from historical incidents  
- **Detect behavioral anomalies** by comparing current activity with learned baselines
- **Correlate threats** across different sources and time windows
- **Generate containment strategies** with automated and manual response options
- **Provide comprehensive reporting** with risk assessments and recommendations

## Configuration Structure

```yaml
monitors:
  enhanced_analyzer:
    enabled: true
    
    # Core Analysis Configuration
    analysis_interval: "60s"                    # How often to run comprehensive analysis
    event_analysis_window: "24h"                # Time window for event analysis
    threat_score_threshold: 5.0                 # Minimum threat score to trigger analysis
    max_analysis_depth: 10                      # Maximum depth for recursive analysis
    
    # Threat Correlation Settings
    threat_correlation_enabled: true            # Enable cross-source threat correlation
    correlation_time_window: "1h"               # Time window for correlating events
    
    # Pattern Recognition Settings  
    pattern_learning_enabled: true              # Enable ML pattern recognition
    min_pattern_occurrence: 3                   # Minimum events to form a pattern
    pattern_significance_score: 6.0             # Minimum score for significant patterns
    pattern_categories:
      - "malware"
      - "intrusion" 
      - "data_exfiltration"
      - "privilege_escalation"
      - "persistence"
      - "reconnaissance"
      - "lateral_movement"
      - "command_control"
    
    # Anomaly Detection Settings
    anomaly_detection_enabled: true             # Enable behavioral anomaly detection
    anomaly_threshold: 0.7                      # Threshold for anomaly detection (0-1)
    baseline_learning_period: "7d"              # How long to learn normal behavior
    model_update_interval: "1h"                 # How often to update ML models
    
    # Containment Planning Settings
    containment_enabled: true                   # Enable automated containment planning
    auto_containment_enabled: false             # Allow fully automated containment
    containment_approval_required: true         # Require approval for containment actions
    max_containment_actions: 5                  # Maximum actions per containment plan
    
    # Historical Analysis Settings
    historical_analysis_enabled: true           # Enable historical trend analysis
    
    # External AI Integration
    external_ai_enabled: false                  # Enable external AI analysis
    ai_analysis_endpoint: ""                    # URL for external AI service
    
    # Forensics Integration
    forensics_integration: true                 # Enable forensic evidence collection
    
    # Advanced Settings
    run_interval: 300                          # Main analysis cycle in seconds (5 minutes)
```

## Component Breakdown

### 1. Threat Analysis Engine

Analyzes individual security events and classifies threats:

```yaml
# Threat analysis focuses on:
# - Attack vector identification (network, filesystem, process, email)
# - Target type assessment (user_account, system, network_infrastructure, data)
# - Sophistication level (basic, intermediate, advanced, advanced_persistent_threat)
# - Intent classification (data_theft, ransomware, cryptomining, reconnaissance)
# - Impact assessment (financial, operational, reputational)

threat_score_threshold: 5.0                    # Events below this score are filtered out
max_analysis_depth: 10                         # Prevents infinite analysis loops

# Threat classification uses these indicators:
# - Rootkit presence: +3 sophistication points
# - Zero-day exploits: +4 sophistication points  
# - Polymorphic code: +3 sophistication points
# - Lateral movement: +2 sophistication points
# - Persistence mechanisms: +2 sophistication points
```

### 2. Pattern Recognition Engine

Learns and identifies recurring attack patterns:

```yaml
pattern_learning_enabled: true
min_pattern_occurrence: 3                      # Need at least 3 similar events
pattern_significance_score: 6.0                # Patterns must score above this threshold

# Pattern similarity calculation considers:
# - Event type similarity (weight: 0.3)
# - Source similarity (weight: 0.2) 
# - Severity similarity (weight: 0.2)
# - Description similarity (weight: 0.3)

# Automatically learned pattern characteristics:
# - Event sequences and timing
# - Common sources and targets
# - Severity distributions
# - Related attack techniques
```

### 3. Behavioral Anomaly Detection

Detects deviations from normal system behavior:

```yaml
anomaly_detection_enabled: true
anomaly_threshold: 0.7                         # Higher values = fewer false positives
baseline_learning_period: "7d"                 # Time to establish normal behavior
model_update_interval: "1h"                    # Continuous learning frequency

# Monitors these behavioral aspects:
# - Event frequency patterns
# - User login and access patterns  
# - System resource usage patterns
# - Network traffic patterns
# - Process execution patterns
# - File system access patterns

# Uses exponential moving average for baseline updates:
# new_baseline = alpha * current_value + (1-alpha) * old_baseline
# where alpha = 0.1 (learning rate)
```

### 4. Threat Correlation Engine

Correlates related threats across different sources:

```yaml
threat_correlation_enabled: true
correlation_time_window: "1h"                  # Events within 1 hour can be correlated

# Correlation factors:
# - Temporal proximity (weight: 0.3)
# - Target overlap (weight: 0.4)
# - Attack category similarity (weight: 0.3)

# Correlation threshold: 0.7
# Threats above this correlation score are merged
```

### 5. Containment Strategy Engine

Generates automated response strategies:

```yaml
containment_enabled: true
auto_containment_enabled: false                # Require human approval
containment_approval_required: true
max_containment_actions: 5                     # Limit actions to prevent system impact

# Built-in containment strategies:
# - isolate_and_clean: Network isolation + malware removal
# - network_isolation: Block network access
# - account_lockdown: Disable compromised accounts
# - system_rebuild: Complete system restoration
# - monitor_and_analyze: Enhanced monitoring only

# Approval levels based on threat score:
# - Score >= 8.0: Executive approval required
# - Score >= 5.0: Manager approval required  
# - Score >= 2.0: Supervisor approval required
# - Score < 2.0: Automated (if enabled)
```

## Environment-Specific Configurations

### High-Security Environment

```yaml
monitors:
  enhanced_analyzer:
    enabled: true
    analysis_interval: "30s"                   # More frequent analysis
    threat_score_threshold: 2.0                # Lower threshold for detection
    anomaly_threshold: 0.5                     # More sensitive anomaly detection
    
    # Aggressive pattern learning
    pattern_learning_enabled: true
    min_pattern_occurrence: 2                  # Detect patterns faster
    pattern_significance_score: 4.0            # Lower significance threshold
    
    # Enhanced correlation
    threat_correlation_enabled: true
    correlation_time_window: "2h"              # Longer correlation window
    
    # Strict containment
    containment_enabled: true
    auto_containment_enabled: false            # Always require approval
    containment_approval_required: true
    max_containment_actions: 10                # More aggressive response
    
    # Full AI integration
    external_ai_enabled: true
    ai_analysis_endpoint: "https://your-ai-service.com/analyze"
    forensics_integration: true
```

### Development Environment

```yaml
monitors:
  enhanced_analyzer:
    enabled: true
    analysis_interval: "300s"                  # Less frequent analysis
    threat_score_threshold: 7.0                # Higher threshold (fewer alerts)
    anomaly_threshold: 0.8                     # Less sensitive to avoid dev noise
    
    # Basic pattern learning
    pattern_learning_enabled: true
    min_pattern_occurrence: 5                  # More events needed for patterns
    pattern_significance_score: 8.0            # Higher significance threshold
    
    # Limited correlation to reduce noise
    threat_correlation_enabled: false
    
    # No automated containment in dev
    containment_enabled: false
    auto_containment_enabled: false
    
    # No external integrations
    external_ai_enabled: false
    forensics_integration: false
```

### Production Environment

```yaml
monitors:
  enhanced_analyzer:
    enabled: true
    analysis_interval: "60s"                   # Standard analysis frequency
    threat_score_threshold: 5.0                # Balanced threshold
    anomaly_threshold: 0.7                     # Standard sensitivity
    
    # Full pattern learning
    pattern_learning_enabled: true
    min_pattern_occurrence: 3
    pattern_significance_score: 6.0
    
    # Advanced correlation  
    threat_correlation_enabled: true
    correlation_time_window: "1h"
    
    # Controlled containment
    containment_enabled: true
    auto_containment_enabled: false            # Manual approval for safety
    containment_approval_required: true
    max_containment_actions: 5
    
    # Business-appropriate integrations
    external_ai_enabled: true                  # For enhanced analysis
    forensics_integration: true                # For incident response
```

## Integration with Event System

### Event Types Analyzed

The Enhanced Analyzer processes and correlates these event types:

```yaml
# Input Events (from other monitors):
- EventMalwareDetected      # From Sentry monitors
- EventRootkitDetected      # From Sentry monitors  
- EventDataExfiltration     # From Sentry monitors
- EventSuspiciousNetwork    # From Sentinel monitors
- EventFileSystemChange     # From Sentry monitors
- EventPrivilegeEscalation  # From Sentinel monitors
- EventSystemAnomaly        # From Sentinel monitors
- EventFirmwareChange       # From Sentry monitors

# Output Events (generated by analyzer):
- EventThreatDetected       # New threats identified
- EventSystemAnomaly        # Behavioral anomalies
- EventThreatDetected       # Pattern matches
- EventThreatDetected       # Correlated threats
```

### Event Severity Mapping

```yaml
# Threat Score to Severity Mapping:
# Score >= 8.0: "critical"   - Immediate executive attention
# Score >= 6.0: "high"       - Security team escalation
# Score >= 4.0: "medium"     - Standard investigation
# Score >= 2.0: "low"        - Routine monitoring
# Score < 2.0:  filtered out (below threshold)
```

## State Information and Metrics

### Available State Fields

```go
// Access current analyzer state:
state := monitor.GetState()

// Core metrics:
state["active_threats_count"]           // Number of active threats
state["patterns_learned"]               // Number of learned patterns  
state["analysis_history_count"]         // Number of completed analyses
state["average_threat_score"]           // Average score of active threats
state["last_analysis_time"]             // Timestamp of last analysis

// Threat distribution:
state["threats_by_category"]            // Count by threat category
state["threats_by_stage"]               // Count by attack progression stage
state["patterns_by_category"]           // Count by pattern category

// Component status:
state["component_status"]               // Status of each analyzer component
state["analyzer_status"]                // Overall analyzer status
```

### Prometheus-Style Metrics

```yaml
# Metrics that could be exported for monitoring:
sentinel_analyzer_threats_active_total{category="malware"}
sentinel_analyzer_threats_active_total{category="intrusion"}
sentinel_analyzer_patterns_learned_total{category="malware"}
sentinel_analyzer_anomalies_detected_total{type="event_frequency"}
sentinel_analyzer_correlations_found_total
sentinel_analyzer_containment_plans_generated_total
sentinel_analyzer_ai_analyses_completed_total
```

## Machine Learning and AI Integration

### Behavioral Baselines

The analyzer builds and maintains baselines for:

```yaml
# User behavior patterns:
- Login times and frequencies
- File access patterns  
- Command usage patterns
- Network activity patterns

# System behavior patterns:
- Process execution patterns
- Resource usage patterns
- Service restart patterns
- Filesystem usage patterns

# Network behavior patterns:
- Connection patterns by protocol
- Traffic volume patterns
- Port usage patterns
- Geographic connection patterns
```

### External AI Integration

```yaml
external_ai_enabled: true
ai_analysis_endpoint: "https://your-ai-service.com/analyze"

# The analyzer sends structured analysis data to external AI:
{
  "threats": [...],           # Active threat summaries
  "patterns": [...],          # Identified patterns
  "context": {                # Environment context
    "system_type": "production",
    "industry": "financial",
    "compliance_requirements": ["PCI-DSS", "SOX"]
  }
}

# AI response provides:
{
  "analysis": "Natural language threat assessment",
  "confidence": 0.85,
  "suggestions": [
    "Consider implementing network segmentation",
    "Review access controls for affected systems"
  ],
  "attribution": {
    "likely_threat_actor": "Advanced Persistent Threat",
    "confidence": 0.7
  }
}
```

## Performance Considerations

### Resource Usage

- **CPU**: High - Complex pattern matching and correlation algorithms
- **Memory**: High - Maintains threat history, patterns, and baselines in memory
- **Storage**: Medium - Stores analysis results and learned patterns
- **Network**: Low - Only for external AI integration

### Optimization Strategies

```yaml
# For high-volume environments:
analysis_interval: "120s"                      # Less frequent analysis
event_analysis_window: "12h"                   # Shorter analysis window
max_analysis_depth: 5                          # Limit recursion depth

# Memory optimization:
# - Limit analysis history to last 100 results
# - Expire old threat patterns after 30 days
# - Use sampling for behavioral baseline updates

# CPU optimization:
# - Run analysis components in parallel
# - Use correlation rules to filter events early
# - Cache pattern matching results
```

## Troubleshooting

### Common Issues

1. **High memory usage**: Reduce `event_analysis_window` or increase `analysis_interval`
2. **Too many false positives**: Increase `anomaly_threshold` and `threat_score_threshold`
3. **Missing threat correlations**: Increase `correlation_time_window`
4. **AI integration failures**: Check `ai_analysis_endpoint` connectivity
5. **Containment not triggering**: Verify `containment_enabled` and approval settings

### Debug Configuration

```yaml
monitors:
  enhanced_analyzer:
    enabled: true
    debug: true                                 # Enable verbose logging
    analysis_interval: "30s"                   # Faster analysis for testing
    
    # Minimal thresholds for testing
    threat_score_threshold: 1.0
    anomaly_threshold: 0.3
    min_pattern_occurrence: 2
    
    # Disable external dependencies
    external_ai_enabled: false
    containment_enabled: false
```

### Monitoring Health

```yaml
# Key health indicators to monitor:
- Analysis completion rate (should be > 95%)
- Average analysis duration (should be < 30s)
- Memory usage growth (should be stable)
- Pattern learning rate (should increase over time)
- False positive rate (should decrease over time)
- Threat correlation accuracy (manual validation needed)
```

## Security Considerations

### Data Protection

- All threat data is encrypted at rest and in transit
- Personal information is anonymized in patterns
- Analysis results include data sensitivity classifications
- Retention policies automatically purge old analysis data

### Access Controls

- Analysis results require security clearance to access
- Containment actions require multi-level approval
- AI integration uses encrypted channels with authentication
- Audit logs track all analysis and containment decisions

### Compliance Integration

```yaml
# The analyzer supports compliance frameworks:
forensics_integration: true                    # Evidence collection for legal use

# Generates compliance-ready reports for:
# - SOC 2 (Security monitoring and incident response)
# - ISO 27001 (Information security management)
# - PCI-DSS (Payment card industry security)
# - NIST Cybersecurity Framework (Detect, Respond, Recover)

# Report formats include:
# - Executive summaries with risk assessments
# - Technical details with evidence chains
# - Timeline analysis for incident reconstruction
# - Recommendation tracking for remediation
```

The Enhanced Analyzer Monitor serves as the "brain" of the Lucid Vigil security system, providing intelligent threat analysis, pattern recognition, and strategic response planning that scales from small deployments to enterprise environments.