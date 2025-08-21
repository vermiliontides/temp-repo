// pkg/monitors/analyzer.go
package monitors

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/events"
	"github.com/lucid-vigil/sentinel/pkg/mointors/scheduler"
	"github.com/lucid-vigil/sentinel/pkg/monitors/base_monitor"
	"github.com/rs/zerolog"
)

// AnalyzerMonitor - Advanced threat analysis and pattern recognition system
type AnalyzerMonitor struct {
	*base_monitor.BaseMonitor
	config              *ComprehensiveAnalyzerConfig
	analysisEngine      *ThreatAnalysisEngine
	patternRecognition  *PatternRecognitionEngine
	containmentStrategy *ContainmentStrategyEngine
	historicalPatterns  map[string]ThreatPattern
	activeThreats       map[string]ActiveThreat
	analysisHistory     []AnalysisResult

	// Machine Learning components
	behaviorBaseline BehaviorBaseline
	anomalyThreshold float64
	learningEnabled  bool

	// Synchronization
	mu sync.RWMutex
}

// ComprehensiveAnalyzerConfig - Configuration for the analyzer system
type ComprehensiveAnalyzerConfig struct {
	// Core analysis settings
	AnalysisInterval          string `mapstructure:"analysis_interval"`
	ThreatCorrelationEnabled  bool   `mapstructure:"threat_correlation_enabled"`
	PatternLearningEnabled    bool   `mapstructure:"pattern_learning_enabled"`
	HistoricalAnalysisEnabled bool   `mapstructure:"historical_analysis_enabled"`
	ContainmentEnabled        bool   `mapstructure:"containment_enabled"`

	// Analysis depth settings
	MaxAnalysisDepth      int     `mapstructure:"max_analysis_depth"`
	EventAnalysisWindow   string  `mapstructure:"event_analysis_window"`
	ThreatScoreThreshold  float64 `mapstructure:"threat_score_threshold"`
	CorrelationTimeWindow string  `mapstructure:"correlation_time_window"`

	// Machine Learning settings
	AnomalyDetectionEnabled bool    `mapstructure:"anomaly_detection_enabled"`
	AnomalyThreshold        float64 `mapstructure:"anomaly_threshold"`
	BaselineLearningPeriod  string  `mapstructure:"baseline_learning_period"`
	ModelUpdateInterval     string  `mapstructure:"model_update_interval"`

	// Pattern recognition settings
	PatternCategories        []string `mapstructure:"pattern_categories"`
	MinPatternOccurrence     int      `mapstructure:"min_pattern_occurrence"`
	PatternSignificanceScore float64  `mapstructure:"pattern_significance_score"`

	// Containment strategy settings
	AutoContainmentEnabled      bool `mapstructure:"auto_containment_enabled"`
	ContainmentApprovalRequired bool `mapstructure:"containment_approval_required"`
	MaxContainmentActions       int  `mapstructure:"max_containment_actions"`

	// Integration settings
	ExternalAIEnabled    bool   `mapstructure:"external_ai_enabled"`
	AIAnalysisEndpoint   string `mapstructure:"ai_analysis_endpoint"`
	ForensicsIntegration bool   `mapstructure:"forensics_integration"`
}

// Core analysis structures
type ThreatAnalysisEngine struct {
	correlationRules  []CorrelationRule
	threatClassifiers []ThreatClassifier
	analysisQueue     chan SecurityEvent
	resultChannel     chan AnalysisResult
}

type PatternRecognitionEngine struct {
	knownPatterns    map[string]ThreatPattern
	learningPatterns map[string]PartialPattern
	patternMatrix    [][]float64
	featureExtractor FeatureExtractor
}

type ContainmentStrategyEngine struct {
	strategies      map[string]ContainmentStrategy
	actionTemplates map[string]ActionTemplate
	approvalQueue   chan ContainmentRequest
	executionQueue  chan ContainmentAction
}

// Data structures for analysis
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        events.EventType       `json:"type"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
	Tags        []string               `json:"tags"`
}

type ThreatPattern struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Category        string                 `json:"category"`
	Description     string                 `json:"description"`
	Indicators      []string               `json:"indicators"`
	Sequence        []SecurityEvent        `json:"sequence"`
	Frequency       int                    `json:"frequency"`
	LastSeen        time.Time              `json:"last_seen"`
	ThreatScore     float64                `json:"threat_score"`
	Characteristics map[string]interface{} `json:"characteristics"`
	RelatedPatterns []string               `json:"related_patterns"`
}

type ActiveThreat struct {
	ID                string          `json:"id"`
	Pattern           ThreatPattern   `json:"pattern"`
	Events            []SecurityEvent `json:"events"`
	StartTime         time.Time       `json:"start_time"`
	LastActivity      time.Time       `json:"last_activity"`
	ThreatScore       float64         `json:"threat_score"`
	ProgressStage     string          `json:"progress_stage"`
	AffectedAssets    []string        `json:"affected_assets"`
	ContainmentStatus string          `json:"containment_status"`
	Analysis          ThreatAnalysis  `json:"analysis"`
}

type AnalysisResult struct {
	ID              string           `json:"id"`
	Timestamp       time.Time        `json:"timestamp"`
	AnalysisType    string           `json:"analysis_type"`
	ThreatID        string           `json:"threat_id"`
	Findings        []Finding        `json:"findings"`
	RiskAssessment  RiskAssessment   `json:"risk_assessment"`
	Recommendations []Recommendation `json:"recommendations"`
	ContainmentPlan ContainmentPlan  `json:"containment_plan"`
	Confidence      float64          `json:"confidence"`
	AIAnalysis      AIAnalysisResult `json:"ai_analysis,omitempty"`
}

type ThreatAnalysis struct {
	Category         string              `json:"category"`
	SubCategory      string              `json:"sub_category"`
	AttackVector     string              `json:"attack_vector"`
	TargetType       string              `json:"target_type"`
	Sophistication   string              `json:"sophistication"`
	Intent           string              `json:"intent"`
	Attribution      AttributionAnalysis `json:"attribution"`
	Timeline         ThreatTimeline      `json:"timeline"`
	ImpactAssessment ImpactAssessment    `json:"impact_assessment"`
}

type Finding struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Evidence    []Evidence             `json:"evidence"`
	Confidence  float64                `json:"confidence"`
	Severity    string                 `json:"severity"`
	Context     map[string]interface{} `json:"context"`
}

type Evidence struct {
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
	Timestamp   time.Time              `json:"timestamp"`
	Hash        string                 `json:"hash,omitempty"`
}

type RiskAssessment struct {
	OverallRisk      string   `json:"overall_risk"`
	RiskScore        float64  `json:"risk_score"`
	BusinessImpact   string   `json:"business_impact"`
	TechnicalImpact  string   `json:"technical_impact"`
	Likelihood       float64  `json:"likelihood"`
	AffectedSystems  []string `json:"affected_systems"`
	DataAtRisk       []string `json:"data_at_risk"`
	ComplianceImpact []string `json:"compliance_impact"`
}

type Recommendation struct {
	Priority      string   `json:"priority"`
	Action        string   `json:"action"`
	Description   string   `json:"description"`
	Timeline      string   `json:"timeline"`
	Resources     []string `json:"resources"`
	RiskReduction float64  `json:"risk_reduction"`
	Dependencies  []string `json:"dependencies"`
}

type ContainmentPlan struct {
	Strategy      string              `json:"strategy"`
	Phase         string              `json:"phase"`
	Actions       []ContainmentAction `json:"actions"`
	Timeline      string              `json:"timeline"`
	Resources     []string            `json:"resources"`
	RollbackPlan  []ContainmentAction `json:"rollback_plan"`
	ApprovalLevel string              `json:"approval_level"`
}

type ContainmentAction struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Target      string                 `json:"target"`
	Parameters  map[string]interface{} `json:"parameters"`
	Priority    int                    `json:"priority"`
	Automated   bool                   `json:"automated"`
	Status      string                 `json:"status"`
}

// Supporting structures
type CorrelationRule struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	EventTypes []events.EventType `json:"event_types"`
	TimeWindow time.Duration      `json:"time_window"`
	Conditions []Condition        `json:"conditions"`
	Weight     float64            `json:"weight"`
	Enabled    bool               `json:"enabled"`
}

type ThreatClassifier struct {
	Category   string             `json:"category"`
	Indicators []string           `json:"indicators"`
	Weights    map[string]float64 `json:"weights"`
	Threshold  float64            `json:"threshold"`
	MLModel    interface{}        `json:"ml_model,omitempty"`
}

type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Weight   float64     `json:"weight"`
}

type BehaviorBaseline struct {
	EventFrequency  map[string]float64     `json:"event_frequency"`
	UserBehavior    map[string]UserProfile `json:"user_behavior"`
	SystemBehavior  SystemProfile          `json:"system_behavior"`
	NetworkBehavior NetworkProfile         `json:"network_behavior"`
	LastUpdated     time.Time              `json:"last_updated"`
	LearningPeriod  time.Duration          `json:"learning_period"`
	SampleCount     int64                  `json:"sample_count"`
}

type UserProfile struct {
	LoginPatterns   []TimePattern            `json:"login_patterns"`
	AccessPatterns  map[string]float64       `json:"access_patterns"`
	CommandUsage    map[string]int           `json:"command_usage"`
	FileAccess      map[string]AccessProfile `json:"file_access"`
	NetworkActivity NetworkActivityProfile   `json:"network_activity"`
}

type SystemProfile struct {
	ProcessPatterns map[string]ProcessProfile `json:"process_patterns"`
	FileSystemUsage FileSystemProfile         `json:"filesystem_usage"`
	ResourceUsage   ResourceProfile           `json:"resource_usage"`
	ServicePatterns map[string]ServiceProfile `json:"service_patterns"`
}

type NetworkProfile struct {
	ConnectionPatterns map[string]int `json:"connection_patterns"`
	TrafficPatterns    TrafficProfile `json:"traffic_patterns"`
	PortUsage          map[int]int    `json:"port_usage"`
	ProtocolUsage      map[string]int `json:"protocol_usage"`
}

// Additional supporting types
type PartialPattern struct {
	Events     []SecurityEvent `json:"events"`
	Frequency  int             `json:"frequency"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	Confidence float64         `json:"confidence"`
}

type FeatureExtractor struct {
	Features map[string]FeatureDefinition `json:"features"`
}

type FeatureDefinition struct {
	Type       string  `json:"type"`
	Extractor  string  `json:"extractor"`
	Weight     float64 `json:"weight"`
	Normalizer string  `json:"normalizer"`
}

type ContainmentStrategy struct {
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	Phases       []ContainmentPhase `json:"phases"`
	TriggerRules []TriggerRule      `json:"trigger_rules"`
	Automated    bool               `json:"automated"`
}

type ContainmentPhase struct {
	Name       string           `json:"name"`
	Actions    []ActionTemplate `json:"actions"`
	Timeline   string           `json:"timeline"`
	Conditions []Condition      `json:"conditions"`
}

type ActionTemplate struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Automated   bool                   `json:"automated"`
	RiskLevel   string                 `json:"risk_level"`
}

type TriggerRule struct {
	Condition Condition `json:"condition"`
	Action    string    `json:"action"`
	Priority  int       `json:"priority"`
	Automated bool      `json:"automated"`
}

type ContainmentRequest struct {
	ThreatID      string              `json:"threat_id"`
	Strategy      string              `json:"strategy"`
	Actions       []ContainmentAction `json:"actions"`
	Priority      string              `json:"priority"`
	Justification string              `json:"justification"`
	RequestTime   time.Time           `json:"request_time"`
}

type AIAnalysisResult struct {
	Provider    string                 `json:"provider"`
	Analysis    string                 `json:"analysis"`
	Confidence  float64                `json:"confidence"`
	Suggestions []string               `json:"suggestions"`
	Context     map[string]interface{} `json:"context"`
	ProcessedAt time.Time              `json:"processed_at"`
}

// Profile types
type TimePattern struct {
	Hour      int     `json:"hour"`
	DayOfWeek int     `json:"day_of_week"`
	Frequency int     `json:"frequency"`
	Variance  float64 `json:"variance"`
}

type AccessProfile struct {
	ReadCount  int       `json:"read_count"`
	WriteCount int       `json:"write_count"`
	LastAccess time.Time `json:"last_access"`
	Patterns   []string  `json:"patterns"`
}

type NetworkActivityProfile struct {
	Connections  int            `json:"connections"`
	BytesIn      int64          `json:"bytes_in"`
	BytesOut     int64          `json:"bytes_out"`
	Protocols    map[string]int `json:"protocols"`
	Destinations map[string]int `json:"destinations"`
}

type ProcessProfile struct {
	StartCount  int            `json:"start_count"`
	Runtime     time.Duration  `json:"runtime"`
	CPUUsage    float64        `json:"cpu_usage"`
	MemoryUsage int64          `json:"memory_usage"`
	Children    map[string]int `json:"children"`
}

type FileSystemProfile struct {
	Reads    int64          `json:"reads"`
	Writes   int64          `json:"writes"`
	Creates  int            `json:"creates"`
	Deletes  int            `json:"deletes"`
	Patterns map[string]int `json:"patterns"`
}

type ResourceProfile struct {
	CPUAverage    float64 `json:"cpu_average"`
	CPUPeak       float64 `json:"cpu_peak"`
	MemoryAverage int64   `json:"memory_average"`
	MemoryPeak    int64   `json:"memory_peak"`
	DiskIO        int64   `json:"disk_io"`
	NetworkIO     int64   `json:"network_io"`
}

type ServiceProfile struct {
	Status      string `json:"status"`
	Restarts    int    `json:"restarts"`
	Connections int    `json:"connections"`
	Errors      int    `json:"errors"`
}

type TrafficProfile struct {
	InboundBytes  int64            `json:"inbound_bytes"`
	OutboundBytes int64            `json:"outbound_bytes"`
	Connections   int              `json:"connections"`
	Protocols     map[string]int64 `json:"protocols"`
}

type AttributionAnalysis struct {
	Indicators        []string `json:"indicators"`
	GeographicOrigin  string   `json:"geographic_origin"`
	TechnicalMarkers  []string `json:"technical_markers"`
	BehavioralMarkers []string `json:"behavioral_markers"`
	KnownGroups       []string `json:"known_groups"`
	Confidence        float64  `json:"confidence"`
}

type ThreatTimeline struct {
	InitialAccess       time.Time `json:"initial_access"`
	Reconnaissance      time.Time `json:"reconnaissance"`
	InitialCompromise   time.Time `json:"initial_compromise"`
	Persistence         time.Time `json:"persistence"`
	PrivilegeEscalation time.Time `json:"privilege_escalation"`
	LateralMovement     time.Time `json:"lateral_movement"`
	Collection          time.Time `json:"collection"`
	Exfiltration        time.Time `json:"exfiltration"`
	Impact              time.Time `json:"impact"`
}

type ImpactAssessment struct {
	DataImpact       string        `json:"data_impact"`
	SystemImpact     string        `json:"system_impact"`
	BusinessImpact   string        `json:"business_impact"`
	ReputationImpact string        `json:"reputation_impact"`
	FinancialImpact  EstimatedCost `json:"financial_impact"`
	RecoveryTime     time.Duration `json:"recovery_time"`
}

type EstimatedCost struct {
	DirectCosts     float64 `json:"direct_costs"`
	IndirectCosts   float64 `json:"indirect_costs"`
	OpportunityCost float64 `json:"opportunity_cost"`
	Currency        string  `json:"currency"`
}

// NewAnalyzerMonitor creates a comprehensive threat analysis system
func NewAnalyzerMonitor(logger zerolog.Logger, eventBus *events.EventBus) scheduler.Monitor {
	monitor := &AnalyzerMonitor{
		BaseMonitor:        base_monitor.NewBaseMonitor("comprehensive_analyzer", base_monitor.ClassAnalyzer, logger, eventBus),
		config:             &ComprehensiveAnalyzerConfig{},
		historicalPatterns: make(map[string]ThreatPattern),
		activeThreats:      make(map[string]ActiveThreat),
		analysisHistory:    make([]AnalysisResult, 0),
		anomalyThreshold:   0.7,
		learningEnabled:    true,
	}

	// Add analyzer capabilities
	monitor.AddCapability(CapabilityMachineLearning)
	monitor.AddCapability(CapabilityBehaviorAnalysis)
	monitor.AddCapability(CapabilityCorrelation)
	monitor.AddCapability(CapabilityThreatIntel)
	monitor.AddCapability("pattern_recognition")
	monitor.AddCapability("threat_analysis")
	monitor.AddCapability("containment_planning")
	monitor.AddCapability("ai_integration")

	// Initialize analysis engines
	monitor.initializeAnalysisEngines()

	return monitor
}

// Configure sets up the comprehensive analysis system
func (am *AnalyzerMonitor) Configure(config map[string]interface{}) error {
	am.LogEvent(zerolog.InfoLevel, "Configuring Comprehensive Analyzer Monitor")

	if err := am.parseConfig(config); err != nil {
		return fmt.Errorf("failed to parse analyzer configuration: %w", err)
	}

	// Initialize components based on configuration
	if am.config.PatternLearningEnabled {
		am.initializePatternLearning()
	}

	if am.config.AnomalyDetectionEnabled {
		am.initializeBehaviorBaseline()
	}

	if am.config.ContainmentEnabled {
		am.initializeContainmentStrategies()
	}

	am.LogEvent(zerolog.InfoLevel, "Comprehensive Analyzer Monitor configured successfully")

	return nil
}

// Run executes comprehensive threat analysis
func (am *AnalyzerMonitor) Run(ctx context.Context) {
	am.LogEvent(zerolog.InfoLevel, "Comprehensive Analyzer Monitor: Starting threat analysis...")
	am.UpdateState("status", "analyzing")
	am.UpdateState("analysis_start", time.Now())

	var wg sync.WaitGroup

	// Run analysis components concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		am.runThreatAnalysis(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.runPatternRecognition(ctx)
	}()

	if am.config.AnomalyDetectionEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			am.runAnomalyDetection(ctx)
		}()
	}

	if am.config.ThreatCorrelationEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			am.runThreatCorrelation(ctx)
		}()
	}

	if am.config.ContainmentEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			am.runContainmentPlanning(ctx)
		}()
	}

	// Wait for all analysis components to complete
	wg.Wait()

	// Generate comprehensive analysis report
	am.generateAnalysisReport(ctx)

	// Update metrics and state
	am.updateAnalysisMetrics()

	am.LogEvent(zerolog.InfoLevel, "Comprehensive Analyzer Monitor: Analysis completed").
		Int("threats_analyzed", len(am.activeThreats)).
		Int("patterns_recognized", len(am.historicalPatterns))
}

// Core analysis methods
func (am *AnalyzerMonitor) runThreatAnalysis(ctx context.Context) {
	am.LogEvent(zerolog.InfoLevel, "Running threat analysis...")
	// Get recent security events from event bus
	if am.EventBus == nil {
		am.LogEvent(zerolog.WarnLevel, "No event bus available for threat analysis")
		return
	}
	// Analyze recent events
	recentEvents := am.getRecentSecurityEvents(ctx)
	for _, event := range recentEvents {
		analysis := am.analyzeSecurityEvent(ctx, event)
		// Corrected: Check the financial impact score from the impact assessment
		if analysis.ImpactAssessment.FinancialImpact.DirectCosts > am.config.ThreatScoreThreshold {
			am.processHighThreatEvent(ctx, event, analysis)
		}
	}
	// Update existing threat analysis
	am.updateActiveThreatAnalysis(ctx)
}

func (am *AnalyzerMonitor) runPatternRecognition(ctx context.Context) {
	am.LogEvent(zerolog.InfoLevel, "Running pattern recognition...")

	if !am.config.PatternLearningEnabled {
		return
	}

	// Extract patterns from recent events
	recentEvents := am.getRecentSecurityEvents(ctx)
	patterns := am.extractPatterns(recentEvents)

	// Compare with known patterns
	for _, pattern := range patterns {
		am.evaluatePattern(ctx, pattern)
	}

	// Learn new patterns
	am.learnNewPatterns(ctx, patterns)
}

func (am *AnalyzerMonitor) runAnomalyDetection(ctx context.Context) {
	am.LogEvent(zerolog.InfoLevel, "Running anomaly detection...")

	// Collect current system behavior
	currentBehavior := am.collectCurrentBehavior(ctx)

	// Compare with baseline
	anomalies := am.detectAnomalies(currentBehavior, am.behaviorBaseline)

	// Process significant anomalies
	for _, anomaly := range anomalies {
		if anomaly.Score > am.anomalyThreshold {
			am.processAnomaly(ctx, anomaly)
		}
	}

	// Update baseline if in learning mode
	if am.learningEnabled {
		am.updateBehaviorBaseline(currentBehavior)
	}
}

func (am *AnalyzerMonitor) runThreatCorrelation(ctx context.Context) {
	am.LogEvent(zerolog.InfoLevel, "Running threat correlation...")

	// Correlate events across different sources
	correlatedThreats := am.correlateThreats(ctx)

	// Update threat scores based on correlation
	for _, threat := range correlatedThreats {
		am.updateThreatScore(ctx, threat)
	}
}

func (am *AnalyzerMonitor) runContainmentPlanning(ctx context.Context) {
	am.LogEvent(zerolog.InfoLevel, "Running containment planning...")

	am.mu.RLock()
	threats := make(map[string]ActiveThreat)
	for k, v := range am.activeThreats {
		threats[k] = v
	}
	am.mu.RUnlock()

	// Generate containment plans for active threats
	for threatID, threat := range threats {
		if threat.ContainmentStatus == "planned" || threat.ContainmentStatus == "" {
			plan := am.generateContainmentPlan(ctx, threat)
			am.updateThreatContainment(threatID, plan)
		}
	}
}

// Analysis helper methods
func (am *AnalyzerMonitor) getRecentSecurityEvents(ctx context.Context) []SecurityEvent {
	// This would integrate with the event bus to get recent events
	// For now, return empty slice as placeholder
	return []SecurityEvent{}
}

func (am *AnalyzerMonitor) analyzeSecurityEvent(ctx context.Context, event SecurityEvent) ThreatAnalysis {
	analysis := ThreatAnalysis{
		Category:       am.categorizeEvent(event),
		AttackVector:   am.identifyAttackVector(event),
		TargetType:     am.identifyTargetType(event),
		Sophistication: am.assessSophistication(event),
		Intent:         am.assessIntent(event),
	}

	// Add timeline analysis
	analysis.Timeline = am.buildThreatTimeline(event)

	// Assess impact
	analysis.ImpactAssessment = am.assessImpact(event)

	// Attempt attribution
	analysis.Attribution = am.performAttribution(event)

	return analysis
}

func (am *AnalyzerMonitor) processHighThreatEvent(ctx context.Context, event SecurityEvent, analysis ThreatAnalysis) {
	// Create or update active threat
	threatID := am.generateThreatID(event, analysis)

	am.mu.Lock()
	if threat, exists := am.activeThreats[threatID]; exists {
		// Update existing threat
		threat.Events = append(threat.Events, event)
		threat.LastActivity = event.Timestamp
		threat.Analysis = analysis
		am.activeThreats[threatID] = threat
	} else {
		// Create new threat
		newThreat := ActiveThreat{
			ID:                threatID,
			Events:            []SecurityEvent{event},
			StartTime:         event.Timestamp,
			LastActivity:      event.Timestamp,
			ThreatScore:       analysis.ImpactAssessment.FinancialImpact.DirectCosts,
			ProgressStage:     "initial",
			Analysis:          analysis,
			ContainmentStatus: "pending",
		}
		am.activeThreats[threatID] = newThreat
	}
	am.mu.Unlock()

	// Publish threat event
	am.PublishEvent(ctx, events.EventThreatDetected, event.Target,
		fmt.Sprintf("High-threat event analyzed: %s", analysis.Category),
		"high", map[string]interface{}{
			"threat_id":      threatID,
			"category":       analysis.Category,
			"attack_vector":  analysis.AttackVector,
			"sophistication": analysis.Sophistication,
		})
}

func (am *AnalyzerMonitor) extractPatterns(events []SecurityEvent) []ThreatPattern {
	patterns := make([]ThreatPattern, 0)

	// Group events by similarity
	eventGroups := am.groupEventsBySimilarity(events)

	// Extract patterns from groups
	for _, group := range eventGroups {
		if len(group) >= am.config.MinPatternOccurrence {
			pattern := am.createPatternFromEvents(group)
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

func (am *AnalyzerMonitor) evaluatePattern(ctx context.Context, pattern ThreatPattern) {
	am.mu.RLock()
	knownPattern, exists := am.historicalPatterns[pattern.ID]
	am.mu.RUnlock()

	if exists {
		// Update existing pattern
		knownPattern.Frequency++
		knownPattern.LastSeen = time.Now()

		am.mu.Lock()
		am.historicalPatterns[pattern.ID] = knownPattern
		am.mu.Unlock()
	} else {
		// New pattern detected
		am.mu.Lock()
		am.historicalPatterns[pattern.ID] = pattern
		am.mu.Unlock()

		am.PublishEvent(ctx, events.EventThreatDetected, "pattern_recognition",
			fmt.Sprintf("New threat pattern detected: %s", pattern.Name),
			"medium", map[string]interface{}{
				"pattern_id":   pattern.ID,
				"category":     pattern.Category,
				"threat_score": pattern.ThreatScore,
			})
	}
}

// Placeholder implementations for complex analysis methods
func (am *AnalyzerMonitor) categorizeEvent(event SecurityEvent) string {
	// Implement event categorization logic
	switch event.Type {
	case events.EventMalwareDetected:
		return "malware"
	case events.EventRootkitDetected:
		return "rootkit"
	case events.EventDataExfiltration:
		return "data_exfiltration"
	case events.EventSuspiciousNetwork:
		return "network_intrusion"
	case events.EventFileSystemChange:
		return "unauthorized_access"
	case events.EventPrivilegeEscalation:
		return "privilege_escalation"
	default:
		return "unknown"
	}
}

func (am *AnalyzerMonitor) identifyAttackVector(event SecurityEvent) string {
	// Analyze attack vector based on event characteristics
	if strings.Contains(event.Description, "network") || strings.Contains(event.Description, "connection") {
		return "network"
	}
	if strings.Contains(event.Description, "file") || strings.Contains(event.Description, "filesystem") {
		return "filesystem"
	}
	if strings.Contains(event.Description, "process") || strings.Contains(event.Description, "execution") {
		return "process_injection"
	}
	if strings.Contains(event.Description, "email") || strings.Contains(event.Description, "phishing") {
		return "email"
	}
	return "unknown"
}

func (am *AnalyzerMonitor) identifyTargetType(event SecurityEvent) string {
	// Determine what type of asset is being targeted
	target := strings.ToLower(event.Target)
	if strings.Contains(target, "user") || strings.Contains(target, "account") {
		return "user_account"
	}
	if strings.Contains(target, "system") || strings.Contains(target, "server") {
		return "system"
	}
	if strings.Contains(target, "network") || strings.Contains(target, "connection") {
		return "network_infrastructure"
	}
	if strings.Contains(target, "data") || strings.Contains(target, "file") {
		return "data"
	}
	return "unknown"
}

func (am *AnalyzerMonitor) assessSophistication(event SecurityEvent) string {
	// Assess attack sophistication based on techniques used
	sophisticationScore := 0

	// Check for advanced techniques
	if strings.Contains(event.Description, "rootkit") {
		sophisticationScore += 3
	}
	if strings.Contains(event.Description, "zero-day") {
		sophisticationScore += 4
	}
	if strings.Contains(event.Description, "polymorphic") {
		sophisticationScore += 3
	}
	if strings.Contains(event.Description, "lateral movement") {
		sophisticationScore += 2
	}
	if strings.Contains(event.Description, "persistence") {
		sophisticationScore += 2
	}

	switch {
	case sophisticationScore >= 6:
		return "advanced_persistent_threat"
	case sophisticationScore >= 4:
		return "advanced"
	case sophisticationScore >= 2:
		return "intermediate"
	default:
		return "basic"
	}
}

func (am *AnalyzerMonitor) assessIntent(event SecurityEvent) string {
	// Determine attacker intent based on event patterns
	description := strings.ToLower(event.Description)

	if strings.Contains(description, "exfiltration") || strings.Contains(description, "upload") {
		return "data_theft"
	}
	if strings.Contains(description, "ransom") || strings.Contains(description, "encrypt") {
		return "ransomware"
	}
	if strings.Contains(description, "mining") || strings.Contains(description, "cryptocurrency") {
		return "cryptomining"
	}
	if strings.Contains(description, "reconnaissance") || strings.Contains(description, "scanning") {
		return "reconnaissance"
	}
	if strings.Contains(description, "persistence") {
		return "establish_foothold"
	}
	return "unknown"
}

func (am *AnalyzerMonitor) buildThreatTimeline(event SecurityEvent) ThreatTimeline {
	// Build threat timeline based on event analysis
	timeline := ThreatTimeline{
		InitialAccess: event.Timestamp,
	}

	// Estimate other phases based on event type and characteristics
	switch event.Type {
	case events.EventSuspiciousNetwork:
		timeline.Reconnaissance = event.Timestamp.Add(-30 * time.Minute)
		timeline.InitialCompromise = event.Timestamp
	case events.EventFileSystemChange:
		timeline.InitialCompromise = event.Timestamp.Add(-1 * time.Hour)
		timeline.Persistence = event.Timestamp
	case events.EventDataExfiltration:
		timeline.Collection = event.Timestamp.Add(-15 * time.Minute)
		timeline.Exfiltration = event.Timestamp
	}

	return timeline
}

func (am *AnalyzerMonitor) assessImpact(event SecurityEvent) ImpactAssessment {
	// Assess potential impact of the threat
	impact := ImpactAssessment{
		DataImpact:       "medium",
		SystemImpact:     "medium",
		BusinessImpact:   "low",
		ReputationImpact: "low",
		RecoveryTime:     time.Hour,
	}

	// Adjust based on event severity and type
	switch event.Severity {
	case "critical":
		impact.DataImpact = "high"
		impact.SystemImpact = "high"
		impact.BusinessImpact = "high"
		impact.RecoveryTime = 24 * time.Hour
		impact.FinancialImpact = EstimatedCost{
			DirectCosts:     50000,
			IndirectCosts:   100000,
			OpportunityCost: 200000,
			Currency:        "USD",
		}
	case "high":
		impact.DataImpact = "high"
		impact.SystemImpact = "medium"
		impact.BusinessImpact = "medium"
		impact.RecoveryTime = 4 * time.Hour
		impact.FinancialImpact = EstimatedCost{
			DirectCosts:     10000,
			IndirectCosts:   25000,
			OpportunityCost: 50000,
			Currency:        "USD",
		}
	default:
		impact.FinancialImpact = EstimatedCost{
			DirectCosts:     1000,
			IndirectCosts:   2500,
			OpportunityCost: 5000,
			Currency:        "USD",
		}
	}

	return impact
}

func (am *AnalyzerMonitor) performAttribution(event SecurityEvent) AttributionAnalysis {
	// Attempt to attribute the attack to known threat actors
	attribution := AttributionAnalysis{
		Indicators:        []string{},
		GeographicOrigin:  "unknown",
		TechnicalMarkers:  []string{},
		BehavioralMarkers: []string{},
		KnownGroups:       []string{},
		Confidence:        0.1,
	}

	// Analyze technical markers
	if data, ok := event.Data["source_ip"]; ok {
		if ip, ok := data.(string); ok {
			attribution.TechnicalMarkers = append(attribution.TechnicalMarkers, fmt.Sprintf("source_ip:%s", ip))
			// Could integrate with threat intelligence feeds here
		}
	}

	// Analyze behavioral markers
	if strings.Contains(event.Description, "lateral movement") {
		attribution.BehavioralMarkers = append(attribution.BehavioralMarkers, "lateral_movement")
	}
	if strings.Contains(event.Description, "living off the land") {
		attribution.BehavioralMarkers = append(attribution.BehavioralMarkers, "lolbins_usage")
	}

	return attribution
}

func (am *AnalyzerMonitor) generateThreatID(event SecurityEvent, analysis ThreatAnalysis) string {
	// Generate unique threat ID based on event and analysis characteristics
	return fmt.Sprintf("threat_%s_%s_%d",
		analysis.Category,
		event.Source,
		event.Timestamp.Unix())
}

func (am *AnalyzerMonitor) updateActiveThreatAnalysis(ctx context.Context) {
	am.mu.Lock()
	defer am.mu.Unlock()

	for threatID, threat := range am.activeThreats {
		// Update threat progression stage
		newStage := am.assessThreatProgression(threat)
		if newStage != threat.ProgressStage {
			threat.ProgressStage = newStage
			am.activeThreats[threatID] = threat

			am.PublishEvent(ctx, events.EventThreatDetected, threat.Analysis.TargetType,
				fmt.Sprintf("Threat progression updated: %s -> %s", threat.ProgressStage, newStage),
				"medium", map[string]interface{}{
					"threat_id":    threatID,
					"old_stage":    threat.ProgressStage,
					"new_stage":    newStage,
					"threat_score": threat.ThreatScore,
				})
		}

		// Update threat score based on recent activity
		threat.ThreatScore = am.calculateUpdatedThreatScore(threat)
		am.activeThreats[threatID] = threat
	}
}

func (am *AnalyzerMonitor) assessThreatProgression(threat ActiveThreat) string {
	// Assess what stage the threat is in based on events and timeline
	eventTypes := make(map[events.EventType]bool)
	for _, event := range threat.Events {
		eventTypes[event.Type] = true
	}

	// Determine progression based on event types observed
	if eventTypes[events.EventDataExfiltration] {
		return "exfiltration"
	}
	if eventTypes[events.EventPrivilegeEscalation] {
		return "privilege_escalation"
	}
	if eventTypes[events.EventFileSystemChange] && len(threat.Events) > 3 {
		return "persistence"
	}
	if eventTypes[events.EventSuspiciousNetwork] {
		return "reconnaissance"
	}

	return "initial"
}

func (am *AnalyzerMonitor) calculateUpdatedThreatScore(threat ActiveThreat) float64 {
	baseScore := threat.ThreatScore

	// Increase score based on event count
	eventMultiplier := 1.0 + (float64(len(threat.Events))-1)*0.1

	// Increase score based on duration
	duration := time.Since(threat.StartTime)
	durationMultiplier := 1.0 + duration.Hours()/24*0.05

	// Increase score based on progression stage
	stageMultiplier := 1.0
	switch threat.ProgressStage {
	case "persistence":
		stageMultiplier = 1.5
	case "privilege_escalation":
		stageMultiplier = 2.0
	case "exfiltration":
		stageMultiplier = 3.0
	}

	return baseScore * eventMultiplier * durationMultiplier * stageMultiplier
}

func (am *AnalyzerMonitor) groupEventsBySimilarity(events []SecurityEvent) [][]SecurityEvent {
	// Group events by similarity for pattern extraction
	groups := make([][]SecurityEvent, 0)
	processed := make(map[int]bool)

	for i, event1 := range events {
		if processed[i] {
			continue
		}

		group := []SecurityEvent{event1}
		processed[i] = true

		for j, event2 := range events {
			if i == j || processed[j] {
				continue
			}

			if am.calculateEventSimilarity(event1, event2) > 0.7 {
				group = append(group, event2)
				processed[j] = true
			}
		}

		if len(group) >= 2 {
			groups = append(groups, group)
		}
	}

	return groups
}

func (am *AnalyzerMonitor) calculateEventSimilarity(event1, event2 SecurityEvent) float64 {
	// Calculate similarity between two events
	similarity := 0.0
	weights := 0.0

	// Type similarity (weight: 0.3)
	if event1.Type == event2.Type {
		similarity += 0.3
	}
	weights += 0.3

	// Source similarity (weight: 0.2)
	if event1.Source == event2.Source {
		similarity += 0.2
	}
	weights += 0.2

	// Severity similarity (weight: 0.2)
	if event1.Severity == event2.Severity {
		similarity += 0.2
	}
	weights += 0.2

	// Description similarity (weight: 0.3)
	descSimilarity := am.calculateStringSimilarity(event1.Description, event2.Description)
	similarity += 0.3 * descSimilarity
	weights += 0.3

	if weights > 0 {
		return similarity / weights
	}
	return 0.0
}

func (am *AnalyzerMonitor) calculateStringSimilarity(str1, str2 string) float64 {
	// Simple string similarity calculation using common words
	words1 := strings.Fields(strings.ToLower(str1))
	words2 := strings.Fields(strings.ToLower(str2))

	if len(words1) == 0 || len(words2) == 0 {
		return 0.0
	}

	commonWords := 0
	word1Set := make(map[string]bool)
	for _, word := range words1 {
		word1Set[word] = true
	}

	for _, word := range words2 {
		if word1Set[word] {
			commonWords++
		}
	}

	maxLen := math.Max(float64(len(words1)), float64(len(words2)))
	return float64(commonWords) / maxLen
}

func (am *AnalyzerMonitor) createPatternFromEvents(events []SecurityEvent) ThreatPattern {
	// Create a threat pattern from a group of similar events
	if len(events) == 0 {
		return ThreatPattern{}
	}

	firstEvent := events[0]
	pattern := ThreatPattern{
		ID:              fmt.Sprintf("pattern_%s_%d", firstEvent.Type, time.Now().Unix()),
		Name:            fmt.Sprintf("%s Pattern", firstEvent.Type),
		Category:        am.categorizeEvent(firstEvent),
		Description:     fmt.Sprintf("Pattern observed from %d similar events", len(events)),
		Sequence:        events,
		Frequency:       len(events),
		LastSeen:        time.Now(),
		ThreatScore:     am.calculatePatternThreatScore(events),
		Characteristics: make(map[string]interface{}),
	}

	// Extract common characteristics
	sources := make(map[string]int)
	targets := make(map[string]int)
	severities := make(map[string]int)

	for _, event := range events {
		sources[event.Source]++
		targets[event.Target]++
		severities[event.Severity]++
	}

	pattern.Characteristics["common_sources"] = sources
	pattern.Characteristics["common_targets"] = targets
	pattern.Characteristics["severity_distribution"] = severities

	return pattern
}

func (am *AnalyzerMonitor) calculatePatternThreatScore(events []SecurityEvent) float64 {
	// Calculate threat score for a pattern based on its events
	baseScore := 0.0

	for _, event := range events {
		switch event.Severity {
		case "critical":
			baseScore += 10.0
		case "high":
			baseScore += 7.0
		case "medium":
			baseScore += 4.0
		case "low":
			baseScore += 1.0
		}
	}

	// Average the scores
	if len(events) > 0 {
		baseScore = baseScore / float64(len(events))
	}

	// Boost score based on frequency
	frequencyMultiplier := 1.0 + float64(len(events))*0.1

	return baseScore * frequencyMultiplier
}

func (am *AnalyzerMonitor) learnNewPatterns(ctx context.Context, patterns []ThreatPattern) {
	// Learn new patterns and update the pattern recognition engine
	for _, pattern := range patterns {
		if pattern.ThreatScore >= am.config.PatternSignificanceScore {
			am.mu.Lock()
			am.historicalPatterns[pattern.ID] = pattern
			am.mu.Unlock()

			am.LogEvent(zerolog.InfoLevel, "New threat pattern learned").
				Str("pattern_id", pattern.ID).
				Str("category", pattern.Category).
				Float64("threat_score", pattern.ThreatScore)
		}
	}
}

// Anomaly detection methods
type Anomaly struct {
	Type        string                 `json:"type"`
	Score       float64                `json:"score"`
	Description string                 `json:"description"`
	Context     map[string]interface{} `json:"context"`
	Timestamp   time.Time              `json:"timestamp"`
}

func (am *AnalyzerMonitor) collectCurrentBehavior(ctx context.Context) BehaviorBaseline {
	// Collect current system behavior for comparison with baseline
	// This would integrate with system monitoring tools
	return BehaviorBaseline{
		EventFrequency:  make(map[string]float64),
		UserBehavior:    make(map[string]UserProfile),
		SystemBehavior:  SystemProfile{},
		NetworkBehavior: NetworkProfile{},
		LastUpdated:     time.Now(),
		SampleCount:     1,
	}
}

func (am *AnalyzerMonitor) detectAnomalies(current, baseline BehaviorBaseline) []Anomaly {
	// Detect anomalies by comparing current behavior with baseline
	anomalies := make([]Anomaly, 0)

	// Check event frequency anomalies
	for eventType, currentFreq := range current.EventFrequency {
		if baselineFreq, exists := baseline.EventFrequency[eventType]; exists {
			deviation := math.Abs(currentFreq-baselineFreq) / baselineFreq
			if deviation > am.anomalyThreshold {
				anomalies = append(anomalies, Anomaly{
					Type:        "event_frequency",
					Score:       deviation,
					Description: fmt.Sprintf("Unusual frequency for event type %s", eventType),
					Context: map[string]interface{}{
						"event_type":    eventType,
						"current_freq":  currentFreq,
						"baseline_freq": baselineFreq,
						"deviation":     deviation,
					},
					Timestamp: time.Now(),
				})
			}
		}
	}

	return anomalies
}

func (am *AnalyzerMonitor) processAnomaly(ctx context.Context, anomaly Anomaly) {
	// Process detected anomaly
	am.PublishEvent(ctx, events.EventSystemAnomaly, anomaly.Type,
		fmt.Sprintf("Behavioral anomaly detected: %s", anomaly.Description),
		am.getSeverityFromScore(anomaly.Score),
		map[string]interface{}{
			"anomaly_type":  anomaly.Type,
			"anomaly_score": anomaly.Score,
			"context":       anomaly.Context,
		})

	am.LogEvent(zerolog.WarnLevel, "Behavioral anomaly processed").
		Str("type", anomaly.Type).
		Float64("score", anomaly.Score).
		Str("description", anomaly.Description)
}

func (am *AnalyzerMonitor) getSeverityFromScore(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

func (am *AnalyzerMonitor) updateBehaviorBaseline(current BehaviorBaseline) {
	// Update behavior baseline with current observations
	am.mu.Lock()
	defer am.mu.Unlock()

	// Simple exponential moving average update
	alpha := 0.1 // Learning rate

	for eventType, currentFreq := range current.EventFrequency {
		if baselineFreq, exists := am.behaviorBaseline.EventFrequency[eventType]; exists {
			am.behaviorBaseline.EventFrequency[eventType] = alpha*currentFreq + (1-alpha)*baselineFreq
		} else {
			am.behaviorBaseline.EventFrequency[eventType] = currentFreq
		}
	}

	am.behaviorBaseline.LastUpdated = time.Now()
	am.behaviorBaseline.SampleCount++
}

// Threat correlation methods
func (am *AnalyzerMonitor) correlateThreats(ctx context.Context) []ActiveThreat {
	// Correlate threats across different sources and time windows
	correlatedThreats := make([]ActiveThreat, 0)

	am.mu.RLock()
	threats := make([]ActiveThreat, 0, len(am.activeThreats))
	for _, threat := range am.activeThreats {
		threats = append(threats, threat)
	}
	am.mu.RUnlock()

	// Find threats that might be related
	for i, threat1 := range threats {
		for j, threat2 := range threats {
			if i >= j {
				continue
			}

			correlation := am.calculateThreatCorrelation(threat1, threat2)
			if correlation > 0.7 {
				// These threats are likely related
				mergedThreat := am.mergeThreats(threat1, threat2)
				correlatedThreats = append(correlatedThreats, mergedThreat)
			}
		}
	}

	return correlatedThreats
}

func (am *AnalyzerMonitor) calculateThreatCorrelation(threat1, threat2 ActiveThreat) float64 {
	// Calculate correlation between two threats
	correlation := 0.0

	// Time correlation - threats happening close together are more likely related
	timeDiff := math.Abs(threat1.StartTime.Sub(threat2.StartTime).Hours())
	timeCorr := math.Max(0, 1.0-timeDiff/24.0) // Correlation decreases over 24 hours
	correlation += 0.3 * timeCorr

	// Target correlation - same or related targets
	if len(threat1.AffectedAssets) > 0 && len(threat2.AffectedAssets) > 0 {
		commonAssets := am.calculateCommonAssets(threat1.AffectedAssets, threat2.AffectedAssets)
		assetCorr := float64(commonAssets) / math.Max(float64(len(threat1.AffectedAssets)), float64(len(threat2.AffectedAssets)))
		correlation += 0.4 * assetCorr
	}

	// Category correlation - similar attack types
	if threat1.Analysis.Category == threat2.Analysis.Category {
		correlation += 0.3
	}

	return correlation
}

func (am *AnalyzerMonitor) calculateCommonAssets(assets1, assets2 []string) int {
	assetSet := make(map[string]bool)
	for _, asset := range assets1 {
		assetSet[asset] = true
	}

	common := 0
	for _, asset := range assets2 {
		if assetSet[asset] {
			common++
		}
	}

	return common
}

func (am *AnalyzerMonitor) mergeThreats(threat1, threat2 ActiveThreat) ActiveThreat {
	// Merge two correlated threats into one
	merged := ActiveThreat{
		ID:          fmt.Sprintf("merged_%s_%s", threat1.ID, threat2.ID),
		StartTime:   threat1.StartTime,
		Events:      append(threat1.Events, threat2.Events...),
		ThreatScore: (threat1.ThreatScore + threat2.ThreatScore) * 1.2, // Boost for correlation
	}

	if threat2.StartTime.Before(threat1.StartTime) {
		merged.StartTime = threat2.StartTime
	}

	if threat1.LastActivity.After(threat2.LastActivity) {
		merged.LastActivity = threat1.LastActivity
	} else {
		merged.LastActivity = threat2.LastActivity
	}

	// Merge affected assets
	assetSet := make(map[string]bool)
	for _, asset := range threat1.AffectedAssets {
		assetSet[asset] = true
	}
	for _, asset := range threat2.AffectedAssets {
		assetSet[asset] = true
	}

	merged.AffectedAssets = make([]string, 0, len(assetSet))
	for asset := range assetSet {
		merged.AffectedAssets = append(merged.AffectedAssets, asset)
	}

	return merged
}

func (am *AnalyzerMonitor) updateThreatScore(ctx context.Context, threat ActiveThreat) {
	// Update threat score based on correlation and new analysis
	am.mu.Lock()
	if existing, exists := am.activeThreats[threat.ID]; exists {
		existing.ThreatScore = threat.ThreatScore
		am.activeThreats[threat.ID] = existing
	}
	am.mu.Unlock()
}

// Containment planning methods
func (am *AnalyzerMonitor) generateContainmentPlan(ctx context.Context, threat ActiveThreat) ContainmentPlan {
	// Generate containment plan based on threat analysis
	plan := ContainmentPlan{
		Strategy:      am.selectContainmentStrategy(threat),
		Phase:         "preparation",
		Actions:       []ContainmentAction{},
		Timeline:      "immediate",
		Resources:     []string{},
		RollbackPlan:  []ContainmentAction{},
		ApprovalLevel: am.getRequiredApprovalLevel(threat),
	}

	// Generate specific actions based on threat type
	actions := am.generateContainmentActions(threat)
	plan.Actions = actions

	// Generate rollback actions
	rollbackActions := am.generateRollbackActions(actions)
	plan.RollbackPlan = rollbackActions

	return plan
}

func (am *AnalyzerMonitor) selectContainmentStrategy(threat ActiveThreat) string {
	// Select appropriate containment strategy based on threat characteristics
	switch threat.Analysis.Category {
	case "malware":
		return "isolate_and_clean"
	case "data_exfiltration":
		return "network_isolation"
	case "privilege_escalation":
		return "account_lockdown"
	case "rootkit":
		return "system_rebuild"
	default:
		return "monitor_and_analyze"
	}
}

func (am *AnalyzerMonitor) getRequiredApprovalLevel(threat ActiveThreat) string {
	// Determine required approval level based on threat score and impact
	switch {
	case threat.ThreatScore >= 8.0:
		return "executive"
	case threat.ThreatScore >= 5.0:
		return "manager"
	case threat.ThreatScore >= 2.0:
		return "supervisor"
	default:
		return "automated"
	}
}

func (am *AnalyzerMonitor) generateContainmentActions(threat ActiveThreat) []ContainmentAction {
	// Generate specific containment actions based on threat analysis
	actions := make([]ContainmentAction, 0)
	// Network isolation for network-based threats
	if threat.Analysis.AttackVector == "network" {
		actions = append(actions, ContainmentAction{
			ID:          fmt.Sprintf("isolate_network_%s", threat.ID),
			Type:        "network_isolation",
			Description: "Isolate affected network segment",
			Target:      "network_segment",
			Parameters: map[string]interface{}{
				"affected_ips": threat.AffectedAssets,
				"duration":     "1h",
			},
			Priority:  1,
			Automated: am.config.AutoContainmentEnabled,
			Status:    "planned",
		})
	}

	return actions
}

func (am *AnalyzerMonitor) extractProcessNames(events []SecurityEvent) []string {
	// Extract process names from security events
	processes := make(map[string]bool)

	for _, event := range events {
		if processName, ok := event.Data["process_name"]; ok {
			if name, ok := processName.(string); ok {
				processes[name] = true
			}
		}
		if strings.Contains(event.Description, "process") {
			// Try to extract process name from description
			words := strings.Fields(event.Description)
			for i, word := range words {
				if word == "process" && i+1 < len(words) {
					processes[words[i+1]] = true
				}
			}
		}
	}

	result := make([]string, 0, len(processes))
	for process := range processes {
		result = append(result, process)
	}

	return result
}

func (am *AnalyzerMonitor) extractUserAccounts(events []SecurityEvent) []string {
	// Extract user accounts from security events
	accounts := make(map[string]bool)

	for _, event := range events {
		if username, ok := event.Data["username"]; ok {
			if name, ok := username.(string); ok {
				accounts[name] = true
			}
		}
		if account, ok := event.Data["account"]; ok {
			if name, ok := account.(string); ok {
				accounts[name] = true
			}
		}
	}

	result := make([]string, 0, len(accounts))
	for account := range accounts {
		result = append(result, account)
	}

	return result
}

func (am *AnalyzerMonitor) updateThreatContainment(threatID string, plan ContainmentPlan) {
	// Update threat with containment plan
	am.mu.Lock()
	if threat, exists := am.activeThreats[threatID]; exists {
		threat.ContainmentStatus = "planned"
		am.activeThreats[threatID] = threat
	}
	am.mu.Unlock()
}

// Analysis reporting methods
func (am *AnalyzerMonitor) generateAnalysisReport(ctx context.Context) {
	am.LogEvent(zerolog.InfoLevel, "Generating comprehensive analysis report...")

	// Generate findings from all analysis components
	findings := am.generateFindings()

	// Create comprehensive analysis result
	result := AnalysisResult{
		ID:              fmt.Sprintf("analysis_%d", time.Now().Unix()),
		Timestamp:       time.Now(),
		AnalysisType:    "comprehensive",
		Findings:        findings,
		RiskAssessment:  am.generateOverallRiskAssessment(),
		Recommendations: am.generateRecommendations(),
		Confidence:      am.calculateOverallConfidence(findings),
	}

	// Add AI analysis if enabled
	if am.config.ExternalAIEnabled {
		result.AIAnalysis = am.performAIAnalysis(ctx, result)
	}

	// Store analysis result
	am.mu.Lock()
	am.analysisHistory = append(am.analysisHistory, result)
	// Keep only last 100 analysis results
	if len(am.analysisHistory) > 100 {
		am.analysisHistory = am.analysisHistory[1:]
	}
	am.mu.Unlock()

	// Publish analysis event
	am.PublishEvent(ctx, events.EventThreatDetected, "comprehensive_analysis",
		fmt.Sprintf("Comprehensive threat analysis completed: %d findings", len(findings)),
		am.getSeverityFromRisk(result.RiskAssessment.OverallRisk),
		map[string]interface{}{
			"analysis_id":    result.ID,
			"findings_count": len(findings),
			"risk_score":     result.RiskAssessment.RiskScore,
			"confidence":     result.Confidence,
			"threats_active": len(am.activeThreats),
		})
}

func (am *AnalyzerMonitor) generateFindings() []Finding {
	// Generate findings from analysis components
	findings := make([]Finding, 0)

	// Add threat findings
	am.mu.RLock()
	for _, threat := range am.activeThreats {
		finding := Finding{
			Type:        "active_threat",
			Description: fmt.Sprintf("Active threat detected: %s", threat.Analysis.Category),
			Evidence:    am.generateEvidenceFromThreat(threat),
			Confidence:  0.8,
			Severity:    am.getSeverityFromScore(threat.ThreatScore),
			Context: map[string]interface{}{
				"threat_id":       threat.ID,
				"category":        threat.Analysis.Category,
				"attack_vector":   threat.Analysis.AttackVector,
				"affected_assets": threat.AffectedAssets,
				"start_time":      threat.StartTime,
			},
		}
		findings = append(findings, finding)
	}

	// Add pattern findings
	for _, pattern := range am.historicalPatterns {
		if pattern.LastSeen.After(time.Now().Add(-24*time.Hour)) && pattern.ThreatScore > 5.0 {
			finding := Finding{
				Type:        "threat_pattern",
				Description: fmt.Sprintf("Significant threat pattern: %s", pattern.Name),
				Evidence:    am.generateEvidenceFromPattern(pattern),
				Confidence:  0.7,
				Severity:    am.getSeverityFromScore(pattern.ThreatScore),
				Context: map[string]interface{}{
					"pattern_id":   pattern.ID,
					"category":     pattern.Category,
					"frequency":    pattern.Frequency,
					"threat_score": pattern.ThreatScore,
				},
			}
			findings = append(findings, finding)
		}
	}
	am.mu.RUnlock()

	// Sort findings by severity and confidence
	sort.Slice(findings, func(i, j int) bool {
		severityScore := func(severity string) int {
			switch severity {
			case "critical":
				return 4
			case "high":
				return 3
			case "medium":
				return 2
			case "low":
				return 1
			default:
				return 0
			}
		}

		iScore := severityScore(findings[i].Severity)
		jScore := severityScore(findings[j].Severity)

		if iScore == jScore {
			return findings[i].Confidence > findings[j].Confidence
		}
		return iScore > jScore
	})

	return findings
}

func (am *AnalyzerMonitor) generateEvidenceFromThreat(threat ActiveThreat) []Evidence {
	// Generate evidence from threat events
	evidence := make([]Evidence, 0)

	for _, event := range threat.Events {
		ev := Evidence{
			Type:        "security_event",
			Source:      event.Source,
			Description: event.Description,
			Data:        event.Data,
			Timestamp:   event.Timestamp,
			Hash:        am.calculateEventHash(event),
		}
		evidence = append(evidence, ev)
	}

	return evidence
}

func (am *AnalyzerMonitor) generateEvidenceFromPattern(pattern ThreatPattern) []Evidence {
	// Generate evidence from threat pattern
	evidence := make([]Evidence, 0)

	ev := Evidence{
		Type:        "threat_pattern",
		Source:      "pattern_recognition",
		Description: pattern.Description,
		Data: map[string]interface{}{
			"indicators":      pattern.Indicators,
			"frequency":       pattern.Frequency,
			"characteristics": pattern.Characteristics,
		},
		Timestamp: pattern.LastSeen,
		Hash:      pattern.ID,
	}
	evidence = append(evidence, ev)

	return evidence
}

func (am *AnalyzerMonitor) calculateEventHash(event SecurityEvent) string {
	// Calculate hash for event evidence
	data := fmt.Sprintf("%s_%s_%s_%s",
		event.Type, event.Source, event.Target, event.Timestamp.Format(time.RFC3339))
	return fmt.Sprintf("hash_%x", []byte(data)[:8])
}

func (am *AnalyzerMonitor) generateOverallRiskAssessment() RiskAssessment {
	// Generate overall risk assessment
	assessment := RiskAssessment{
		OverallRisk:      "low",
		RiskScore:        0.0,
		BusinessImpact:   "minimal",
		TechnicalImpact:  "minimal",
		Likelihood:       0.1,
		AffectedSystems:  []string{},
		DataAtRisk:       []string{},
		ComplianceImpact: []string{},
	}

	// Calculate risk based on active threats
	am.mu.RLock()
	threatCount := len(am.activeThreats)
	maxThreatScore := 0.0
	allAffectedSystems := make(map[string]bool)

	for _, threat := range am.activeThreats {
		if threat.ThreatScore > maxThreatScore {
			maxThreatScore = threat.ThreatScore
		}
		for _, asset := range threat.AffectedAssets {
			allAffectedSystems[asset] = true
		}
	}
	am.mu.RUnlock()

	// Set risk level based on threat count and max score
	switch {
	case threatCount >= 5 || maxThreatScore >= 8.0:
		assessment.OverallRisk = "critical"
		assessment.BusinessImpact = "severe"
		assessment.TechnicalImpact = "severe"
		assessment.Likelihood = 0.9
	case threatCount >= 3 || maxThreatScore >= 6.0:
		assessment.OverallRisk = "high"
		assessment.BusinessImpact = "significant"
		assessment.TechnicalImpact = "significant"
		assessment.Likelihood = 0.7
	case threatCount >= 1 || maxThreatScore >= 4.0:
		assessment.OverallRisk = "medium"
		assessment.BusinessImpact = "moderate"
		assessment.TechnicalImpact = "moderate"
		assessment.Likelihood = 0.5
	case maxThreatScore >= 2.0:
		assessment.OverallRisk = "low"
		assessment.BusinessImpact = "minimal"
		assessment.TechnicalImpact = "minimal"
		assessment.Likelihood = 0.3
	}

	assessment.RiskScore = maxThreatScore

	// Convert affected systems map to slice
	for system := range allAffectedSystems {
		assessment.AffectedSystems = append(assessment.AffectedSystems, system)
	}

	return assessment
}

func (am *AnalyzerMonitor) generateRecommendations() []Recommendation {
	// Generate recommendations based on analysis
	recommendations := make([]Recommendation, 0)

	am.mu.RLock()
	threatCount := len(am.activeThreats)

	// High-level recommendations based on threat landscape
	if threatCount > 0 {
		rec := Recommendation{
			Priority:      "high",
			Action:        "immediate_containment",
			Description:   "Implement containment measures for active threats",
			Timeline:      "immediate",
			Resources:     []string{"security_tam", "system_admin"},
			RiskReduction: 0.7,
			Dependencies:  []string{},
		}
		recommendations = append(recommendations, rec)
	}

	// Pattern-based recommendations
	for _, pattern := range am.historicalPatterns {
		if pattern.ThreatScore > 6.0 && pattern.Frequency > 5 {
			rec := Recommendation{
				Priority:      "medium",
				Action:        "strengthen_defenses",
				Description:   fmt.Sprintf("Strengthen defenses against %s attacks", pattern.Category),
				Timeline:      "1-2 days",
				Resources:     []string{"security_tam"},
				RiskReduction: 0.5,
				Dependencies:  []string{"threat_analysis_complete"},
			}
			recommendations = append(recommendations, rec)
		}
	}
	am.mu.RUnlock()

	// System-wide recommendations
	if am.config.AnomalyDetectionEnabled {
		rec := Recommendation{
			Priority:      "low",
			Action:        "baseline_update",
			Description:   "Update behavior baselines with recent observations",
			Timeline:      "weekly",
			Resources:     []string{"automated_system"},
			RiskReduction: 0.2,
			Dependencies:  []string{},
		}
		recommendations = append(recommendations, rec)
	}

	return recommendations
}

func (am *AnalyzerMonitor) calculateOverallConfidence(findings []Finding) float64 {
	// Calculate overall confidence based on findings
	if len(findings) == 0 {
		return 0.5 // Default confidence when no findings
	}

	totalConfidence := 0.0
	for _, finding := range findings {
		totalConfidence += finding.Confidence
	}

	return totalConfidence / float64(len(findings))
}

func (am *AnalyzerMonitor) getSeverityFromRisk(risk string) string {
	// Convert risk level to event severity
	switch risk {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

func (am *AnalyzerMonitor) performAIAnalysis(ctx context.Context, result AnalysisResult) AIAnalysisResult {
	// Perform AI analysis using external service
	// This would integrate with external AI services like OpenAI, Claude, etc.
	aiResult := AIAnalysisResult{
		Provider:   "placeholder_ai",
		Analysis:   "AI analysis placeholder - would integrate with external AI service",
		Confidence: 0.6,
		Suggestions: []string{
			"Consider implementing additional monitoring for detected patterns",
			"Review and update incident response procedures",
			"Enhance network segmentation to limit threat propagation",
		},
		Context: map[string]interface{}{
			"threats_analyzed": len(am.activeThreats),
			"patterns_found":   len(am.historicalPatterns),
		},
		ProcessedAt: time.Now(),
	}

	return aiResult
}

// Metrics and state management
func (am *AnalyzerMonitor) updateAnalysisMetrics() {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Update state with current metrics
	am.UpdateState("active_threats_count", len(am.activeThreats))
	am.UpdateState("patterns_learned", len(am.historicalPatterns))
	am.UpdateState("analysis_history_count", len(am.analysisHistory))

	// Calculate threat distribution
	threatsByCategory := make(map[string]int)
	threatsByStage := make(map[string]int)
	totalThreatScore := 0.0

	for _, threat := range am.activeThreats {
		threatsByCategory[threat.Analysis.Category]++
		threatsByStage[threat.ProgressStage]++
		totalThreatScore += threat.ThreatScore
	}

	am.UpdateState("threats_by_category", threatsByCategory)
	am.UpdateState("threats_by_stage", threatsByStage)

	if len(am.activeThreats) > 0 {
		am.UpdateState("average_threat_score", totalThreatScore/float64(len(am.activeThreats)))
	} else {
		am.UpdateState("average_threat_score", 0.0)
	}

	// Pattern metrics
	patternsByCategory := make(map[string]int)
	for _, pattern := range am.historicalPatterns {
		patternsByCategory[pattern.Category]++
	}
	am.UpdateState("patterns_by_category", patternsByCategory)

	// Component status
	componentStatus := map[string]bool{
		"threat_analysis":      true,
		"pattern_recognition":  am.config.PatternLearningEnabled,
		"anomaly_detection":    am.config.AnomalyDetectionEnabled,
		"threat_correlation":   am.config.ThreatCorrelationEnabled,
		"containment_planning": am.config.ContainmentEnabled,
		"ai_integration":       am.config.ExternalAIEnabled,
	}
	am.UpdateState("component_status", componentStatus)

	am.UpdateState("last_analysis_time", time.Now())
	am.UpdateState("analyzer_status", "active")
}

// Configuration and initialization methods
func (am *AnalyzerMonitor) initializeAnalysisEngines() {
	// Initialize the analysis engines
	am.analysisEngine = &ThreatAnalysisEngine{
		correlationRules:  am.initializeCorrelationRules(),
		threatClassifiers: am.initializeThreatClassifiers(),
		analysisQueue:     make(chan SecurityEvent, 100),
		resultChannel:     make(chan AnalysisResult, 50),
	}

	am.patternRecognition = &PatternRecognitionEngine{
		knownPatterns:    make(map[string]ThreatPattern),
		learningPatterns: make(map[string]PartialPattern),
		featureExtractor: am.initializeFeatureExtractor(),
	}

	am.containmentStrategy = &ContainmentStrategyEngine{
		strategies:      am.initializeContainmentStrategies(),
		actionTemplates: am.initializeActionTemplates(),
		approvalQueue:   make(chan ContainmentRequest, 20),
		executionQueue:  make(chan ContainmentAction, 50),
	}
}

func (am *AnalyzerMonitor) initializeCorrelationRules() []CorrelationRule {
	// Initialize correlation rules for threat detection
	return []CorrelationRule{
		{
			ID:         "malware_network_correlation",
			Name:       "Malware with Network Activity",
			EventTypes: []events.EventType{events.EventMalwareDetected, events.EventSuspiciousNetwork},
			TimeWindow: 30 * time.Minute,
			Conditions: []Condition{
				{Field: "severity", Operator: ">=", Value: "medium", Weight: 0.7},
			},
			Weight:  0.8,
			Enabled: true,
		},
		{
			ID:         "privilege_escalation_persistence",
			Name:       "Privilege Escalation with Persistence",
			EventTypes: []events.EventType{events.EventPrivilegeEscalation, events.EventFileSystemChange},
			TimeWindow: 60 * time.Minute,
			Conditions: []Condition{
				{Field: "target_type", Operator: "==", Value: "system", Weight: 0.6},
			},
			Weight:  0.9,
			Enabled: true,
		},
	}
}

func (am *AnalyzerMonitor) initializeThreatClassifiers() []ThreatClassifier {
	// Initialize threat classifiers for categorization
	return []ThreatClassifier{
		{
			Category:   "advanced_persistent_threat",
			Indicators: []string{"lateral_movement", "persistence", "data_collection", "stealth"},
			Weights: map[string]float64{
				"lateral_movement": 0.3,
				"persistence":      0.3,
				"data_collection":  0.2,
				"stealth":          0.2,
			},
			Threshold: 0.7,
		},
		{
			Category:   "ransomware",
			Indicators: []string{"file_encryption", "ransom_note", "process_injection", "network_discovery"},
			Weights: map[string]float64{
				"file_encryption":   0.4,
				"ransom_note":       0.3,
				"process_injection": 0.2,
				"network_discovery": 0.1,
			},
			Threshold: 0.6,
		},
	}
}

func (am *AnalyzerMonitor) initializeFeatureExtractor() FeatureExtractor {
	// Initialize feature extractor for pattern recognition
	return FeatureExtractor{
		Features: map[string]FeatureDefinition{
			"event_frequency": {
				Type:       "numerical",
				Extractor:  "count_per_hour",
				Weight:     0.3,
				Normalizer: "min_max",
			},
			"severity_distribution": {
				Type:       "categorical",
				Extractor:  "severity_histogram",
				Weight:     0.4,
				Normalizer: "none",
			},
			"source_diversity": {
				Type:       "numerical",
				Extractor:  "unique_sources",
				Weight:     0.3,
				Normalizer: "log_scale",
			},
		},
	}
}

func (am *AnalyzerMonitor) initializePatternLearning() {
	// Initialize pattern learning capabilities
	am.LogEvent(zerolog.InfoLevel, "Initializing pattern learning capabilities")
}

func (am *AnalyzerMonitor) initializeBehaviorBaseline() {
	// Initialize behavior baseline for anomaly detection
	am.behaviorBaseline = BehaviorBaseline{
		EventFrequency:  make(map[string]float64),
		UserBehavior:    make(map[string]UserProfile),
		SystemBehavior:  SystemProfile{},
		NetworkBehavior: NetworkProfile{},
		LastUpdated:     time.Now(),
		SampleCount:     0,
	}

	am.LogEvent(zerolog.InfoLevel, "Initialized behavior baseline for anomaly detection")
}

func (am *AnalyzerMonitor) initializeContainmentStrategies() map[string]ContainmentStrategy {
	// Initialize containment strategies
	strategies := make(map[string]ContainmentStrategy)

	strategies["isolate_and_clean"] = ContainmentStrategy{
		Name:        "Isolate and Clean",
		Description: "Isolate affected systems and perform malware removal",
		Phases: []ContainmentPhase{
			{
				Name: "isolation",
				Actions: []ActionTemplate{
					{Type: "network_isolation", Description: "Isolate from network", Automated: true, RiskLevel: "low"},
				},
			},
			{
				Name: "cleaning",
				Actions: []ActionTemplate{
					{Type: "malware_removal", Description: "Remove malware", Automated: false, RiskLevel: "medium"},
				},
			},
		},
		Automated: false,
	}

	return strategies
}

func (am *AnalyzerMonitor) initializeActionTemplates() map[string]ActionTemplate {
	// Initialize action templates
	templates := make(map[string]ActionTemplate)

	templates["network_isolation"] = ActionTemplate{
		Type:        "network_isolation",
		Description: "Isolate system from network",
		Parameters: map[string]interface{}{
			"method":   "firewall_rule",
			"duration": "1h",
		},
		Automated: true,
		RiskLevel: "low",
	}

	templates["process_termination"] = ActionTemplate{
		Type:        "process_termination",
		Description: "Terminate malicious process",
		Parameters: map[string]interface{}{
			"force": true,
		},
		Automated: true,
		RiskLevel: "medium",
	}

	return templates
}

func (am *AnalyzerMonitor) parseConfig(config map[string]interface{}) error {
	// Parse configuration with defaults
	stringConfigs := map[string]*string{
		"analysis_interval":        &am.config.AnalysisInterval,
		"event_analysis_window":    &am.config.EventAnalysisWindow,
		"correlation_time_window":  &am.config.CorrelationTimeWindow,
		"baseline_learning_period": &am.config.BaselineLearningPeriod,
		"model_update_interval":    &am.config.ModelUpdateInterval,
		"ai_analysis_endpoint":     &am.config.AIAnalysisEndpoint,
	}

	for key, ptr := range stringConfigs {
		if val, ok := config[key].(string); ok {
			*ptr = val
		}
	}

	// Parse boolean configurations
	boolConfigs := map[string]*bool{
		"threat_correlation_enabled":    &am.config.ThreatCorrelationEnabled,
		"pattern_learning_enabled":      &am.config.PatternLearningEnabled,
		"historical_analysis_enabled":   &am.config.HistoricalAnalysisEnabled,
		"containment_enabled":           &am.config.ContainmentEnabled,
		"anomaly_detection_enabled":     &am.config.AnomalyDetectionEnabled,
		"auto_containment_enabled":      &am.config.AutoContainmentEnabled,
		"containment_approval_required": &am.config.ContainmentApprovalRequired,
		"external_ai_enabled":           &am.config.ExternalAIEnabled,
		"forensics_integration":         &am.config.ForensicsIntegration,
	}

	for key, ptr := range boolConfigs {
		if val, ok := config[key].(bool); ok {
			*ptr = val
		}
	}

	// Parse numeric configurations
	if val, ok := config["max_analysis_depth"].(int); ok {
		am.config.MaxAnalysisDepth = val
	}
	if val, ok := config["min_pattern_occurrence"].(int); ok {
		am.config.MinPatternOccurrence = val
	}
	if val, ok := config["max_containment_actions"].(int); ok {
		am.config.MaxContainmentActions = val
	}

	// Parse float configurations
	if val, ok := config["threat_score_threshold"].(float64); ok {
		am.config.ThreatScoreThreshold = val
	}
	if val, ok := config["anomaly_threshold"].(float64); ok {
		am.config.AnomalyThreshold = val
	}
	if val, ok := config["pattern_significance_score"].(float64); ok {
		am.config.PatternSignificanceScore = val
	}

	// Parse array configurations
	if categories, ok := config["pattern_categories"].([]interface{}); ok {
		am.config.PatternCategories = make([]string, len(categories))
		for i, cat := range categories {
			if str, ok := cat.(string); ok {
				am.config.PatternCategories[i] = str
			}
		}
	}

	// Set defaults
	am.setConfigDefaults()

	return nil
}

func (am *AnalyzerMonitor) setConfigDefaults() {
	// Set default values for missing configuration
	if am.config.AnalysisInterval == "" {
		am.config.AnalysisInterval = "60s"
	}
	if am.config.EventAnalysisWindow == "" {
		am.config.EventAnalysisWindow = "24h"
	}
	if am.config.CorrelationTimeWindow == "" {
		am.config.CorrelationTimeWindow = "1h"
	}
	if am.config.BaselineLearningPeriod == "" {
		am.config.BaselineLearningPeriod = "7d"
	}
	if am.config.ModelUpdateInterval == "" {
		am.config.ModelUpdateInterval = "1h"
	}
	if am.config.MaxAnalysisDepth == 0 {
		am.config.MaxAnalysisDepth = 10
	}
	if am.config.MinPatternOccurrence == 0 {
		am.config.MinPatternOccurrence = 3
	}
	if am.config.MaxContainmentActions == 0 {
		am.config.MaxContainmentActions = 5
	}
	if am.config.ThreatScoreThreshold == 0 {
		am.config.ThreatScoreThreshold = 5.0
	}
	if am.config.AnomalyThreshold == 0 {
		am.config.AnomalyThreshold = 0.7
	}
	if am.config.PatternSignificanceScore == 0 {
		am.config.PatternSignificanceScore = 6.0
	}
	if len(am.config.PatternCategories) == 0 {
		am.config.PatternCategories = []string{
			"malware", "intrusion", "data_exfiltration",
			"privilege_escalation", "persistence", "reconnaissance",
		}
	}
}

// Public API methods
func (am *AnalyzerMonitor) GetActiveThreats() map[string]ActiveThreat {
	am.mu.RLock()
	defer am.mu.RUnlock()

	threats := make(map[string]ActiveThreat)
	for k, v := range am.activeThreats {
		threats[k] = v
	}
	return threats
}

func (am *AnalyzerMonitor) GetThreatPatterns() map[string]ThreatPattern {
	am.mu.RLock()
	defer am.mu.RUnlock()

	patterns := make(map[string]ThreatPattern)
	for k, v := range am.historicalPatterns {
		patterns[k] = v
	}
	return patterns
}

func (am *AnalyzerMonitor) GetAnalysisHistory() []AnalysisResult {
	am.mu.RLock()
	defer am.mu.RUnlock()

	history := make([]AnalysisResult, len(am.analysisHistory))
	copy(history, am.analysisHistory)
	return history
}

func (am *AnalyzerMonitor) GetConfig() *ComprehensiveAnalyzerConfig {
	return am.config
}

func (am *AnalyzerMonitor) GetBehaviorBaseline() BehaviorBaseline {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.behaviorBaseline
}

// Cleanup method
func (am *AnalyzerMonitor) Cleanup() error {
	am.LogEvent(zerolog.InfoLevel, "Cleaning up Analyzer Monitor resources")
	// Close channels and clean up resources
	if am.analysisEngine != nil {
		close(am.analysisEngine.analysisQueue)
		close(am.analysisEngine.resultChannel)
	}

	if am.containmentStrategy != nil {
		close(am.containmentStrategy.approvalQueue)
		close(am.containmentStrategy.executionQueue)
	}

	am.LogEvent(zerolog.InfoLevel, "Analyzer Monitor cleanup completed")
	return nil
}

func (am *AnalyzerMonitor) generateRollbackActions(actions []ContainmentAction) []ContainmentAction {
	// Generate rollback actions for containment actions
	rollbackActions := make([]ContainmentAction, 0)

	for _, action := range actions {
		rollback := ContainmentAction{
			ID:          fmt.Sprintf("rollback_%s", action.ID),
			Type:        fmt.Sprintf("rollback_%s", action.Type),
			Description: fmt.Sprintf("Rollback action: %s", action.Description),
			Target:      action.Target,
			Parameters:  action.Parameters,
			Priority:    action.Priority,
			Automated:   false, // Rollbacks should be manual
			Status:      "planned",
		}
		rollbackActions = append(rollbackActions, rollback)
	}

	return rollbackActions
}
