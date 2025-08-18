// pkg/monitors/scribe/scribe_monitor.go
package scribe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/monitors/base"
	"github.com/lucid-vigil/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
)

// ScribeMonitor crafts legally-sound forensic documentation for legal cases
// Generates non-technical and technical reports for each incident
type ScribeMonitor struct {
	*base.BaseMonitor
	config    *ScribeConfig
	incidents []ForensicIncident
}

// ScribeConfig holds configuration for the ScribeMonitor
type ScribeConfig struct {
	ReportFormats   []string `mapstructure:"report_formats"`
	EvidenceStorage string   `mapstructure:"evidence_storage"`
	ChainOfCustody  bool     `mapstructure:"chain_of_custody"`
	DigitalSigning  bool     `mapstructure:"digital_signing"`
	RetentionDays   int      `mapstructure:"retention_days"`
	LegalCompliance []string `mapstructure:"legal_compliance"`
}

// ForensicIncident represents a complete forensic incident record
type ForensicIncident struct {
	ID               string                 `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	IncidentType     string                 `json:"incident_type"`
	Severity         string                 `json:"severity"`
	Source           string                 `json:"source"`
	TechnicalDetails map[string]interface{} `json:"technical_details"`
	Evidence         []EvidenceItem         `json:"evidence"`
	Reports          []Report               `json:"reports"`
	LegalReadiness   bool                   `json:"legal_readiness"`
	ChainOfCustody   ChainOfCustodyRecord   `json:"chain_of_custody"`
	Status           string                 `json:"status"` // "active", "investigated", "closed"
}

// EvidenceItem represents a piece of digital evidence
type EvidenceItem struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"` // "file", "log", "network", "memory"
	Path      string            `json:"path"`
	Hash      string            `json:"hash"`
	Size      int64             `json:"size"`
	Timestamp time.Time         `json:"timestamp"`
	Collector string            `json:"collector"` // Who/what collected this evidence
	Metadata  map[string]string `json:"metadata"`
	ChainHash string            `json:"chain_hash"` // For chain of custody
}

// Report represents a generated forensic report
type Report struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`   // "technical", "executive", "legal"
	Format    string    `json:"format"` // "pdf", "json", "html"
	Title     string    `json:"title"`
	Content   []byte    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	Author    string    `json:"author"`
	Signature string    `json:"signature"`
	FilePath  string    `json:"file_path"`
}

// ChainOfCustodyRecord maintains the legal chain of custody
type ChainOfCustodyRecord struct {
	Entries []CustodyEntry `json:"entries"`
}

// CustodyEntry represents a single chain of custody entry
type CustodyEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"` // "collected", "analyzed", "transferred", "stored"
	Person    string    `json:"person"`
	Location  string    `json:"location"`
	Purpose   string    `json:"purpose"`
	Hash      string    `json:"hash"` // Hash at time of action
	Signature string    `json:"signature"`
}

// NewScribeMonitor creates a new ScribeMonitor
func NewScribeMonitor(logger zerolog.Logger) scheduler.Monitor {
	return &ScribeMonitor{
		BaseMonitor: base.NewBaseMonitor("scribe", logger),
		config:      &ScribeConfig{},
		incidents:   make([]ForensicIncident, 0),
	}
}

// Configure sets up the scribe monitor with the provided configuration
func (sm *ScribeMonitor) Configure(config map[string]interface{}) error {
	// Parse configuration
	if reportFormats, ok := config["report_formats"].([]interface{}); ok {
		sm.config.ReportFormats = make([]string, len(reportFormats))
		for i, format := range reportFormats {
			if str, ok := format.(string); ok {
				sm.config.ReportFormats[i] = str
			}
		}
	}

	if evidenceStorage, ok := config["evidence_storage"].(string); ok {
		sm.config.EvidenceStorage = evidenceStorage
	}

	if chainOfCustody, ok := config["chain_of_custody"].(bool); ok {
		sm.config.ChainOfCustody = chainOfCustody
	}

	if digitalSigning, ok := config["digital_signing"].(bool); ok {
		sm.config.DigitalSigning = digitalSigning
	}

	if retentionDays, ok := config["retention_days"].(int); ok {
		sm.config.RetentionDays = retentionDays
	}

	// Ensure evidence storage directory exists
	if sm.config.EvidenceStorage != "" {
		if err := os.MkdirAll(sm.config.EvidenceStorage, 0750); err != nil {
			return fmt.Errorf("failed to create evidence storage directory: %w", err)
		}
	}

	sm.LogEvent(zerolog.InfoLevel, "Scribe monitor configured successfully.")
	return nil
}

// Run executes the scribe monitoring logic
func (sm *ScribeMonitor) Run(ctx context.Context) {
	sm.LogEvent(zerolog.InfoLevel, "Scribe Monitor: Documenting security incidents...")

	// Collect incident data from other monitors
	sm.collectIncidentData()

	// Generate forensic documentation
	sm.generateForensicReports()

	// Maintain chain of custody
	sm.maintainChainOfCustody()

	// Prepare legal-ready documentation
	sm.prepareLegalDocumentation(ctx)

	// Clean up old incidents based on retention policy
	sm.cleanupOldIncidents()

	// Update metrics
	sm.updateMetrics()

	sm.LogEvent(zerolog.InfoLevel, "Scribe Monitor documentation cycle complete.")
}

// collectIncidentData collects incident data from other monitors
func (sm *ScribeMonitor) collectIncidentData() {
	sm.LogEvent(zerolog.DebugLevel, "Collecting incident data from security events...")

	// In a real implementation, this would:
	// 1. Query a shared event bus or database for new security events
	// 2. Correlate events into incidents
	// 3. Collect relevant evidence for each incident

	// For now, we'll simulate finding incidents
	sm.simulateIncidentCollection()
}

// simulateIncidentCollection creates sample incidents for demonstration
func (sm *ScribeMonitor) simulateIncidentCollection() {
	// This would be replaced with real incident collection logic
	if len(sm.incidents) == 0 {
		sampleIncident := ForensicIncident{
			ID:           generateIncidentID(),
			Timestamp:    time.Now(),
			IncidentType: "suspicious_process",
			Severity:     "medium",
			Source:       "process_monitor",
			TechnicalDetails: map[string]interface{}{
				"process_name": "nc",
				"pid":          12345,
				"command_line": "nc -l -p 4444",
			},
			Evidence:       []EvidenceItem{},
			Reports:        []Report{},
			LegalReadiness: false,
			Status:         "active",
		}

		sm.incidents = append(sm.incidents, sampleIncident)
		sm.LogEvent(zerolog.InfoLevel, "New incident collected").Str("incident_id", sampleIncident.ID)
	}
}

// generateForensicReports creates various types of forensic reports
func (sm *ScribeMonitor) generateForensicReports() {
	sm.LogEvent(zerolog.DebugLevel, "Generating forensic reports...")

	for i, incident := range sm.incidents {
		if len(incident.Reports) == 0 {
			// Generate technical report
			if contains(sm.config.ReportFormats, "json") {
				report := sm.generateTechnicalReport(incident)
				sm.incidents[i].Reports = append(sm.incidents[i].Reports, report)
			}

			// Generate executive summary
			if contains(sm.config.ReportFormats, "html") {
				report := sm.generateExecutiveReport(incident)
				sm.incidents[i].Reports = append(sm.incidents[i].Reports, report)
			}

			// Generate legal report if required
			if sm.config.ChainOfCustody {
				report := sm.generateLegalReport(incident)
				sm.incidents[i].Reports = append(sm.incidents[i].Reports, report)
			}
		}
	}
}

// generateTechnicalReport creates a detailed technical report
func (sm *ScribeMonitor) generateTechnicalReport(incident ForensicIncident) Report {
	reportData := map[string]interface{}{
		"incident_id":       incident.ID,
		"timestamp":         incident.Timestamp,
		"type":              incident.IncidentType,
		"severity":          incident.Severity,
		"technical_details": incident.TechnicalDetails,
		"evidence_summary":  sm.summarizeEvidence(incident.Evidence),
		"generated_at":      time.Now(),
		"generator":         "lucid_vigil_scribe",
	}

	content, _ := json.MarshalIndent(reportData, "", "  ")

	report := Report{
		ID:        generateReportID(),
		Type:      "technical",
		Format:    "json",
		Title:     fmt.Sprintf("Technical Analysis - Incident %s", incident.ID),
		Content:   content,
		Timestamp: time.Now(),
		Author:    "Lucid Vigil Scribe",
	}

	// Save to file if storage configured
	if sm.config.EvidenceStorage != "" {
		filePath := filepath.Join(sm.config.EvidenceStorage, fmt.Sprintf("technical_report_%s.json", incident.ID))
		os.WriteFile(filePath, content, 0640)
		report.FilePath = filePath
	}

	return report
}

// generateExecutiveReport creates an executive summary report
func (sm *ScribeMonitor) generateExecutiveReport(incident ForensicIncident) Report {
	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Executive Summary - Incident %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background-color: #f0f0f0; padding: 20px; border-left: 4px solid #d32f2f; }
        .severity-%s { border-left-color: %s; }
        .details { margin: 20px 0; }
        .timestamp { color: #666; }
    </style>
</head>
<body>
    <div class="header severity-%s">
        <h1>Security Incident Report</h1>
        <p class="timestamp">Generated: %s</p>
        <p><strong>Incident ID:</strong> %s</p>
        <p><strong>Severity:</strong> %s</p>
        <p><strong>Type:</strong> %s</p>
    </div>
    <div class="details">
        <h2>Executive Summary</h2>
        <p>A %s severity security incident was detected by the %s monitor.</p>
        <p>The incident occurred at %s and requires %s attention.</p>
        
        <h2>Recommended Actions</h2>
        <ul>
            <li>Immediate investigation by security team</li>
            <li>Evidence preservation and chain of custody maintenance</li>
            <li>Impact assessment and containment measures</li>
        </ul>
    </div>
</body>
</html>`,
		incident.ID,
		incident.Severity, sm.getSeverityColor(incident.Severity),
		incident.Severity,
		time.Now().Format("2006-01-02 15:04:05"),
		incident.ID,
		incident.Severity,
		incident.IncidentType,
		incident.Severity,
		incident.Source,
		incident.Timestamp.Format("2006-01-02 15:04:05"),
		sm.getAttentionLevel(incident.Severity))

	report := Report{
		ID:        generateReportID(),
		Type:      "executive",
		Format:    "html",
		Title:     fmt.Sprintf("Executive Summary - Incident %s", incident.ID),
		Content:   []byte(htmlContent),
		Timestamp: time.Now(),
		Author:    "Lucid Vigil Scribe",
	}

	// Save to file if storage configured
	if sm.config.EvidenceStorage != "" {
		filePath := filepath.Join(sm.config.EvidenceStorage, fmt.Sprintf("executive_report_%s.html", incident.ID))
		os.WriteFile(filePath, []byte(htmlContent), 0640)
		report.FilePath = filePath
	}

	return report
}

// generateLegalReport creates a legal-compliant report
func (sm *ScribeMonitor) generateLegalReport(incident ForensicIncident) Report {
	legalData := map[string]interface{}{
		"case_reference":    incident.ID,
		"incident_summary":  sm.createLegalSummary(incident),
		"evidence_chain":    incident.ChainOfCustody,
		"compliance_flags":  sm.config.LegalCompliance,
		"generated_by":      "Lucid Vigil Forensic System",
		"generation_time":   time.Now(),
		"digital_signature": "",
	}

	if sm.config.DigitalSigning {
		legalData["digital_signature"] = sm.generateDigitalSignature(legalData)
	}

	content, _ := json.MarshalIndent(legalData, "", "  ")

	report := Report{
		ID:        generateReportID(),
		Type:      "legal",
		Format:    "json",
		Title:     fmt.Sprintf("Legal Report - Incident %s", incident.ID),
		Content:   content,
		Timestamp: time.Now(),
		Author:    "Lucid Vigil Legal Scribe",
	}

	// Save to secure location if storage configured
	if sm.config.EvidenceStorage != "" {
		legalDir := filepath.Join(sm.config.EvidenceStorage, "legal")
		os.MkdirAll(legalDir, 0700) // More restrictive permissions for legal documents
		filePath := filepath.Join(legalDir, fmt.Sprintf("legal_report_%s.json", incident.ID))
		os.WriteFile(filePath, content, 0600)
		report.FilePath = filePath
	}

	return report
}

// maintainChainOfCustody ensures proper chain of custody for all evidence
func (sm *ScribeMonitor) maintainChainOfCustody() {
	sm.LogEvent(zerolog.DebugLevel, "Maintaining chain of custody for evidence...")

	if !sm.config.ChainOfCustody {
		return
	}

	for i, incident := range sm.incidents {
		for j, evidence := range incident.Evidence {
			if evidence.ChainHash == "" {
				// Initialize chain of custody
				entry := CustodyEntry{
					Timestamp: time.Now(),
					Action:    "collected",
					Person:    "lucid_vigil_system",
					Location:  "automated_collection",
					Purpose:   "security_incident_response",
					Hash:      evidence.Hash,
				}

				if sm.incidents[i].ChainOfCustody.Entries == nil {
					sm.incidents[i].ChainOfCustody.Entries = []CustodyEntry{}
				}

				sm.incidents[i].ChainOfCustody.Entries = append(sm.incidents[i].ChainOfCustody.Entries, entry)
				sm.incidents[i].Evidence[j].ChainHash = sm.calculateChainHash(entry)
			}
		}
	}
}

// prepareLegalDocumentation prepares all documentation for legal proceedings
func (sm *ScribeMonitor) prepareLegalDocumentation(ctx context.Context) {
	sm.LogEvent(zerolog.DebugLevel, "Preparing legal documentation...")

	for i, incident := range sm.incidents {
		if !incident.LegalReadiness && len(incident.Reports) > 0 {
			// Verify all reports are complete and signed
			allReportsReady := true
			for _, report := range incident.Reports {
				if report.Type == "legal" && (report.Signature == "" && sm.config.DigitalSigning) {
					allReportsReady = false
					break
				}
			}

			if allReportsReady {
				sm.incidents[i].LegalReadiness = true
				sm.LogEvent(zerolog.InfoLevel, "Incident documentation ready for legal proceedings").
					Str("incident_id", incident.ID)
			}
		}
	}
}

// cleanupOldIncidents removes incidents that exceed the retention policy
func (sm *ScribeMonitor) cleanupOldIncidents() {
	if sm.config.RetentionDays <= 0 {
		return
	}

	cutoffDate := time.Now().AddDate(0, 0, -sm.config.RetentionDays)
	originalCount := len(sm.incidents)

	// Filter out old incidents
	filteredIncidents := make([]ForensicIncident, 0)
	for _, incident := range sm.incidents {
		if incident.Timestamp.After(cutoffDate) {
			filteredIncidents = append(filteredIncidents, incident)
		} else {
			// Archive the incident before removal
			sm.archiveIncident(incident)
		}
	}

	sm.incidents = filteredIncidents
	cleanedCount := originalCount - len(sm.incidents)

	if cleanedCount > 0 {
		sm.LogEvent(zerolog.InfoLevel, "Cleaned up old incidents").
			Int("removed", cleanedCount).
			Int("remaining", len(sm.incidents))
	}
}

// Helper functions

func (sm *ScribeMonitor) updateMetrics() {
	sm.UpdateMetrics("active_incidents", len(sm.incidents))

	totalReports := 0
	legalReadyIncidents := 0
	for _, incident := range sm.incidents {
		totalReports += len(incident.Reports)
		if incident.LegalReadiness {
			legalReadyIncidents++
		}
	}

	sm.UpdateMetrics("total_reports", totalReports)
	sm.UpdateMetrics("legal_ready_incidents", legalReadyIncidents)
}

func (sm *ScribeMonitor) summarizeEvidence(evidence []EvidenceItem) map[string]interface{} {
	summary := map[string]interface{}{
		"total_items": len(evidence),
		"types":       make(map[string]int),
		"total_size":  int64(0),
	}

	types := summary["types"].(map[string]int)
	for _, item := range evidence {
		types[item.Type]++
		summary["total_size"] = summary["total_size"].(int64) + item.Size
	}

	return summary
}

func (sm *ScribeMonitor) getSeverityColor(severity string) string {
	switch severity {
	case "critical":
		return "#d32f2f"
	case "high":
		return "#f57c00"
	case "medium":
		return "#ffa000"
	case "low":
		return "#388e3c"
	default:
		return "#757575"
	}
}

func (sm *ScribeMonitor) getAttentionLevel(severity string) string {
	switch severity {
	case "critical":
		return "immediate"
	case "high":
		return "urgent"
	case "medium":
		return "prompt"
	case "low":
		return "routine"
	default:
		return "standard"
	}
}

func (sm *ScribeMonitor) createLegalSummary(incident ForensicIncident) map[string]interface{} {
	return map[string]interface{}{
		"case_id":           incident.ID,
		"description":       fmt.Sprintf("Security incident of type %s with %s severity", incident.IncidentType, incident.Severity),
		"timeline":          incident.Timestamp,
		"evidence_count":    len(incident.Evidence),
		"reports_generated": len(incident.Reports),
	}
}

func (sm *ScribeMonitor) generateDigitalSignature(data map[string]interface{}) string {
	// In a real implementation, this would use proper digital signing
	// For now, we'll create a simple hash as a placeholder
	content, _ := json.Marshal(data)
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

func (sm *ScribeMonitor) calculateChainHash(entry CustodyEntry) string {
	content, _ := json.Marshal(entry)
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

func (sm *ScribeMonitor) archiveIncident(incident ForensicIncident) {
	if sm.config.EvidenceStorage == "" {
		return
	}

	archiveDir := filepath.Join(sm.config.EvidenceStorage, "archive")
	os.MkdirAll(archiveDir, 0750)

	archivePath := filepath.Join(archiveDir, fmt.Sprintf("incident_%s.json", incident.ID))
	content, _ := json.MarshalIndent(incident, "", "  ")
	os.WriteFile(archivePath, content, 0640)

	sm.LogEvent(zerolog.InfoLevel, "Incident archived").
		Str("incident_id", incident.ID).
		Str("archive_path", archivePath)
}

// Utility functions

func generateIncidentID() string {
	return fmt.Sprintf("INC-%d", time.Now().Unix())
}

func generateReportID() string {
	return fmt.Sprintf("RPT-%d", time.Now().UnixNano())
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
