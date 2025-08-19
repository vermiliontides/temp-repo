package certificate

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lucid-vigil/sentinel/pkg/monitors/base"
	"github.com/lucid-vigil/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
)

// CertificateMonitorConfig holds configuration for the CertificateMonitor.
type CertificateMonitorConfig struct {
	DomainsToMonitor    []string `mapstructure:"domains_to_monitor"`
	ExpiryThresholdDays int      `mapstructure:"expiry_threshold_days"`
	RunInterval         int      `mapstructure:"run_interval"`
	BaselineDir         string   `mapstructure:"baseline_dir"`
}

// CertificateMonitor implements the scheduler.Monitor interface for certificate monitoring.
type CertificateMonitor struct {
	*base.BaseMonitor
	config *CertificateMonitorConfig
}

// NewCertificateMonitor creates a new CertificateMonitor.
func NewCertificateMonitor(logger zerolog.Logger) scheduler.Monitor {
	return &CertificateMonitor{
		BaseMonitor: base.NewBaseMonitor("certificate_monitor", logger),
		config:      &CertificateMonitorConfig{},
	}
}

// Run executes the certificate monitoring logic.
func (cm *CertificateMonitor) Run(ctx context.Context) {
	cm.LogEvent(zerolog.InfoLevel, "Running Certificate Monitor...")

	// Ensure baseline directory exists
	if _, err := os.Stat(cm.config.BaselineDir); os.IsNotExist(err) {
		err := os.MkdirAll(cm.config.BaselineDir, 0755)
		if err != nil {
			cm.LogEvent(zerolog.ErrorLevel, "Failed to create baseline directory.").Err(err).Str("dir", cm.config.BaselineDir)
			return
		}
	}

	cm.checkCertificates()

	cm.LogEvent(zerolog.InfoLevel, "Certificate Monitor finished.")
}

// checkCertificates fetches certificate details, compares fingerprints, and checks expiration.
func (cm *CertificateMonitor) checkCertificates() {
	for _, entry := range cm.config.DomainsToMonitor {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			cm.LogEvent(zerolog.WarnLevel, "Invalid domain entry format. Expected 'domain:port'.").Str("entry", entry)
			continue
		}
		domain := parts[0]
		port := parts[1]
		address := fmt.Sprintf("%s:%s", domain, port)

		cm.LogEvent(zerolog.InfoLevel, "Checking certificate.").Str("domain", domain).Str("port", port)

		conn, err := tls.DialWithDialer(nil, "tcp", address, &tls.Config{
			InsecureSkipVerify: true, // We'll verify manually
			ServerName:         domain,
		})
		if err != nil {
			cm.LogEvent(zerolog.ErrorLevel, "Failed to connect to server for certificate check.").Err(err).Str("address", address)
			continue
		}
		defer conn.Close()

		certs := conn.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			cm.LogEvent(zerolog.WarnLevel, "No certificates found.").Str("address", address)
			continue
		}

		leafCert := certs[0] // Leaf certificate
		hash := sha256.Sum256(leafCert.Raw)
		fingerprint := hex.EncodeToString(hash[:])
		baselineFile := filepath.Join(cm.config.BaselineDir, fmt.Sprintf("%s_%s.fp", domain, port))

		// Compare with baseline fingerprint
		baselineFP, err := os.ReadFile(baselineFile)
		if os.IsNotExist(err) {
			cm.LogEvent(zerolog.InfoLevel, "Creating new certificate baseline.").Str("domain", domain).Str("port", port)
			err = os.WriteFile(baselineFile, []byte(fingerprint), 0644)
			if err != nil {
				cm.LogEvent(zerolog.ErrorLevel, "Failed to write baseline file.").Err(err).Str("file", baselineFile)
			}
		} else if err != nil {
			cm.LogEvent(zerolog.ErrorLevel, "Failed to read baseline file.").Err(err).Str("file", baselineFile)
		} else if string(baselineFP) != fingerprint {
			cm.LogEvent(zerolog.ErrorLevel, "Certificate FINGERPRINT MISMATCH! Possible MITM attack or certificate change.").
				Str("domain", domain).
				Str("port", port).
				Str("old_fingerprint", string(baselineFP)).
				Str("new_fingerprint", fingerprint)
			// Update baseline after change
			err = os.WriteFile(baselineFile, []byte(fingerprint), 0644)
			if err != nil {
				cm.LogEvent(zerolog.ErrorLevel, "Failed to update baseline file.").Err(err).Str("file", baselineFile)
			}
		}

		// Check expiration date
		daysLeft := int(leafCert.NotAfter.Sub(time.Now()).Hours() / 24)
		if daysLeft <= cm.config.ExpiryThresholdDays {
			cm.LogEvent(zerolog.WarnLevel, "Certificate is expiring soon.").
				Str("domain", domain).
				Str("port", port).
				Int("days_left", daysLeft)
		} else {
			cm.LogEvent(zerolog.InfoLevel, "Certificate is valid.").
				Str("domain", domain).
				Str("port", port).
				Int("days_left", daysLeft)
		}
	}
}
