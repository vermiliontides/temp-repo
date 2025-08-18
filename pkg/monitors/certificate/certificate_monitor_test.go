package certificate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kali-security-monitoring/sentinel/pkg/scheduler"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
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

// Mocking network and file operations for testing
var (
	dialWithDialer = func(network, addr string, config *tls.Config) (*tls.Conn, error) {
		// Mock successful connection and return a dummy cert
		return &tls.Conn{},
			// Return a dummy certificate for testing
			// In a real mock, you'd create a proper x509.Certificate
			// For simplicity, we'll just return a nil error and let the test handle the rest
			nil
	}
	// Mock os.ReadFile
	readFile = ioutil.ReadFile
	// Mock os.WriteFile
	writeFile = ioutil.WriteFile
	// Mock os.Stat
	osStat = os.Stat
	// Mock os.MkdirAll
	osMkdirAll = os.MkdirAll
)

func TestCertificateMonitor_Run(t *testing.T) {
	// Setup log capture
	lc := &LogCapture{}
	log.Logger = zerolog.New(lc).With().Timestamp().Logger()
	defer lc.ClearLogs()

	// Create monitor instance
	monitor := NewCertificateMonitor(log.Logger)
	cm, ok := monitor.(*CertificateMonitor)
	assert.True(t, ok)

	// Create a temporary directory for baselines
	testBaselineDir, err := ioutil.TempDir("", "cert_baseline_test")
	assert.NoError(t, err)
	defer os.RemoveAll(testBaselineDir)

	// Set config for testing
	cm.config = &Config{
		DomainsToMonitor:    []string{"example.com:443"},
		ExpiryThresholdDays: 30,
		BaselineDir:         testBaselineDir,
	}

	// --- Test Case 1: New Certificate (Baseline Creation) ---
	t.Run("NewCertificate", func(t *testing.T) {
		lc.ClearLogs()

		// Mock functions
		dialWithDialer = func(network, addr string, config *tls.Config) (*tls.Conn, error) {
			return &tls.Conn{ConnectionState: tls.ConnectionState{PeerCertificates: []*x509.Certificate{{RawSHA256: []byte{0x01}}}}}, nil
		}
		readFile = func(filename string) ([]byte, error) {
			return nil, os.ErrNotExist // Simulate no baseline file
		}
		writeFile = func(filename string, data []byte, perm os.FileMode) error {
			return nil // Simulate successful write
		}
		osStat = func(name string) (os.FileInfo, error) {
			if name == testBaselineDir {
				return nil, os.ErrNotExist // Simulate dir not existing initially
			}
			return nil, os.ErrNotExist
		}
		osMkdirAll = func(path string, perm os.FileMode) error {
			return nil // Simulate successful mkdir
		}

		// Run the monitor
		cm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "Creating new certificate baseline.")
		assert.Contains(t, logs, "Certificate is valid.")
	})

	// --- Test Case 2: Fingerprint Mismatch ---
	t.Run("FingerprintMismatch", func(t *testing.T) {
		lc.ClearLogs()

		// Mock functions
		dialWithDialer = func(network, addr string, config *tls.Config) (*tls.Conn, error) {
			return &tls.Conn{ConnectionState: tls.ConnectionState{PeerCertificates: []*x509.Certificate{{RawSHA256: []byte{0x02}}}}}, nil // New fingerprint
		}
		readFile = func(filename string) ([]byte, error) {
			return []byte("01"), nil // Old fingerprint
		}
		writeFile = func(filename string, data []byte, perm os.FileMode) error {
			return nil // Simulate successful write
		}
		osStat = func(name string) (os.FileInfo, error) {
			return nil, nil // Simulate dir existing
		}
		osMkdirAll = func(path string, perm os.FileMode) error {
			return nil // Simulate successful mkdir
		}

		// Run the monitor
		cm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "Certificate FINGERPRINT MISMATCH!")
	})

	// --- Test Case 3: Certificate Expiring Soon ---
	t.Run("ExpiringSoon", func(t *testing.T) {
		lc.ClearLogs()

		// Mock functions
		dialWithDialer = func(network, addr string, config *tls.Config) (*tls.Conn, error) {
			return &tls.Conn{ConnectionState: tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
				RawSHA256: []byte{0x03},
				NotAfter:  time.Now().Add(20 * 24 * time.Hour), // Expires in 20 days
			}}}},
			nil
		}
		readFile = func(filename string) ([]byte, error) {
			return []byte("03"), nil
		}
		writeFile = func(filename string, data []byte, perm os.FileMode) error {
			return nil
		}
		osStat = func(name string) (os.FileInfo, error) {
			return nil, nil
		}
		osMkdirAll = func(path string, perm os.FileMode) error {
			return nil
		}

		// Run the monitor
		cm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "Certificate is expiring soon.")
	})

	// --- Test Case 4: Connection Error ---
	t.Run("ConnectionError", func(t *testing.T) {
		lc.ClearLogs()

		// Mock functions
		dialWithDialer = func(network, addr string, config *tls.Config) (*tls.Conn, error) {
			return nil, errors.New("mock connection error")
		}
		readFile = func(filename string) ([]byte, error) {
			return nil, os.ErrNotExist
		}
		writeFile = func(filename string, data []byte, perm os.FileMode) error {
			return nil
		}
		osStat = func(name string) (os.FileInfo, error) {
			return nil, nil
		}
		osMkdirAll = func(path string, perm os.FileMode) error {
			return nil
		}

		// Run the monitor
		cm.Run(context.Background())

		// Assertions
		logs := strings.Join(lc.GetLogs(), "")
		assert.Contains(t, logs, "Failed to connect to server for certificate check.")
	})

	// Restore original functions
	dialWithDialer = tls.DialWithDialer
	readFile = ioutil.ReadFile
	writeFile = ioutil.WriteFile
	osStat = os.Stat
	osMkdirAll = os.MkdirAll
}

func TestNewCertificateMonitor(t *testing.T) {
	logger := zerolog.Nop()
	monitor := NewCertificateMonitor(logger)

	assert.NotNil(t, monitor)
	assert.Equal(t, "certificate_monitor", monitor.Name())

	cm, ok := monitor.(*CertificateMonitor)
	assert.True(t, ok)
	assert.NotNil(t, cm.BaseMonitor)
	assert.NotNil(t, cm.config)
}
