package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mohseenjamall/apjson/pkg/config"
	"github.com/mohseenjamall/apjson/pkg/types"
)

// Test NewGenerator
func TestNewGenerator(t *testing.T) {
	cfg := config.NewConfig()
	gen := NewGenerator(cfg, "/tmp/reports")

	if gen == nil {
		t.Fatal("NewGenerator returned nil")
	}
}

// Test Generator initialization
func TestGeneratorInitialization(t *testing.T) {
	cfg := config.NewConfig()
	gen := NewGenerator(cfg, "/tmp/reports")

	if gen == nil {
		t.Fatal("Generator is nil")
	}
}

// Test GenerateJSON
func TestGenerateJSON(t *testing.T) {
	cfg := config.NewConfig()
	gen := NewGenerator(cfg, t.TempDir())

	results := &types.ScanResults{
		TargetURL: "http://example.com",
		Vulnerabilities: []types.Vulnerability{
			{
				Type:     "SQL Injection",
				Severity: "High",
				URL:      "http://example.com/page?id=1",
			},
		},
		Statistics: map[string]interface{}{
			"total_urls": 100,
		},
	}

	outputPath := filepath.Join(t.TempDir(), "report.json")

	err := gen.GenerateJSON(results, outputPath)
	if err != nil {
		t.Errorf("GenerateJSON failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("JSON report was not created")
	}
}

// Test GenerateHTML
func TestGenerateHTML(t *testing.T) {
	cfg := config.NewConfig()
	gen := NewGenerator(cfg, t.TempDir())

	results := &types.ScanResults{
		TargetURL: "http://example.com",
		Vulnerabilities: []types.Vulnerability{
			{
				Type:     "XSS",
				Severity: "Medium",
				URL:      "http://example.com/search?q=test",
			},
		},
		Statistics: map[string]interface{}{
			"total_urls": 50,
		},
	}

	outputPath := filepath.Join(t.TempDir(), "report.html")

	err := gen.GenerateHTML(results, outputPath)
	if err != nil {
		t.Errorf("GenerateHTML failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("HTML report was not created")
	}
}

// Test getSeverityClass
func TestGetSeverityClass(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"Critical", "critical"},
		{"High", "high"},
		{"Medium", "medium"},
		{"Low", "low"},
		{"Info", "low"}, // function returns "low" for unknown severities
	}

	for _, tc := range tests {
		result := getSeverityClass(tc.severity)
		if result != tc.expected {
			t.Errorf("getSeverityClass(%s) = %s, want %s", tc.severity, result, tc.expected)
		}
	}
}

// Test ScanResults struct
func TestScanResultsStruct(t *testing.T) {
	results := types.ScanResults{
		TargetURL: "http://example.com",
		Vulnerabilities: []types.Vulnerability{
			{Type: "SQLi", Severity: "High"},
			{Type: "XSS", Severity: "Medium"},
		},
		Statistics: map[string]interface{}{
			"total_urls": 150,
		},
	}

	if results.TargetURL != "http://example.com" {
		t.Error("TargetURL not set correctly")
	}

	if len(results.Vulnerabilities) != 2 {
		t.Error("Vulnerabilities count incorrect")
	}
}

// Test Vulnerability struct
func TestVulnerabilityStruct(t *testing.T) {
	vuln := types.Vulnerability{
		Type:        "SQL Injection",
		Severity:    "High",
		URL:         "http://example.com/page?id=1",
		Parameter:   "id",
		Description: "SQL Injection vulnerability",
		Remediation: "Use parameterized queries",
		CVSSScore:   8.5,
	}

	if vuln.Type != "SQL Injection" {
		t.Error("Vulnerability Type not set")
	}

	if vuln.Severity != "High" {
		t.Error("Vulnerability Severity not set")
	}

	if vuln.CVSSScore != 8.5 {
		t.Error("Vulnerability CVSSScore not set")
	}
}

// Test Generator with different output dirs
func TestGeneratorOutputDirs(t *testing.T) {
	cfg := config.NewConfig()

	dirs := []string{"/tmp/reports", "/tmp/output", "/tmp/scans"}

	for _, dir := range dirs {
		gen := NewGenerator(cfg, dir)

		if gen == nil {
			t.Errorf("Failed to create generator for output dir: %s", dir)
		}
	}
}

// Benchmark NewGenerator
func BenchmarkNewGenerator(b *testing.B) {
	cfg := config.NewConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewGenerator(cfg, "/tmp/reports")
	}
}

// Benchmark GenerateJSON
func BenchmarkGenerateJSON(b *testing.B) {
	cfg := config.NewConfig()
	gen := NewGenerator(cfg, b.TempDir())

	results := &types.ScanResults{
		TargetURL: "http://example.com",
		Statistics: map[string]interface{}{
			"total_urls": 100,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outputPath := filepath.Join(b.TempDir(), "report.json")
		gen.GenerateJSON(results, outputPath)
	}
}
