package injection

import (
	"testing"

	"github.com/mohseenjamall/apjson/pkg/config"
)

// Test NewTester
func TestNewTester(t *testing.T) {
	cfg := config.NewConfig()
	tester := NewTester(cfg)

	if tester == nil {
		t.Fatal("NewTester returned nil")
	}
}

// Test Vulnerability struct
func TestVulnerabilityStruct(t *testing.T) {
	vuln := Vulnerability{
		Type:        SQLInjection,
		Technique:   TimeBased,
		URL:         "http://example.com/test?id=1",
		Parameter:   "id",
		Payload:     "1' AND SLEEP(5)--",
		Evidence:    "Response delayed",
		Severity:    "High",
		Confidence:  0.95,
		Description: "SQL Injection vulnerability",
		Remediation: "Use parameterized queries",
	}

	if vuln.Type != SQLInjection {
		t.Error("Vulnerability Type not set correctly")
	}

	if vuln.Technique != TimeBased {
		t.Error("Vulnerability Technique not set correctly")
	}

	if vuln.Parameter != "id" {
		t.Error("Vulnerability Parameter not set correctly")
	}

	if vuln.Confidence < 0 || vuln.Confidence > 1 {
		t.Error("Vulnerability Confidence out of range")
	}
}

// Test InjectionType constants
func TestInjectionTypeConstants(t *testing.T) {
	tests := []struct {
		injType  InjectionType
		expected string
	}{
		{SQLInjection, "SQL Injection"},
		{XSSInjection, "Cross-Site Scripting (XSS)"},
		{CommandInjection, "Command Injection"},
	}

	for _, tc := range tests {
		if string(tc.injType) != tc.expected {
			t.Errorf("InjectionType %v != %s", tc.injType, tc.expected)
		}
	}
}

// Test SQLiTechnique constants
func TestSQLiTechniqueConstants(t *testing.T) {
	tests := []struct {
		technique SQLiTechnique
		expected  string
	}{
		{TimeBased, "Time-Based Blind"},
		{ErrorBased, "Error-Based"},
		{BooleanBased, "Boolean-Based Blind"},
		{UnionBased, "UNION-Based"},
		{StackedQuery, "Stacked Queries"},
	}

	for _, tc := range tests {
		if string(tc.technique) != tc.expected {
			t.Errorf("SQLiTechnique %v != %s", tc.technique, tc.expected)
		}
	}
}

// Test GetPayloadTemplates
func TestGetPayloadTemplates(t *testing.T) {
	templates := GetPayloadTemplates()

	if templates == nil {
		t.Fatal("GetPayloadTemplates returned nil")
	}

	if len(templates) == 0 {
		t.Error("No payload templates returned")
	}

	// Check for common payload categories
	expectedCategories := []string{"time_based", "error_based", "union_based"}

	for _, category := range expectedCategories {
		if payloads, ok := templates[category]; ok {
			if len(payloads) == 0 {
				t.Errorf("Category %s has no payloads", category)
			} else {
				t.Logf("Category %s has %d payloads", category, len(payloads))
			}
		}
	}
}

// Test Tester with nil config
func TestTesterWithConfig(t *testing.T) {
	// Test with actual config
	cfg := config.NewConfig()
	cfg.EnableInjection = true
	cfg.MaxThreads = 4

	tester := NewTester(cfg)

	if tester == nil {
		t.Fatal("NewTester with config returned nil")
	}
}

// Test Tester.TestURL with invalid URL
func TestTestURLWithInvalidURL(t *testing.T) {
	cfg := config.NewConfig()
	tester := NewTester(cfg)

	// Test with invalid URL (should not panic)
	results := tester.TestURL("")

	// Should return empty results for invalid URL
	if results == nil {
		t.Error("TestURL returned nil instead of empty slice")
	}
}

// Test Tester.TestURL with URL without parameters
func TestTestURLNoParams(t *testing.T) {
	cfg := config.NewConfig()
	tester := NewTester(cfg)

	// URL without parameters
	results := tester.TestURL("http://example.com/test")

	// Should return empty results (no params to test)
	if len(results) > 0 {
		t.Error("Expected no results for URL without parameters")
	}
}

// Benchmark NewTester
func BenchmarkNewTester(b *testing.B) {
	cfg := config.NewConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewTester(cfg)
	}
}

// Benchmark GetPayloadTemplates
func BenchmarkGetPayloadTemplates(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetPayloadTemplates()
	}
}
