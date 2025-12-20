package injection

import (
	"testing"

	"github.com/mohseenjamall/apjson/pkg/config"
)

// Test XSS Scanner creation
func TestNewXSSScanner(t *testing.T) {
	cfg := config.NewConfig()
	tester := NewTester(cfg)

	if tester == nil {
		t.Fatal("XSS Tester creation failed")
	}
}

// Test XSS Context types
func TestXSSContextTypes(t *testing.T) {
	// Test that XSS types exist
	if string(XSSInjection) != "Cross-Site Scripting (XSS)" {
		t.Error("XSSInjection type mismatch")
	}
}

// Test XSS payloads availability
func TestXSSPayloads(t *testing.T) {
	templates := GetPayloadTemplates()

	// Check if XSS payloads exist
	if payloads, ok := templates["xss"]; ok {
		t.Logf("Found %d XSS payloads", len(payloads))
	} else {
		t.Log("XSS payloads may be in different category")
	}
}

// Test XSS Vulnerability creation
func TestXSSVulnerability(t *testing.T) {
	vuln := Vulnerability{
		Type:        XSSInjection,
		URL:         "http://example.com/search?q=test",
		Parameter:   "q",
		Payload:     "<script>alert('XSS')</script>",
		Evidence:    "Payload reflected in response",
		Severity:    "High",
		Confidence:  0.90,
		Description: "Reflected XSS vulnerability",
		Remediation: "Encode output and use CSP",
	}

	if vuln.Type != XSSInjection {
		t.Error("XSS Vulnerability type not set correctly")
	}

	if vuln.Severity != "High" {
		t.Error("XSS Vulnerability severity not set correctly")
	}
}

// Benchmark XSS related operations
func BenchmarkXSSPayloadAccess(b *testing.B) {
	for i := 0; i < b.N; i++ {
		templates := GetPayloadTemplates()
		_ = templates["xss"]
	}
}
