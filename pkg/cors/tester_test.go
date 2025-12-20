package cors

import (
	"testing"

	"github.com/mohseenjamall/apjson/pkg/config"
)

// Test NewTester
func TestNewCORSTester(t *testing.T) {
	cfg := config.NewConfig()
	tester := NewTester(cfg)

	if tester == nil {
		t.Fatal("NewTester returned nil")
	}
}

// Test Finding struct
func TestFindingStruct(t *testing.T) {
	finding := Finding{
		Type:        WildcardOrigin,
		Severity:    "High",
		URL:         "http://example.com/api",
		Origin:      "https://evil.com",
		Headers:     map[string]string{"Access-Control-Allow-Origin": "*"},
		Description: "Wildcard origin allowed",
		Remediation: "Specify allowed origins explicitly",
	}

	if finding.Type != WildcardOrigin {
		t.Error("Finding Type not set correctly")
	}

	if finding.Severity != "High" {
		t.Error("Finding Severity not set correctly")
	}

	if finding.Headers == nil {
		t.Error("Finding Headers not set")
	}
}

// Test FindingType constants
func TestFindingTypeConstants(t *testing.T) {
	types := []struct {
		findingType FindingType
		expected    string
	}{
		{WildcardOrigin, "Wildcard Origin Allowed"},
		{NullOriginBypass, "Null Origin Bypass"},
		{TrustedSubdomains, "Trusted Subdomain Bypass"},
		{InsecureHTTP, "HTTP Origin Allowed"},
		{CredentialsExposed, "Credentials with Wildcard"},
		{MissingHeaders, "Missing CORS Headers"},
	}

	for _, tc := range types {
		if string(tc.findingType) != tc.expected {
			t.Errorf("FindingType %v != %s", tc.findingType, tc.expected)
		}
	}
}

// Test Test method with empty URL
func TestTestWithEmptyURL(t *testing.T) {
	cfg := config.NewConfig()
	tester := NewTester(cfg)

	// Should not panic with empty URL
	results := tester.Test("")

	if results == nil {
		t.Error("Test returned nil instead of empty slice")
	}
}

// Benchmark NewTester
func BenchmarkNewCORSTester(b *testing.B) {
	cfg := config.NewConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewTester(cfg)
	}
}
