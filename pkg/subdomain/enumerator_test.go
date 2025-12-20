package subdomain

import (
	"testing"
	"time"

	"github.com/mohseenjamall/apjson/pkg/config"
)

// Test NewEnumerator
func TestNewEnumerator(t *testing.T) {
	cfg := config.NewConfig()
	enum := NewEnumerator(cfg, "example.com", "/tmp/output")

	if enum == nil {
		t.Fatal("NewEnumerator returned nil")
	}
}

// Test Result struct
func TestResultStruct(t *testing.T) {
	result := Result{
		Subdomain:   "www.example.com",
		IPAddresses: []string{"93.184.216.34"},
		Source:      "bruteforce",
		Timestamp:   time.Now(),
	}

	if result.Subdomain != "www.example.com" {
		t.Error("Result Subdomain not set correctly")
	}

	if len(result.IPAddresses) != 1 {
		t.Error("Result IPAddresses not set correctly")
	}

	if result.Source != "bruteforce" {
		t.Error("Result Source not set correctly")
	}

	if result.Timestamp.IsZero() {
		t.Error("Result Timestamp not set")
	}
}

// Test Enumerator initialization
func TestEnumeratorInitialization(t *testing.T) {
	cfg := config.NewConfig()
	enum := NewEnumerator(cfg, "example.com", "/tmp/test")

	if enum == nil {
		t.Fatal("Enumerator is nil")
	}
}

// Test GetStatistics with empty results
func TestGetStatisticsEmpty(t *testing.T) {
	cfg := config.NewConfig()
	enum := NewEnumerator(cfg, "example.com", "/tmp/test")

	stats := enum.GetStatistics()

	if stats == nil {
		t.Fatal("GetStatistics returned nil")
	}

	if stats["total_subdomains"] != 0 {
		t.Error("Empty enumerator should have 0 total_subdomains")
	}
}

// Test CheckSubdomainTakeover (offline test)
func TestCheckSubdomainTakeoverOffline(t *testing.T) {
	cfg := config.NewConfig()
	enum := NewEnumerator(cfg, "example.com", "/tmp/test")

	// This should not panic
	_, _ = enum.CheckSubdomainTakeover("nonexistent.example.com")

	// Just testing it doesn't panic
}

// Test Enumerator with various domains
func TestEnumeratorDomains(t *testing.T) {
	cfg := config.NewConfig()

	domains := []string{
		"example.com",
		"test.org",
		"subdomain.example.com",
	}

	for _, domain := range domains {
		enum := NewEnumerator(cfg, domain, "/tmp/test")

		if enum == nil {
			t.Errorf("Failed to create enumerator for domain: %s", domain)
		}
	}
}

// Test Result with multiple IPs
func TestResultMultipleIPs(t *testing.T) {
	result := Result{
		Subdomain:   "www.example.com",
		IPAddresses: []string{"93.184.216.34", "93.184.216.35", "93.184.216.36"},
		Source:      "subfinder",
		Timestamp:   time.Now(),
	}

	if len(result.IPAddresses) != 3 {
		t.Errorf("Expected 3 IPs, got %d", len(result.IPAddresses))
	}
}

// Test Result sources
func TestResultSources(t *testing.T) {
	sources := []string{"subfinder", "bruteforce", "certspotter"}

	for _, source := range sources {
		result := Result{
			Subdomain: "test.example.com",
			Source:    source,
		}

		if result.Source != source {
			t.Errorf("Source mismatch: expected %s, got %s", source, result.Source)
		}
	}
}

// Benchmark NewEnumerator
func BenchmarkNewEnumerator(b *testing.B) {
	cfg := config.NewConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewEnumerator(cfg, "example.com", "/tmp/test")
	}
}

// Benchmark GetStatistics
func BenchmarkGetStatistics(b *testing.B) {
	cfg := config.NewConfig()
	enum := NewEnumerator(cfg, "example.com", "/tmp/test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enum.GetStatistics()
	}
}
