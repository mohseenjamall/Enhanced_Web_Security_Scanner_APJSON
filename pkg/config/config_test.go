package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Test NewConfig
func TestNewConfig(t *testing.T) {
	cfg := NewConfig()

	if cfg == nil {
		t.Fatal("NewConfig returned nil")
	}

	// Check defaults
	if cfg.MaxThreads <= 0 {
		t.Error("MaxThreads should have a default value")
	}

	if cfg.CrawlDepth <= 0 {
		t.Error("CrawlDepth should have a default value")
	}

	if cfg.ScanTimeout <= 0 {
		t.Error("ScanTimeout should have a default value")
	}
}

// Test default feature flags
func TestDefaultFeatureFlags(t *testing.T) {
	cfg := NewConfig()

	// EnableSecrets and EnableCORS should be true by default
	if !cfg.EnableSecrets {
		t.Error("EnableSecrets should be true by default")
	}

	if !cfg.EnableCORS {
		t.Error("EnableCORS should be true by default")
	}

	// EnableSubdomains should be false by default
	if cfg.EnableSubdomains {
		t.Error("EnableSubdomains should be false by default")
	}
}

// Test Config modification
func TestConfigModification(t *testing.T) {
	cfg := NewConfig()

	// Modify values
	cfg.MaxThreads = 32
	cfg.CrawlDepth = 10
	cfg.Verbose = true
	cfg.EnableInjection = true

	if cfg.MaxThreads != 32 {
		t.Error("MaxThreads modification failed")
	}

	if cfg.CrawlDepth != 10 {
		t.Error("CrawlDepth modification failed")
	}

	if !cfg.Verbose {
		t.Error("Verbose modification failed")
	}

	if !cfg.EnableInjection {
		t.Error("EnableInjection modification failed")
	}
}

// Test Config output directory
func TestConfigOutputDir(t *testing.T) {
	cfg := NewConfig()

	expected := "./scan_results"
	if cfg.OutputDir != expected {
		t.Errorf("Default OutputDir should be %s, got %s", expected, cfg.OutputDir)
	}

	cfg.OutputDir = "/tmp/test_output"
	if cfg.OutputDir != "/tmp/test_output" {
		t.Error("OutputDir not set correctly")
	}
}

// Test Config SaveToFile
func TestConfigSaveToFile(t *testing.T) {
	cfg := NewConfig()
	cfg.MaxThreads = 16
	cfg.Verbose = true

	// Create temp file
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test_config.yaml")

	err := cfg.SaveToFile(tempFile)
	if err != nil {
		t.Errorf("SaveToFile failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tempFile); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}
}

// Test Config LoadFromFile
func TestConfigLoadFromFile(t *testing.T) {
	cfg := NewConfig()
	cfg.MaxThreads = 32
	cfg.Verbose = true

	// Save to temp file
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test_config.yaml")

	err := cfg.SaveToFile(tempFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Load into new config
	newCfg := NewConfig()
	err = newCfg.LoadFromFile(tempFile)
	if err != nil {
		t.Errorf("LoadFromFile failed: %v", err)
	}

	if newCfg.MaxThreads != 32 {
		t.Errorf("LoadFromFile: MaxThreads mismatch, got %d", newCfg.MaxThreads)
	}
}

// Test UserAgent default
func TestConfigUserAgent(t *testing.T) {
	cfg := NewConfig()

	if cfg.UserAgent == "" {
		t.Error("UserAgent should have a default value")
	}
}

// Benchmark NewConfig
func BenchmarkNewConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewConfig()
	}
}
