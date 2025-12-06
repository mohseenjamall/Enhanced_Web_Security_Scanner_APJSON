package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type Config struct {
	// General settings
	ConfigFile      string
	MaxThreads      int
	CrawlDepth      int
	ScanTimeout     int
	DownloadTimeout int
	OutputDir       string
	Verbose         bool
	UserAgent       string
	
	// Feature flags
	EnableSecrets     bool
	EnableCORS        bool
	EnableSubdomains  bool
	EnableAuthTests   bool
	EnableInjection   bool
	EnableSSLScan     bool
	EnableWAFDetect   bool
	EnableGraphQL     bool
	StealthMode       bool
	
	// Reporting
	PDFReport    bool
	CVSSScoring  bool
	
	// Stealth settings
	RequestsPerSecond int
	UseProxy          bool
	ProxyList         string
	RandomUserAgents  bool
	RequestDelayMS    int
	
	// Subdomain settings
	SubdomainWordlist string
	DNSResolvers      string
	
	// Custom templates
	CustomNucleiTemplates string
}

// NewConfig creates a new configuration with default values
func NewConfig() *Config {
	return &Config{
		MaxThreads:            8,
		CrawlDepth:            3,
		ScanTimeout:           600,
		DownloadTimeout:       30,
		OutputDir:             "./scan_results",
		Verbose:               false,
		UserAgent:             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		EnableSecrets:         true,
		EnableCORS:            true,
		EnableSubdomains:      false,
		EnableAuthTests:       false,
		EnableInjection:       true,
		EnableSSLScan:         false,
		EnableWAFDetect:       true,
		EnableGraphQL:         true,
		StealthMode:           false,
		PDFReport:             false,
		CVSSScoring:           true,
		RequestsPerSecond:     10,
		UseProxy:              false,
		RandomUserAgents:      false,
		RequestDelayMS:        100,
		SubdomainWordlist:     "",
		DNSResolvers:          "",
		CustomNucleiTemplates: "",
	}
}

// LoadFromFile loads configuration from a YAML file
func (c *Config) LoadFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	
	return yaml.Unmarshal(data, c)
}

// LoadFromFlags loads configuration from command-line flags
func (c *Config) LoadFromFlags(cmd *cobra.Command) error {
	flags := cmd.Flags()
	
	// General settings
	if val, err := flags.GetInt("threads"); err == nil {
		c.MaxThreads = val
	}
	if val, err := flags.GetInt("depth"); err == nil {
		c.CrawlDepth = val
	}
	if val, err := flags.GetInt("timeout"); err == nil {
		c.ScanTimeout = val
	}
	if val, err := flags.GetString("output"); err == nil {
		c.OutputDir = val
	}
	if val, err := flags.GetBool("verbose"); err == nil {
		c.Verbose = val
	}
	
	// Feature flags
	if val, err := flags.GetBool("enable-secrets"); err == nil {
		c.EnableSecrets = val
	}
	if val, err := flags.GetBool("enable-cors"); err == nil {
		c.EnableCORS = val
	}
	if val, err := flags.GetBool("enable-subdomains"); err == nil {
		c.EnableSubdomains = val
	}
	if val, err := flags.GetBool("enable-auth-tests"); err == nil {
		c.EnableAuthTests = val
	}
	if val, err := flags.GetBool("enable-injection"); err == nil {
		c.EnableInjection = val
	}
	if val, err := flags.GetBool("enable-ssl-scan"); err == nil {
		c.EnableSSLScan = val
	}
	if val, err := flags.GetBool("enable-waf-detect"); err == nil {
		c.EnableWAFDetect = val
	}
	if val, err := flags.GetBool("enable-graphql"); err == nil {
		c.EnableGraphQL = val
	}
	if val, err := flags.GetBool("stealth-mode"); err == nil {
		c.StealthMode = val
	}
	
	// Reporting flags
	if val, err := flags.GetBool("pdf-report"); err == nil {
		c.PDFReport = val
	}
	if val, err := flags.GetBool("cvss-scoring"); err == nil {
		c.CVSSScoring = val
	}
	
	return nil
}

// SaveToFile saves the current configuration to a YAML file
func (c *Config) SaveToFile(filename string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, data, 0644)
}
