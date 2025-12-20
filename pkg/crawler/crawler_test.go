package crawler

import (
	"testing"

	"github.com/mohseenjamall/apjson/pkg/config"
)

// Test NewCrawler
func TestNewCrawler(t *testing.T) {
	cfg := config.NewConfig()
	crawler := NewCrawler(cfg, "http://example.com", "/tmp/output")

	if crawler == nil {
		t.Fatal("NewCrawler returned nil")
	}
}

// Test CrawlResults struct
func TestCrawlResultsStruct(t *testing.T) {
	results := CrawlResults{
		AllURLs:      []string{"http://example.com", "http://example.com/page"},
		JSFiles:      []string{"http://example.com/app.js"},
		JSONFiles:    []string{"http://example.com/config.json"},
		APIEndpoints: []string{"http://example.com/api/v1/users"},
		ParamURLs:    []string{"http://example.com/search?q=test"},
	}

	if len(results.AllURLs) != 2 {
		t.Error("AllURLs not set correctly")
	}

	if len(results.JSFiles) != 1 {
		t.Error("JSFiles not set correctly")
	}

	if len(results.JSONFiles) != 1 {
		t.Error("JSONFiles not set correctly")
	}

	if len(results.APIEndpoints) != 1 {
		t.Error("APIEndpoints not set correctly")
	}

	if len(results.ParamURLs) != 1 {
		t.Error("ParamURLs not set correctly")
	}
}

// Test Crawler initialization
func TestCrawlerInitialization(t *testing.T) {
	cfg := config.NewConfig()
	c := NewCrawler(cfg, "http://example.com", "/tmp/test")

	if c == nil {
		t.Fatal("Crawler is nil")
	}
}

// Test URL categorization
func TestCrawlerCategorizeURL(t *testing.T) {
	cfg := config.NewConfig()
	c := NewCrawler(cfg, "http://example.com", "/tmp/test")

	results := &CrawlResults{
		AllURLs:      make([]string, 0),
		JSFiles:      make([]string, 0),
		JSONFiles:    make([]string, 0),
		APIEndpoints: make([]string, 0),
		ParamURLs:    make([]string, 0),
	}

	testURLs := []struct {
		url         string
		expectJS    bool
		expectJSON  bool
		expectAPI   bool
		expectParam bool
	}{
		{"http://example.com/app.js", true, false, false, false},
		{"http://example.com/config.json", false, true, false, false},
		{"http://example.com/api/v1/users", false, false, true, false},
		{"http://example.com/search?q=test", false, false, false, true},
		{"http://example.com/page", false, false, false, false},
	}

	for _, tc := range testURLs {
		c.categorizeURL(tc.url, results)
	}

	// Verify categorization
	if len(results.JSFiles) < 1 {
		t.Error("JS files not categorized")
	}

	if len(results.JSONFiles) < 1 {
		t.Error("JSON files not categorized")
	}

	if len(results.APIEndpoints) < 1 {
		t.Error("API endpoints not categorized")
	}

	if len(results.ParamURLs) < 1 {
		t.Error("Param URLs not categorized")
	}
}

// Test makeAbsolute function
func TestMakeAbsolute(t *testing.T) {
	cfg := config.NewConfig()
	c := NewCrawler(cfg, "http://example.com", "/tmp/test")

	tests := []struct {
		baseURL     string
		relativeURL string
		expected    string
	}{
		{"http://example.com", "/path/page", "http://example.com/path/page"},
		{"http://example.com", "https://other.com/page", "https://other.com/page"},
		{"http://example.com/dir/", "file.js", "http://example.com/dir/file.js"},
	}

	for _, tc := range tests {
		result := c.makeAbsolute(tc.baseURL, tc.relativeURL)
		if result != tc.expected {
			t.Errorf("makeAbsolute(%s, %s) = %s, want %s",
				tc.baseURL, tc.relativeURL, result, tc.expected)
		}
	}
}

// Test Crawler with different configs
func TestCrawlerWithConfigs(t *testing.T) {
	configs := []struct {
		depth   int
		threads int
	}{
		{1, 4},
		{3, 8},
		{5, 16},
	}

	for _, tc := range configs {
		cfg := config.NewConfig()
		cfg.CrawlDepth = tc.depth
		cfg.MaxThreads = tc.threads

		c := NewCrawler(cfg, "http://example.com", "/tmp/test")

		if c == nil {
			t.Errorf("Failed to create crawler with depth=%d, threads=%d", tc.depth, tc.threads)
		}
	}
}

// Benchmark NewCrawler
func BenchmarkNewCrawler(b *testing.B) {
	cfg := config.NewConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewCrawler(cfg, "http://example.com", "/tmp/test")
	}
}

// Benchmark categorizeURL
func BenchmarkCategorizeURL(b *testing.B) {
	cfg := config.NewConfig()
	c := NewCrawler(cfg, "http://example.com", "/tmp/test")
	results := &CrawlResults{
		AllURLs:      make([]string, 0),
		JSFiles:      make([]string, 0),
		JSONFiles:    make([]string, 0),
		APIEndpoints: make([]string, 0),
		ParamURLs:    make([]string, 0),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.categorizeURL("http://example.com/api/v1/users?id=1", results)
	}
}
