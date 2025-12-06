package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/mohseenjamall/apjson/pkg/config"
	"github.com/mohseenjamall/apjson/pkg/types"
	"github.com/mohseenjamall/apjson/pkg/secrets"
	"github.com/mohseenjamall/apjson/pkg/cors"
	"github.com/mohseenjamall/apjson/pkg/crawler"
	"github.com/mohseenjamall/apjson/pkg/report"
)

// Scanner represents the main scanner orchestrator
type Scanner struct {
	config      *config.Config
	targetURL   string
	outputDir   string
	startTime   time.Time
	results     *types.ScanResults
	mu          sync.Mutex
}

// New creates a new scanner instance
func New(cfg *config.Config, targetURL string) (*Scanner, error) {
	// Create output directory
	timestamp := time.Now().Format("20060102_150405")
	domain := extractDomain(targetURL)
	outputDir := filepath.Join(cfg.OutputDir, fmt.Sprintf("%s_%s", domain, timestamp))
	
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}
	
	// Create subdirectories
	subdirs := []string{"js_files", "api_endpoints", "reports", "screenshots"}
	for _, dir := range subdirs {
		if err := os.MkdirAll(filepath.Join(outputDir, dir), 0755); err != nil {
			return nil, fmt.Errorf("failed to create %s directory: %w", dir, err)
		}
	}
	
	return &Scanner{
		config:    cfg,
		targetURL: targetURL,
		outputDir: outputDir,
		startTime: time.Now(),
		results: &types.ScanResults{
			TargetURL:       targetURL,
			Secrets:         make([]secrets.Secret, 0),
			CORSFindings:    make([]cors.Finding, 0),
			Vulnerabilities: make([]types.Vulnerability, 0),
			Statistics:      make(map[string]interface{}),
		},
	}, nil
}

// Execute runs the complete scan workflow
func (s *Scanner) Execute() error {
	color.Cyan("\n[*] Starting scan of: %s\n", s.targetURL)
	color.Cyan("[*] Output directory: %s\n\n", s.outputDir)
	
	// Phase 1: Crawling and Discovery
	if err := s.runCrawling(); err != nil {
		color.Red("[!] Crawling phase failed: %v\n", err)
		return err
	}
	
	// Phase 2: Content Analysis
	if err := s.runContentAnalysis(); err != nil {
		color.Yellow("[!] Content analysis phase encountered errors: %v\n", err)
		// Continue despite errors
	}
	
	// Phase 3: Vulnerability Testing
	if err := s.runVulnerabilityTests(); err != nil {
		color.Yellow("[!] Vulnerability testing phase encountered errors: %v\n", err)
		// Continue despite errors
	}
	
	// Phase 4: Reporting
	if err := s.generateReports(); err != nil {
		color.Red("[!] Report generation failed: %v\n", err)
		return err
	}
	
	s.printSummary()
	return nil
}

// runCrawling performs web crawling and endpoint discovery
func (s *Scanner) runCrawling() error {
	color.Green("\n═══ Phase 1: Crawling & Discovery ═══\n")
	
	// Create crawler
	c := crawler.NewCrawler(s.config, s.targetURL, s.outputDir)
	
	// Perform crawling
	color.Yellow("[*] Crawling %s with depth %d\n", s.targetURL, s.config.CrawlDepth)
	crawlResults, err := c.Crawl()
	if err != nil {
		color.Red("[!] Crawling failed: %v\n", err)
		return err
	}
	
	// Display results
	color.Green("[✓] Discovered %d total URLs\n", len(crawlResults.AllURLs))
	color.Cyan("  - JavaScript files: %d\n", len(crawlResults.JSFiles))
	color.Cyan("  - JSON files: %d\n", len(crawlResults.JSONFiles))
	color.Cyan("  - API endpoints: %d\n", len(crawlResults.APIEndpoints))
	color.Cyan("  - Parameterized URLs: %d\n", len(crawlResults.ParamURLs))
	
	// Save URLs to files
	s.saveURLsToFiles(crawlResults)
	
	// Download JS and JSON files
	if len(crawlResults.JSFiles) > 0 || len(crawlResults.JSONFiles) > 0 {
		color.Yellow("[*] Downloading JS/JSON files...\n")
		downloadDir := filepath.Join(s.outputDir, "js_files", "downloaded")
		downloaded, err := c.DownloadFiles(crawlResults.JSFiles, crawlResults.JSONFiles, downloadDir)
		if err != nil {
			color.Yellow("[!] Download errors occurred: %v\n", err)
		}
		color.Green("[✓] Downloaded %d files\n", downloaded)
		
		s.mu.Lock()
		s.results.Statistics["downloaded_files"] = downloaded
		s.mu.Unlock()
	}
	
	// Update statistics
	s.mu.Lock()
	s.results.Statistics["total_urls"] = len(crawlResults.AllURLs)
	s.results.Statistics["js_files"] = len(crawlResults.JSFiles)
	s.results.Statistics["json_files"] = len(crawlResults.JSONFiles)
	s.results.Statistics["api_endpoints"] = len(crawlResults.APIEndpoints)
	s.results.Statistics["param_urls"] = len(crawlResults.ParamURLs)
	s.mu.Unlock()
	
	color.Green("[✓] Crawling complete\n")
	return nil
}

// saveURLsToFiles saves discovered URLs to respective files
func (s *Scanner) saveURLsToFiles(results *crawler.CrawlResults) {
	// Save all URLs
	if len(results.AllURLs) > 0 {
		s.writeLinesToFile(filepath.Join(s.outputDir, "all_urls.txt"), results.AllURLs)
	}
	
	// Save JS URLs
	if len(results.JSFiles) > 0 {
		s.writeLinesToFile(filepath.Join(s.outputDir, "js_files", "js_urls.txt"), results.JSFiles)
	}
	
	// Save JSON URLs
	if len(results.JSONFiles) > 0 {
		s.writeLinesToFile(filepath.Join(s.outputDir, "js_files", "json_urls.txt"), results.JSONFiles)
	}
	
	// Save API endpoints
	if len(results.APIEndpoints) > 0 {
		s.writeLinesToFile(filepath.Join(s.outputDir, "api_endpoints", "api_urls.txt"), results.APIEndpoints)
	}
	
	// Save parameterized URLs
	if len(results.ParamURLs) > 0 {
		s.writeLinesToFile(filepath.Join(s.outputDir, "api_endpoints", "param_urls.txt"), results.ParamURLs)
	}
}

// writeLinesToFile writes lines to a file
func (s *Scanner) writeLinesToFile(filename string, lines []string) {
	file, err := os.Create(filename)
	if err != nil {
		return
	}
	defer file.Close()
	
	for _, line := range lines {
		fmt.Fprintln(file, line)
	}
}

// runContentAnalysis analyzes downloaded content for secrets and patterns
func (s *Scanner) runContentAnalysis() error {
	color.Green("\n═══ Phase 2: Content Analysis ═══\n")
	
	var wg sync.WaitGroup
	
	// Secret scanning
	if s.config.EnableSecrets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.scanForSecrets()
		}()
	}
	
	wg.Wait()
	color.Green("[✓] Content analysis complete\n")
	return nil
}

// runVulnerabilityTests performs active security testing
func (s *Scanner) runVulnerabilityTests() error {
	color.Green("\n═══ Phase 3: Vulnerability Testing ═══\n")
	
	var wg sync.WaitGroup
	
	// CORS testing
	if s.config.EnableCORS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.testCORS()
		}()
	}
	
	wg.Wait()
	color.Green("[✓] Vulnerability testing complete\n")
	return nil
}

// scanForSecrets scans downloaded files for exposed secrets
func (s *Scanner) scanForSecrets() {
	color.Yellow("[*] Scanning for exposed secrets...\n")
	
	detector := secrets.NewDetector()
	jsDir := filepath.Join(s.outputDir, "js_files")
	
	// Walk through files
	totalSecrets := 0
	err := filepath.Walk(jsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		
		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip files we can't read
		}
		
		// Scan for secrets
		found := detector.ScanContent(string(content), path)
		
		s.mu.Lock()
		s.results.Secrets = append(s.results.Secrets, found...)
		totalSecrets += len(found)
		s.mu.Unlock()
		
		if len(found) > 0 {
			color.Red("[!] Found %d secrets in %s\n", len(found), filepath.Base(path))
		}
		
		return nil
	})
	
	if err != nil {
		color.Red("[!] Error during secret scanning: %v\n", err)
	}
	
	if totalSecrets > 0 {
		color.Red("[!] Total secrets found: %d\n", totalSecrets)
	} else {
		color.Green("[✓] No secrets detected\n")
	}
}

// testCORS performs CORS misconfiguration testing
func (s *Scanner) testCORS() {
	color.Yellow("[*] Testing CORS configuration...\n")
	
	tester := cors.NewTester(s.config)
	findings := tester.Test(s.targetURL)
	
	s.mu.Lock()
	s.results.CORSFindings = append(s.results.CORSFindings, findings...)
	s.mu.Unlock()
	
	if len(findings) > 0 {
		color.Red("[!] Found %d CORS issues\n", len(findings))
	} else {
		color.Green("[✓] No CORS misconfigurations detected\n")
	}
}

// generateReports creates HTML, JSON, and optionally PDF reports
func (s *Scanner) generateReports() error {
	color.Green("\n═══ Phase 4: Generating Reports ═══\n")
	
	reportGen := report.NewGenerator(s.config, s.outputDir)
	
	// Calculate statistics
	s.results.Statistics["scan_duration"] = time.Since(s.startTime).String()
	s.results.Statistics["total_secrets"] = len(s.results.Secrets)
	s.results.Statistics["total_cors_issues"] = len(s.results.CORSFindings)
	s.results.Statistics["total_vulnerabilities"] = len(s.results.Vulnerabilities)
	
	// Generate HTML report
	htmlPath := filepath.Join(s.outputDir, "reports", "report.html")
	if err := reportGen.GenerateHTML(s.results, htmlPath); err != nil {
		return fmt.Errorf("failed to generate HTML report: %w", err)
	}
	color.Green("[✓] HTML report: %s\n", htmlPath)
	
	// Generate JSON report
	jsonPath := filepath.Join(s.outputDir, "reports", "scan_summary.json")
	if err := reportGen.GenerateJSON(s.results, jsonPath); err != nil {
		return fmt.Errorf("failed to generate JSON report: %w", err)
	}
	color.Green("[✓] JSON report: %s\n", jsonPath)
	
	// Generate PDF report if enabled
	if s.config.PDFReport {
		pdfPath := filepath.Join(s.outputDir, "reports", "report.pdf")
		if err := reportGen.GeneratePDF(s.results, pdfPath); err != nil {
			color.Yellow("[!] PDF generation failed: %v\n", err)
		} else {
			color.Green("[✓] PDF report: %s\n", pdfPath)
		}
	}
	
	return nil
}

// printSummary displays scan results summary
func (s *Scanner) printSummary() {
	duration := time.Since(s.startTime)
	
	color.Cyan("\n╔═══════════════════════════════════════════════╗\n")
	color.Cyan("║          Scan Summary                         ║\n")
	color.Cyan("╚═══════════════════════════════════════════════╝\n\n")
	
	fmt.Printf("Target URL:     %s\n", s.targetURL)
	fmt.Printf("Scan Duration:  %s\n", duration.Round(time.Second))
	fmt.Printf("Output Dir:     %s\n\n", s.outputDir)
	
	// Statistics
	color.Yellow("Discovery:\n")
	fmt.Printf("  URLs:         %v\n", s.results.Statistics["total_urls"])
	fmt.Printf("  JS Files:     %v\n", s.results.Statistics["js_files"])
	fmt.Printf("  API Endpoints: %v\n\n", s.results.Statistics["api_endpoints"])
	
	// Findings
	color.Red("Security Findings:\n")
	
	// Secrets by severity
	criticalSecrets := 0
	highSecrets := 0
	mediumSecrets := 0
	lowSecrets := 0
	
	for _, secret := range s.results.Secrets {
		switch secret.Severity {
		case "Critical":
			criticalSecrets++
		case "High":
			highSecrets++
		case "Medium":
			mediumSecrets++
		case "Low":
			lowSecrets++
		}
	}
	
	if criticalSecrets > 0 {
		color.Red("  Critical Secrets:    %d\n", criticalSecrets)
	}
	if highSecrets > 0 {
		color.Red("  High Secrets:        %d\n", highSecrets)
	}
	if mediumSecrets > 0 {
		color.Yellow("  Medium Secrets:      %d\n", mediumSecrets)
	}
	if lowSecrets > 0 {
		color.Green("  Low Secrets:         %d\n", lowSecrets)
	}
	
	if len(s.results.CORSFindings) > 0 {
		color.Red("  CORS Issues:         %d\n", len(s.results.CORSFindings))
	}
	
	if len(s.results.Vulnerabilities) > 0 {
		color.Red("  Vulnerabilities:     %d\n", len(s.results.Vulnerabilities))
	}
	
	fmt.Println()
	color.Cyan("Reports generated in: %s\n", filepath.Join(s.outputDir, "reports"))
}

// extractDomain extracts domain name from URL
func extractDomain(url string) string {
	// Simple extraction - can be improved
	domain := url
	if idx := strings.Index(url, "://"); idx != -1 {
		domain = url[idx+3:]
	}
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}
