package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/mohseenjamall/apjson/pkg/injection"
	"github.com/mohseenjamall/apjson/pkg/types"
)

// testInjections performs SQL injection and XSS testing
func (s *Scanner) testInjections() {
	color.Yellow("[*] Testing for injection vulnerabilities...\\n")

	injectionTester := injection.NewTester(s.config)

	// Get parameterized URLs from crawl results
	paramURLs := s.getParameterizedURLs()
	if len(paramURLs) == 0 {
		color.Yellow("[*] No parameterized URLs found for injection testing\\n")
		return
	}

	color.Cyan("[*] Testing %d parameterized URLs\\n", len(paramURLs))

	totalVulns := 0
	tested := 0
	maxTests := 20 // Limit for performance

	for _, urlStr := range paramURLs {
		if tested >= maxTests {
			break
		}
		tested++

		// Test for SQL injection
		vulns := injectionTester.TestURL(urlStr)

		s.mu.Lock()
		for _, vuln := range vulns {
			// Convert to types.Vulnerability
			s.results.Vulnerabilities = append(s.results.Vulnerabilities, types.Vulnerability{
				Type:        string(vuln.Type),
				Severity:    vuln.Severity,
				URL:         vuln.URL,
				Parameter:   vuln.Parameter,
				Description: vuln.Description,
				Remediation: vuln.Remediation,
			})
			totalVulns++
		}
		s.mu.Unlock()

		if len(vulns) > 0 {
			for _, v := range vulns {
				color.Red("[!] %s in parameter '%s' (%s)\\n", v.Type, v.Parameter, v.Technique)
			}
		}
	}

	if totalVulns > 0 {
		color.Red("[!] Total injection vulnerabilities found: %d\\n", totalVulns)
	} else {
		color.Green("[✓] No injection vulnerabilities detected\\n")
	}
}

// getParameterizedURLs returns URLs with query parameters from crawl results
func (s *Scanner) getParameterizedURLs() []string {
	paramURLsFile := filepath.Join(s.outputDir, "api_endpoints", "param_urls.txt")

	file, err := os.Open(paramURLsFile)
	if err != nil {
		return []string{}
	}
	defer file.Close()

	urls := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}

	return urls
}
