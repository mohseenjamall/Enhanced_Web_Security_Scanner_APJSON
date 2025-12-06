package scanner

import (
	"strings"

	"github.com/fatih/color"
	"github.com/mohseenjamall/apjson/pkg/subdomain"
)

// enumerateSubdomains performs subdomain enumeration if enabled
func (s *Scanner) enumerateSubdomains() {
	if !s.config.EnableSubdomains {
		return
	}

	color.Yellow("[*] Enumerating subdomains...\\n")

	// Extract root domain from target URL
	domain := extractRootDomain(s.targetURL)
	if domain == "" {
		color.Red("[!] Could not extract domain from URL\\n")
		return
	}

	// Create subdomain enumerator
	enum := subdomain.NewEnumerator(s.config, domain, s.outputDir)

	// Run enumeration
	results, err := enum.Enumerate()
	if err != nil {
		color.Red("[!] Subdomain enumeration failed: %v\\n", err)
		return
	}

	// Save results
	if err := enum.SaveResults(); err != nil {
		color.Yellow("[!] Failed to save subdomain results: %v\\n", err)
	}

	// Display statistics
	stats := enum.GetStatistics()
	color.Green("[✓] Discovered %d subdomains\\n", stats["total_subdomains"])
	color.Cyan("  - Resolved: %d\\n", stats["resolved"])
	color.Cyan("  - From Subfinder: %d\\n", stats["subfinder"])
	color.Cyan("  - From Bruteforce: %d\\n", stats["bruteforce"])

	// Check for subdomain takeover (optional, on first few subdomains)
	color.Yellow("[*] Checking for subdomain takeover vulnerabilities...\\n")
	takeovers := 0
	checked := 0
	maxCheck := 10 // Limit checks for performance

	for _, result := range results {
		if checked >= maxCheck {
			break
		}
		checked++

		vulnerable, service := enum.CheckSubdomainTakeover(result.Subdomain)
		if vulnerable {
			takeovers++
			color.Red("[!] Potential subdomain takeover: %s (%s)\\n", result.Subdomain, service)
		}
	}

	if takeovers == 0 {
		color.Green("[✓] No subdomain takeover vulnerabilities detected\\n")
	}

	// Update scanner statistics
	s.mu.Lock()
	s.results.Statistics["total_subdomains"] = stats["total_subdomains"]
	s.results.Statistics["resolved_subdomains"] = stats["resolved"]
	s.results.Statistics["subdomain_takeovers"] = takeovers
	s.mu.Unlock()
}

// extractRootDomain extracts the root domain from a URL
func extractRootDomain(url string) string {
	// Remove protocol
	domain := url
	if idx := strings.Index(url, "://"); idx != -1 {
		domain = url[idx+3:]
	}

	// Remove path
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	// Remove port
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	// Extract root domain (simple approach - works for most cases)
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		// Return last two parts (e.g., example.com from www.example.com)
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}

	return domain
}
