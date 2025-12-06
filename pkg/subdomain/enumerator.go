package subdomain

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mohseenjamall/apjson/pkg/config"
)

// Result represents a discovered subdomain
type Result struct {
	Subdomain   string
	IPAddresses []string
	Source      string // "subfinder", "bruteforce", "certspotter", etc.
	Timestamp   time.Time
}

// Enumerator performs subdomain enumeration
type Enumerator struct {
	config       *config.Config
	domain       string
	outputDir    string
	results      []Result
	mu           sync.Mutex
	resolvedSubs map[string]bool
}

// NewEnumerator creates a new subdomain enumerator
func NewEnumerator(cfg *config.Config, domain, outputDir string) *Enumerator {
	return &Enumerator{
		config:       cfg,
		domain:       domain,
		outputDir:    outputDir,
		results:      make([]Result, 0),
		resolvedSubs: make(map[string]bool),
	}
}

// Enumerate runs subdomain enumeration using multiple techniques
func (e *Enumerator) Enumerate() ([]Result, error) {
	var wg sync.WaitGroup

	// Passive enumeration with Subfinder
	if e.isSubfinderAvailable() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.runSubfinder()
		}()
	}

	// DNS bruteforce (optional, can be slow)
	if e.config.EnableSubdomains {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.runDNSBruteforce()
		}()
	}

	wg.Wait()

	// Resolve all discovered subdomains
	e.resolveSubdomains()

	return e.results, nil
}

// isSubfinderAvailable checks if Subfinder is installed
func (e *Enumerator) isSubfinderAvailable() bool {
	cmd := exec.Command("subfinder", "-version")
	err := cmd.Run()
	return err == nil
}

// runSubfinder uses ProjectDiscovery's Subfinder for passive enumeration
func (e *Enumerator) runSubfinder() {
	outputFile := filepath.Join(e.outputDir, "subfinder_results.txt")

	args := []string{
		"-d", e.domain,
		"-o", outputFile,
		"-silent",
		"-all", // Use all sources
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "subfinder", args...)
	if err := cmd.Run(); err != nil {
		return
	}

	// Read results
	file, err := os.Open(outputFile)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain == "" {
			continue
		}

		e.mu.Lock()
		if !e.resolvedSubs[subdomain] {
			e.results = append(e.results, Result{
				Subdomain: subdomain,
				Source:    "subfinder",
				Timestamp: time.Now(),
			})
			e.resolvedSubs[subdomain] = true
		}
		e.mu.Unlock()
	}
}

// runDNSBruteforce performs DNS bruteforce with common subdomain names
func (e *Enumerator) runDNSBruteforce() {
	// Common subdomains to try
	commonSubs := []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
		"ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
		"ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
		"ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
		"static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
		"wiki", "web", "media", "email", "images", "img", "www1", "intranet",
		"portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4",
		"www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my",
		"svn", "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup",
		"mx2", "lyncdiscover", "info", "apps", "download", "remote", "db", "forums",
		"store", "relay", "files", "newsletter", "app", "live", "owa", "en", "start",
		"sms", "office", "exchange", "ipv4",
	}

	sem := make(chan struct{}, 50) // Limit concurrent DNS queries
	var wg sync.WaitGroup

	for _, sub := range commonSubs {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fullDomain := subdomain + "." + e.domain
			ips, err := e.resolveDomain(fullDomain)
			if err == nil && len(ips) > 0 {
				e.mu.Lock()
				if !e.resolvedSubs[fullDomain] {
					e.results = append(e.results, Result{
						Subdomain:   fullDomain,
						IPAddresses: ips,
						Source:      "bruteforce",
						Timestamp:   time.Now(),
					})
					e.resolvedSubs[fullDomain] = true
				}
				e.mu.Unlock()
			}
		}(sub)
	}

	wg.Wait()
}

// resolveSubdomains resolves IP addresses for all discovered subdomains
func (e *Enumerator) resolveSubdomains() {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for i := range e.results {
		if len(e.results[i].IPAddresses) > 0 {
			continue // Already resolved
		}

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ips, err := e.resolveDomain(e.results[idx].Subdomain)
			if err == nil {
				e.mu.Lock()
				e.results[idx].IPAddresses = ips
				e.mu.Unlock()
			}
		}(i)
	}

	wg.Wait()
}

// resolveDomain resolves a domain to IP addresses
func (e *Enumerator) resolveDomain(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, ip.String())
	}

	return result, nil
}

// CheckSubdomainTakeover checks for potential subdomain takeover vulnerabilities
func (e *Enumerator) CheckSubdomainTakeover(subdomain string) (bool, string) {
	// Common fingerprints for subdomain takeover
	takeoverFingerprints := map[string][]string{
		"GitHub Pages": {
			"There isn't a GitHub Pages site here",
			"For root URLs (like http://example.com/) you must provide an index.html file",
		},
		"Heroku": {
			"No such app",
			"There's nothing here, yet.",
		},
		"Amazon S3": {
			"NoSuchBucket",
			"The specified bucket does not exist",
		},
		"Shopify": {
			"Sorry, this shop is currently unavailable",
		},
		"Tumblr": {
			"Whatever you were looking for doesn't currently exist at this address",
		},
		"WordPress": {
			"Do you want to register",
		},
		"Ghost": {
			"The thing you were looking for is no longer here",
		},
		"Bitbucket": {
			"Repository not found",
		},
	}

	// Try to fetch the subdomain
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Simple HTTP check (would need proper HTTP client in production)
	cmd := exec.CommandContext(ctx, "curl", "-L", "-s", "http://"+subdomain)
	output, err := cmd.Output()
	if err != nil {
		return false, ""
	}

	responseBody := string(output)

	// Check for takeover fingerprints
	for service, fingerprints := range takeoverFingerprints {
		for _, fingerprint := range fingerprints {
			if strings.Contains(responseBody, fingerprint) {
				return true, service
			}
		}
	}

	return false, ""
}

// SaveResults saves enumeration results to files
func (e *Enumerator) SaveResults() error {
	// Save all subdomains
	allSubsFile := filepath.Join(e.outputDir, "subdomains_all.txt")
	file, err := os.Create(allSubsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, result := range e.results {
		fmt.Fprintf(file, "%s\t%s\t%s\n",
			result.Subdomain,
			strings.Join(result.IPAddresses, ","),
			result.Source,
		)
	}

	return nil
}

// GetStatistics returns enumeration statistics
func (e *Enumerator) GetStatistics() map[string]int {
	stats := map[string]int{
		"total_subdomains": len(e.results),
		"resolved":         0,
		"subfinder":        0,
		"bruteforce":       0,
	}

	for _, result := range e.results {
		if len(result.IPAddresses) > 0 {
			stats["resolved"]++
		}
		if result.Source == "subfinder" {
			stats["subfinder"]++
		} else if result.Source == "bruteforce" {
			stats["bruteforce"]++
		}
	}

	return stats
}
