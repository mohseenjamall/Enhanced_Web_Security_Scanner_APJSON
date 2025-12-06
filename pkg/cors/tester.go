package cors

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mohseenjamall/apjson/pkg/config"
)

// FindingType represents the type of CORS issue
type FindingType string

const (
	WildcardOrigin      FindingType = "Wildcard Origin Allowed"
	NullOriginBypass    FindingType = "Null Origin Bypass"
	TrustedSubdomains   FindingType = "Trusted Subdomain Bypass"
	InsecureHTTP        FindingType = "HTTP Origin Allowed"
	CredentialsExposed  FindingType = "Credentials with Wildcard"
	PreflightBypass     FindingType = "Preflight Bypass"
	MissingHeaders      FindingType = "Missing CORS Headers"
)

// Finding represents a CORS security issue
type Finding struct {
	Type        FindingType
	Severity    string
	URL         string
	Origin      string
	Headers     map[string]string
	Description string
	Remediation string
}

// Tester performs CORS security testing
type Tester struct {
	config *config.Config
	client *http.Client
}

// NewTester creates a new CORS tester
func NewTester(cfg *config.Config) *Tester {
	return &Tester{
		config: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.ScanTimeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Test performs comprehensive CORS testing
func (t *Tester) Test(targetURL string) []Finding {
	findings := make([]Finding, 0)
	
	// Test origins to try
	testOrigins := []string{
		"https://evil.com",
		"null",
		"http://" + extractDomain(targetURL),
		extractSubdomain(targetURL),
	}
	
	for _, origin := range testOrigins {
		finding := t.testOrigin(targetURL, origin)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	
	// Test for missing security headers
	headerFindings := t.testSecurityHeaders(targetURL)
	findings = append(findings, headerFindings...)
	
	return findings
}

// testOrigin tests a specific origin
func (t *Tester) testOrigin(url, origin string) *Finding {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", t.config.UserAgent)
	
	resp, err := t.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	// Check Access-Control-Allow-Origin header
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")
	
	if allowOrigin == "" {
		return nil
	}
	
	// Check for wildcard with credentials
	if allowOrigin == "*" && strings.ToLower(allowCreds) == "true" {
		return &Finding{
			Type:     CredentialsExposed,
			Severity: "Critical",
			URL:      url,
			Origin:   origin,
			Headers: map[string]string{
				"Access-Control-Allow-Origin":      allowOrigin,
				"Access-Control-Allow-Credentials": allowCreds,
			},
			Description: "Server allows wildcard origin (*) with credentials enabled. This exposes user data to any origin.",
			Remediation: "Never use wildcard (*) with Access-Control-Allow-Credentials: true. Specify explicit origins instead.",
		}
	}
	
	// Check for null origin bypass
	if origin == "null" && (allowOrigin == "null" || allowOrigin == origin) {
		return &Finding{
			Type:     NullOriginBypass,
			Severity: "High",
			URL:      url,
			Origin:   origin,
			Headers: map[string]string{
				"Access-Control-Allow-Origin": allowOrigin,
			},
			Description: "Server reflects 'null' origin, allowing sandbox bypass attacks.",
			Remediation: "Reject 'null' origin in CORS policy. Validate origins against a whitelist.",
		}
	}
	
	// Check if evil origin is reflected
	if strings.Contains(origin, "evil") && (allowOrigin == origin || allowOrigin == "*") {
		severity := "High"
		if allowOrigin == "*" {
			severity = "Medium"
		}
		
		return &Finding{
			Type:     WildcardOrigin,
			Severity: severity,
			URL:      url,
			Origin:   origin,
			Headers: map[string]string{
				"Access-Control-Allow-Origin": allowOrigin,
			},
			Description: fmt.Sprintf("Server allows untrusted origin: %s", origin),
			Remediation: "Implement strict origin validation. Only allow trusted domains.",
		}
	}
	
	// Check for HTTP downgrade
	if strings.HasPrefix(origin, "http://") && strings.HasPrefix(url, "https://") {
		if allowOrigin == origin || allowOrigin == "*" {
			return &Finding{
				Type:     InsecureHTTP,
				Severity: "Medium",
				URL:      url,
				Origin:   origin,
				Headers: map[string]string{
					"Access-Control-Allow-Origin": allowOrigin,
				},
				Description: "HTTPS site allows HTTP origin, enabling downgrade attacks.",
				Remediation: "Only allow HTTPS origins for HTTPS sites.",
			}
		}
	}
	
	return nil
}

// testSecurityHeaders tests for missing or weak security headers
func (t *Tester) testSecurityHeaders(url string) []Finding {
	findings := make([]Finding, 0)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return findings
	}
	
	req.Header.Set("User-Agent", t.config.UserAgent)
	
	resp, err := t.client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()
	
	// Check for important security headers
	securityHeaders := map[string]string{
		"X-Frame-Options":           "Prevents clickjacking attacks",
		"X-Content-Type-Options":    "Prevents MIME-sniffing attacks",
		"Strict-Transport-Security": "Enforces HTTPS connections",
		"Content-Security-Policy":   "Prevents XSS and injection attacks",
		"X-XSS-Protection":          "Enables browser XSS protection",
	}
	
	missingHeaders := make([]string, 0)
	for header, purpose := range securityHeaders {
		if resp.Header.Get(header) == "" {
			missingHeaders = append(missingHeaders, fmt.Sprintf("%s (%s)", header, purpose))
		}
	}
	
	if len(missingHeaders) > 0 {
		findings = append(findings, Finding{
			Type:        MissingHeaders,
			Severity:    "Low",
			URL:         url,
			Description: fmt.Sprintf("Missing security headers: %s", strings.Join(missingHeaders, ", ")),
			Remediation: "Implement missing security headers to enhance protection against common web attacks.",
		})
	}
	
	return findings
}

// extractDomain extracts domain from URL
func extractDomain(url string) string {
	domain := url
	if idx := strings.Index(url, "://"); idx != -1 {
		domain = url[idx+3:]
	}
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}

// extractSubdomain creates a subdomain variant for testing
func extractSubdomain(url string) string {
	domain := extractDomain(url)
	
	// Extract protocol
	protocol := "https://"
	if strings.HasPrefix(url, "http://") {
		protocol = "http://"
	}
	
	return protocol + "attacker." + domain
}
