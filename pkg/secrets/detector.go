package secrets

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// SecretType represents the category of detected secret
type SecretType string

const (
	SecretTypeAWSAccessKey          SecretType = "AWS Access Key ID"
	SecretTypeAWSSecretKey          SecretType = "AWS Secret Access Key"
	SecretTypeAWSSessionToken       SecretType = "AWS Session Token"
	SecretTypeGCPAPIKey             SecretType = "Google Cloud API Key"
	SecretTypeGCPServiceAccount     SecretType = "Google Cloud Service Account"
	SecretTypeAzureConnectionString SecretType = "Azure Connection String"
	SecretTypeGitHubToken           SecretType = "GitHub Token"
	SecretTypeGitHubPAT             SecretType = "GitHub Personal Access Token"
	SecretTypeJWT                   SecretType = "JWT Token"
	SecretTypeSlackToken            SecretType = "Slack Token"
	SecretTypeSlackWebhook          SecretType = "Slack Webhook"
	SecretTypeStripeKey             SecretType = "Stripe API Key"
	SecretTypeTwilioKey             SecretType = "Twilio API Key"
	SecretTypeMailgunKey            SecretType = "Mailgun API Key"
	SecretTypeSendGridKey           SecretType = "SendGrid API Key"
	SecretTypePrivateKey            SecretType = "Private Key"
	SecretTypePassword              SecretType = "Password"
	SecretTypeDatabaseURL           SecretType = "Database Connection String"
	SecretTypeAPIKey                SecretType = "Generic API Key"
	SecretTypeHighEntropy           SecretType = "High Entropy String"
)

// Secret represents a detected secret with metadata
type Secret struct {
	Type       SecretType
	Value      string
	Context    string
	FilePath   string
	LineNumber int
	Severity   string
	Entropy    float64
	Confidence float64
	Hash       string
}

// Detector handles secret detection with multiple strategies
type Detector struct {
	patterns        map[SecretType]*regexp.Regexp
	minEntropyScore float64
	excludePatterns []*regexp.Regexp
}

// NewDetector creates a new secret detector with predefined patterns
func NewDetector() *Detector {
	d := &Detector{
		patterns:        make(map[SecretType]*regexp.Regexp),
		minEntropyScore: 4.5, // Shannon entropy threshold
		excludePatterns: make([]*regexp.Regexp, 0),
	}

	d.initializePatterns()
	d.initializeExcludePatterns()

	return d
}

// initializePatterns sets up regex patterns for known secret types
func (d *Detector) initializePatterns() {
	patterns := map[SecretType]string{
		// AWS Credentials
		SecretTypeAWSAccessKey:    `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
		SecretTypeAWSSecretKey:    `(?i)aws(.{0,20})?['"\s]*[0-9a-zA-Z/+=]{40}`,
		SecretTypeAWSSessionToken: `(?i)aws(.{0,20})?session(.{0,20})?['"\s]*[0-9a-zA-Z/+=]{100,}`,

		// Google Cloud Platform
		SecretTypeGCPAPIKey:         `AIza[0-9A-Za-z\\-_]{35}`,
		SecretTypeGCPServiceAccount: `"type":\s*"service_account"`,

		// Azure
		SecretTypeAzureConnectionString: `(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}`,

		// GitHub
		SecretTypeGitHubToken: `(?i)github[_\s]*(token|pat)[_\s]*[:=]\s*['"]?([a-f0-9]{40}|ghp_[a-zA-Z0-9]{36})['"]?`,
		SecretTypeGitHubPAT:   `ghp_[a-zA-Z0-9]{36}`,

		// JWT
		SecretTypeJWT: `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}`,

		// Slack
		SecretTypeSlackToken:   `xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`,
		SecretTypeSlackWebhook: `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,

		// Payment & Email APIs
		SecretTypeStripeKey:   `(?i)(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}`,
		SecretTypeTwilioKey:   `SK[0-9a-fA-F]{32}`,
		SecretTypeMailgunKey:  `key-[0-9a-zA-Z]{32}`,
		SecretTypeSendGridKey: `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`,

		// Private Keys
		SecretTypePrivateKey: `-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----`,

		// Database Connection Strings
		SecretTypeDatabaseURL: `(?i)(mongodb|mysql|postgres|postgresql|redis)://[^\s]+:[^\s]+@[^\s]+`,

		// Generic Patterns
		SecretTypePassword: `(?i)(password|passwd|pwd|secret)[\s]*[:=][\s]*['"]([^'"]{8,})['"]`,
		SecretTypeAPIKey:   `(?i)(api[_\s]?key|apikey)[\s]*[:=][\s]*['"]([a-zA-Z0-9]{32,})['"]`,
	}

	for secretType, pattern := range patterns {
		d.patterns[secretType] = regexp.MustCompile(pattern)
	}
}

// initializeExcludePatterns sets up patterns for common false positives
func (d *Detector) initializeExcludePatterns() {
	excludes := []string{
		// Common placeholder patterns
		`(?i)(example|sample|test|demo|fake|dummy|placeholder|xxx+|000+)`,
		// Documentation URLs
		`(?i)(docs?\.|\w+\.readme|github\.com/.*#)`,
		// Variable names
		`(?i)^(var|let|const|def|function)\s`,
		// Common test strings
		`(?i)(your_|my_|insert_|replace_)(key|token|secret|password)`,
	}

	for _, pattern := range excludes {
		d.excludePatterns = append(d.excludePatterns, regexp.MustCompile(pattern))
	}
}

// ScanContent scans the given content for secrets
func (d *Detector) ScanContent(content, filePath string) []Secret {
	secrets := make([]Secret, 0)

	// Regex-based detection
	for secretType, pattern := range d.patterns {
		matches := pattern.FindAllStringSubmatchIndex(content, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}

			value := content[match[0]:match[1]]
			lineNum := d.getLineNumber(content, match[0])
			context := d.extractContext(content, match[0], 50)

			// Skip if matches exclude patterns
			if d.isExcluded(value) || d.isExcluded(context) {
				continue
			}

			secret := Secret{
				Type:       secretType,
				Value:      value,
				Context:    context,
				FilePath:   filePath,
				LineNumber: lineNum,
				Entropy:    d.calculateEntropy(value),
				Confidence: d.calculateConfidence(secretType, value),
				Hash:       d.hashSecret(value),
			}

			secret.Severity = d.calculateSeverity(secret)
			secrets = append(secrets, secret)
		}
	}

	// Entropy-based detection for unknown secrets
	entropySecrets := d.scanWithEntropy(content, filePath)
	secrets = append(secrets, entropySecrets...)

	return d.deduplicateSecrets(secrets)
}

// scanWithEntropy detects high-entropy strings that might be secrets
func (d *Detector) scanWithEntropy(content, filePath string) []Secret {
	secrets := make([]Secret, 0)

	// Look for Base64-encoded strings
	base64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	matches := base64Pattern.FindAllStringIndex(content, -1)

	for _, match := range matches {
		value := content[match[0]:match[1]]
		entropy := d.calculateEntropy(value)

		// Only flag if entropy is high enough and length is significant
		if entropy >= d.minEntropyScore && len(value) >= 20 && len(value) <= 200 {
			if d.isExcluded(value) {
				continue
			}

			lineNum := d.getLineNumber(content, match[0])
			context := d.extractContext(content, match[0], 50)

			secret := Secret{
				Type:       SecretTypeHighEntropy,
				Value:      value,
				Context:    context,
				FilePath:   filePath,
				LineNumber: lineNum,
				Entropy:    entropy,
				Confidence: d.calculateEntropyConfidence(entropy, len(value)),
				Hash:       d.hashSecret(value),
				Severity:   "Medium",
			}

			secrets = append(secrets, secret)
		}
	}

	return secrets
}

// calculateEntropy calculates Shannon entropy of a string
func (d *Detector) calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	frequencies := make(map[rune]float64)
	for _, char := range s {
		frequencies[char]++
	}

	var entropy float64
	length := float64(len(s))

	for _, freq := range frequencies {
		probability := freq / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// CalculateEntropy is the exported version for testing
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	frequencies := make(map[rune]float64)
	for _, char := range s {
		frequencies[char]++
	}

	var entropy float64
	length := float64(len(s))

	for _, freq := range frequencies {
		probability := freq / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// calculateConfidence determines confidence score based on pattern match
func (d *Detector) calculateConfidence(secretType SecretType, value string) float64 {
	// High confidence for specific patterns
	highConfidenceTypes := map[SecretType]bool{
		SecretTypeAWSAccessKey: true,
		SecretTypeGCPAPIKey:    true,
		SecretTypeGitHubPAT:    true,
		SecretTypeStripeKey:    true,
		SecretTypeSlackToken:   true,
		SecretTypePrivateKey:   true,
	}

	if highConfidenceTypes[secretType] {
		return 0.95
	}

	// Medium confidence for contextual patterns
	return 0.75
}

// calculateEntropyConfidence determines confidence for entropy-based detection
func (d *Detector) calculateEntropyConfidence(entropy float64, length int) float64 {
	// Higher entropy = higher confidence
	baseScore := (entropy - d.minEntropyScore) / (8.0 - d.minEntropyScore)

	// Longer strings = higher confidence
	lengthScore := float64(length) / 100.0
	if lengthScore > 1.0 {
		lengthScore = 1.0
	}

	return (baseScore + lengthScore) / 2.0
}

// calculateSeverity determines severity level of the secret
func (d *Detector) calculateSeverity(secret Secret) string {
	criticalTypes := map[SecretType]bool{
		SecretTypeAWSSecretKey:      true,
		SecretTypeAWSSessionToken:   true,
		SecretTypePrivateKey:        true,
		SecretTypeDatabaseURL:       true,
		SecretTypeGCPServiceAccount: true,
	}

	highTypes := map[SecretType]bool{
		SecretTypeAWSAccessKey:          true,
		SecretTypeGitHubPAT:             true,
		SecretTypeStripeKey:             true,
		SecretTypeSlackToken:            true,
		SecretTypeAzureConnectionString: true,
	}

	if criticalTypes[secret.Type] {
		return "Critical"
	}
	if highTypes[secret.Type] {
		return "High"
	}
	if secret.Confidence >= 0.8 {
		return "High"
	}
	if secret.Confidence >= 0.6 {
		return "Medium"
	}
	return "Low"
}

// isExcluded checks if a value matches exclude patterns
func (d *Detector) isExcluded(value string) bool {
	for _, pattern := range d.excludePatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

// getLineNumber returns the line number for a position in content
func (d *Detector) getLineNumber(content string, pos int) int {
	return strings.Count(content[:pos], "\n") + 1
}

// extractContext extracts surrounding context for a match
func (d *Detector) extractContext(content string, pos, radius int) string {
	start := pos - radius
	if start < 0 {
		start = 0
	}

	end := pos + radius
	if end > len(content) {
		end = len(content)
	}

	context := content[start:end]
	// Remove newlines for cleaner display
	context = strings.ReplaceAll(context, "\n", " ")
	context = strings.ReplaceAll(context, "\r", "")

	return strings.TrimSpace(context)
}

// hashSecret creates a hash of the secret for deduplication
func (d *Detector) hashSecret(value string) string {
	hash := sha256.Sum256([]byte(value))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// deduplicateSecrets removes duplicate secrets based on hash
func (d *Detector) deduplicateSecrets(secrets []Secret) []Secret {
	seen := make(map[string]bool)
	unique := make([]Secret, 0)

	for _, secret := range secrets {
		if !seen[secret.Hash] {
			seen[secret.Hash] = true
			unique = append(unique, secret)
		}
	}

	return unique
}

// GetSummary returns a summary of detected secrets by type and severity
func GetSummary(secrets []Secret) map[string]interface{} {
	summary := make(map[string]interface{})

	byType := make(map[SecretType]int)
	bySeverity := make(map[string]int)

	for _, secret := range secrets {
		byType[secret.Type]++
		bySeverity[secret.Severity]++
	}

	summary["total"] = len(secrets)
	summary["by_type"] = byType
	summary["by_severity"] = bySeverity

	return summary
}

// FormatSecret formats a secret for display
func (s *Secret) FormatSecret() string {
	return fmt.Sprintf("[%s] %s (Confidence: %.2f, Entropy: %.2f) at %s:%d",
		s.Severity, s.Type, s.Confidence, s.Entropy, s.FilePath, s.LineNumber)
}
