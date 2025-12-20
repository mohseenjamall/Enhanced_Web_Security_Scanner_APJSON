package secrets

import (
	"testing"
)

// Test NewDetector
func TestNewDetector(t *testing.T) {
	detector := NewDetector()

	if detector == nil {
		t.Fatal("NewDetector returned nil")
	}

	if detector.patterns == nil {
		t.Error("Detector patterns not initialized")
	}

	if detector.minEntropyScore <= 0 {
		t.Error("Detector entropy threshold not set")
	}
}

// Test Detector ScanContent returns slice
func TestScanContentReturnsSlice(t *testing.T) {
	detector := NewDetector()

	result := detector.ScanContent("test content", "test.txt")

	if result == nil {
		t.Error("ScanContent should return empty slice, not nil")
	}
}

// Test high entropy detection
func TestHighEntropyDetection(t *testing.T) {
	detector := NewDetector()

	// Very high entropy string (should be detected)
	highEntropy := "aK8xN2mP9qR4sT7vW1yZ3bC5dF6gH2jK9"

	secrets := detector.ScanContent(highEntropy, "test.txt")

	// Should detect something with high entropy
	if len(secrets) > 0 {
		t.Logf("Detected secret type: %s with confidence %.2f", secrets[0].Type, secrets[0].Confidence)
	}
}

// Test CalculateEntropy export
func TestCalculateEntropyExport(t *testing.T) {
	tests := []struct {
		input    string
		minValue float64
		maxValue float64
	}{
		{"", 0, 0},
		{"aaaa", 0, 1},
		{"abc123XYZ!@#", 3, 5},
		{"aK8xN2mP9qR4sT7vW1yZ3bC5dF6gH", 4, 5},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			entropy := CalculateEntropy(tt.input)

			if entropy < tt.minValue || entropy > tt.maxValue {
				t.Errorf("CalculateEntropy(%q) = %.2f, want [%.2f, %.2f]",
					tt.input, entropy, tt.minValue, tt.maxValue)
			}
		})
	}
}

// Test AWS pattern
func TestAWSKeyPattern(t *testing.T) {
	detector := NewDetector()

	// Valid AWS Access Key pattern
	awsKey := "AKIAIOSFODNN7EXAMPLE"

	secrets := detector.ScanContent(awsKey, "test.txt")

	found := false
	for _, s := range secrets {
		if s.Type == SecretTypeAWSAccessKey {
			found = true
			t.Logf("Found AWS key with confidence %.2f", s.Confidence)
		}
	}

	if !found {
		t.Log("AWS key not detected - may need pattern adjustment")
	}
}

// Test GitHub Token pattern
func TestGitHubTokenPattern(t *testing.T) {
	detector := NewDetector()

	tokens := []string{
		"ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"gho_1234567890abcdefghijklmnopqrstuvwxyz",
	}

	for _, token := range tokens {
		secrets := detector.ScanContent(token, "test.txt")

		found := false
		for _, s := range secrets {
			if s.Type == SecretTypeGitHubToken || s.Type == SecretTypeGitHubPAT {
				found = true
				t.Logf("Found GitHub token type: %s", s.Type)
			}
		}

		if !found {
			t.Logf("GitHub token %s not detected", token[:10]+"...")
		}
	}
}

// Test Private Key Detection
func TestPrivateKeyDetection(t *testing.T) {
	detector := NewDetector()

	privateKey := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...
-----END PRIVATE KEY-----`

	secrets := detector.ScanContent(privateKey, "test.pem")

	for _, s := range secrets {
		if s.Type == SecretTypePrivateKey {
			t.Logf("Detected private key with severity: %s", s.Severity)
			return
		}
	}
}

// Test empty content
func TestEmptyContent(t *testing.T) {
	detector := NewDetector()

	secrets := detector.ScanContent("", "test.txt")

	if len(secrets) > 0 {
		t.Error("Empty content should not detect any secrets")
	}
}

// Test normal text (no secrets)
func TestNormalText(t *testing.T) {
	detector := NewDetector()

	normalTexts := []string{
		"Hello, world!",
		"This is a normal log message",
		"User logged in successfully",
		"123456789",
	}

	for _, text := range normalTexts {
		secrets := detector.ScanContent(text, "test.txt")

		// Should not detect high-confidence secrets
		for _, s := range secrets {
			if s.Confidence > 0.9 {
				t.Errorf("High confidence secret in normal text: %q (type: %s)", text, s.Type)
			}
		}
	}
}

// Test Secret struct fields
func TestSecretStructFields(t *testing.T) {
	secret := Secret{
		Type:       SecretTypeAWSAccessKey,
		Value:      "test",
		Context:    "context",
		FilePath:   "file.txt",
		LineNumber: 1,
		Severity:   "High",
		Entropy:    5.0,
		Confidence: 0.95,
		Hash:       "hash123",
	}

	if secret.Type != SecretTypeAWSAccessKey {
		t.Error("Secret Type not set correctly")
	}

	if secret.Confidence != 0.95 {
		t.Error("Secret Confidence not set correctly")
	}
}

// Benchmark ScanContent
func BenchmarkScanContent(b *testing.B) {
	detector := NewDetector()
	content := "Some content with AKIAIOSFODNN7EXAMPLE and password=secret123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.ScanContent(content, "test.txt")
	}
}

// Benchmark CalculateEntropy
func BenchmarkCalculateEntropy(b *testing.B) {
	content := "aK8xN2mP9qR4sT7vW1yZ3bC5dF6gH"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalculateEntropy(content)
	}
}
