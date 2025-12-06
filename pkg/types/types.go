package types

import (
	"github.com/mohseenjamall/apjson/pkg/secrets"
	"github.com/mohseenjamall/apjson/pkg/cors"
)

// ScanResults holds all scan findings
type ScanResults struct {
	TargetURL       string
	Secrets         []secrets.Secret
	CORSFindings    []cors.Finding
	Vulnerabilities []Vulnerability
	Statistics      map[string]interface{}
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	Type        string
	Severity    string
	URL         string
	Parameter   string
	Description string
	Remediation string
	CVSSScore   float64
}
