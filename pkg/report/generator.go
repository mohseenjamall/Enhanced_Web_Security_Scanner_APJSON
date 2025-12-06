package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/mohseenjamall/apjson/pkg/config"
	"github.com/mohseenjamall/apjson/pkg/types"
)

// Generator handles report generation in multiple formats
type Generator struct {
	config    *config.Config
	outputDir string
}

// NewGenerator creates a new report generator
func NewGenerator(cfg *config.Config, outputDir string) *Generator {
	return &Generator{
		config:    cfg,
		outputDir: outputDir,
	}
}

// GenerateHTML creates an interactive HTML report
func (g *Generator) GenerateHTML(results *types.ScanResults, outputPath string) error {
	htmlTemplate := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {{.TargetURL}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; color: #2c3e50; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        h1 { font-size: 28px; margin-bottom: 10px; }
        .meta { opacity: 0.9; font-size: 14px; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .stat-value { font-size: 36px; font-weight: bold; margin-bottom: 10px; }
        .stat-label { color: #7f8c8d; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f39c12; }
        .low { color: #27ae60; }
        .section { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h2 { color: #2c3e50; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #3498db; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }
        th { background: #f8f9fa; font-weight: 600; color: #2c3e50; }
        tr:hover { background: #f8f9fa; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }
        .badge-critical { background: #e74c3c; }
        .badge-high { background: #e67e22; }
        .badge-medium { background: #f39c12; }
        .badge-low { background: #27ae60; }
        .footer { text-align: center; padding: 20px; color: #7f8c8d; font-size: 14px; }
        code { background: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Web Security Scan Report</h1>
            <div class="meta">
                <p>Target: {{.TargetURL}}</p>
                <p>Generated: {{.Timestamp}}</p>
                <p>Duration: {{.Duration}}</p>
            </div>
        </header>

        <div class="summary">
            <div class="stat-card">
                <div class="stat-value critical">{{.CriticalCount}}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value high">{{.HighCount}}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value medium">{{.MediumCount}}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value low">{{.LowCount}}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.TotalFindings}}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>

        {{if .Secrets}}
        <div class="section">
            <h2>🔐 Exposed Secrets</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Location</th>
                    <th>Confidence</th>
                </tr>
                {{range .Secrets}}
                <tr>
                    <td><span class="badge badge-{{.SeverityClass}}">{{.Severity}}</span></td>
                    <td>{{.Type}}</td>
                    <td><code>{{.FilePath}}:{{.LineNumber}}</code></td>
                    <td>{{.ConfidencePercent}}%</td>
                </tr>
                {{end}}
            </table>
        </div>
        {{end}}

        {{if .CORSFindings}}
        <div class="section">
            <h2>🌐 CORS Misconfigurations</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Issue</th>
                    <th>Description</th>
                    <th>Remediation</th>
                </tr>
                {{range .CORSFindings}}
                <tr>
                    <td><span class="badge badge-{{.SeverityClass}}">{{.Severity}}</span></td>
                    <td>{{.Type}}</td>
                    <td>{{.Description}}</td>
                    <td>{{.Remediation}}</td>
                </tr>
                {{end}}
            </table>
        </div>
        {{end}}

        <div class="footer">
            <p>Generated by Enhanced Web Security Scanner v3.0.0</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>`

	// Prepare template data
	data := g.prepareHTMLData(results)
	
	// Parse and execute template
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}
	
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	
	return tmpl.Execute(file, data)
}

// GenerateJSON creates a machine-readable JSON report
func (g *Generator) GenerateJSON(results *types.ScanResults, outputPath string) error {
	// Add metadata
	report := map[string]interface{}{
		"target":     results.TargetURL,
		"timestamp":  time.Now().Format(time.RFC3339),
		"statistics": results.Statistics,
		"secrets": results.Secrets,
		"cors_findings": results.CORSFindings,
		"vulnerabilities": results.Vulnerabilities,
	}
	
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	
	return os.WriteFile(outputPath, data, 0644)
}

// GeneratePDF creates a professional PDF report
func (g *Generator) GeneratePDF(results *types.ScanResults, outputPath string) error {
	// TODO: Implement PDF generation using wkhtmltopdf or similar
	// For now, return not implemented
	return fmt.Errorf("PDF generation not yet implemented")
}

// prepareHTMLData prepares data for HTML template
func (g *Generator) prepareHTMLData(results *types.ScanResults) map[string]interface{} {
	// Count findings by severity
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	
	for _, secret := range results.Secrets {
		switch secret.Severity {
		case "Critical":
			criticalCount++
		case "High":
			highCount++
		case "Medium":
			mediumCount++
		case "Low":
			lowCount++
		}
	}
	
	for _, finding := range results.CORSFindings {
		switch finding.Severity {
		case "Critical":
			criticalCount++
		case "High":
			highCount++
		case "Medium":
			mediumCount++
		case "Low":
			lowCount++
		}
	}
	
	// Prepare secrets for display
	type SecretDisplay struct {
		Severity          string
		SeverityClass     string
		Type              string
		FilePath          string
		LineNumber        int
		ConfidencePercent int
	}
	
	secretsDisplay := make([]SecretDisplay, 0)
	for _, s := range results.Secrets {
		secretsDisplay = append(secretsDisplay, SecretDisplay{
			Severity:          s.Severity,
			SeverityClass:     getSeverityClass(s.Severity),
			Type:              string(s.Type),
			FilePath:          s.FilePath,
			LineNumber:        s.LineNumber,
			ConfidencePercent: int(s.Confidence * 100),
		})
	}
	
	// Prepare CORS findings for display
	type CORSDisplay struct {
		Severity      string
		SeverityClass string
		Type          string
		Description   string
		Remediation   string
	}
	
	corsDisplay := make([]CORSDisplay, 0)
	for _, f := range results.CORSFindings {
		corsDisplay = append(corsDisplay, CORSDisplay{
			Severity:      f.Severity,
			SeverityClass: getSeverityClass(f.Severity),
			Type:          string(f.Type),
			Description:   f.Description,
			Remediation:   f.Remediation,
		})
	}
	
	return map[string]interface{}{
		"TargetURL":      results.TargetURL,
		"Timestamp":      time.Now().Format("2006-01-02 15:04:05"),
		"Duration":       results.Statistics["scan_duration"],
		"CriticalCount":  criticalCount,
		"HighCount":      highCount,
		"MediumCount":    mediumCount,
		"LowCount":       lowCount,
		"TotalFindings":  criticalCount + highCount + mediumCount + lowCount,
		"Secrets":        secretsDisplay,
		"CORSFindings":   corsDisplay,
	}
}

// getSeverityClass returns CSS class name for severity
func getSeverityClass(severity string) string {
	switch severity {
	case "Critical":
		return "critical"
	case "High":
		return "high"
	case "Medium":
		return "medium"
	case "Low":
		return "low"
	default:
		return "low"
	}
}
