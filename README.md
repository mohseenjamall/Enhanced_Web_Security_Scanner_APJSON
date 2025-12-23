# Enhanced Web Security Scanner (APJSON v3.0)

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker" alt="Docker">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=for-the-badge" alt="Platform">
  <br>
  <img src="https://github.com/mohseenjamall/apjson/workflows/CI/badge.svg" alt="CI Status">
  <img src="https://github.com/mohseenjamall/apjson/workflows/Docker/badge.svg" alt="Docker Build">
</p>

A comprehensive, professional-grade penetration testing tool for web application security assessment. Built in Go for high performance and easy deployment. **Now with Docker support for instant deployment!** 🐳

## 🚀 Quick Start

**Using Docker Hub (Fastest - No Build Required!):**
```bash
# Pull and run instantly!
docker pull mohseenjamall/apjson:latest
docker run --rm -v $(pwd)/results:/app/scan_results \
  mohseenjamall/apjson:latest https://example.com
```

**Or Build Locally:**
```bash
git clone https://github.com/mohseenjamall/apjson.git
cd apjson
docker build -t apjson:latest .
docker run --rm -v $(pwd)/results:/app/scan_results apjson:latest https://example.com
```

**Using Native Binary:**
```bash
git clone https://github.com/mohseenjamall/apjson.git
cd apjson
go build -o apjson main.go
./apjson https://example.com
```

📖 **Full documentation:** [Installation](#-installation) | [Docker Guide](DOCKER.md) | [Usage](#-usage)

---

## ✨ Features

### 🔍 Discovery & Crawling
- **Advanced Web Crawling** - Powered by Katana for efficient site discovery
- **JavaScript Analysis** - Extracts and analyzes JS/JSON files
- **API Endpoint Detection** - Identifies REST, GraphQL, and other API endpoints
- **Subdomain Enumeration** - Multi-source subdomain discovery *(optional)*

### 🛡️ Security Testing

#### Secret Detection
- **20+ Credential Types** - AWS, GCP, Azure, GitHub, Slack, Stripe, JWT, and more
- **Entropy-Based Detection** - Finds unknown secrets using Shannon entropy analysis
- **False-Positive Filtering** - Smart exclusion patterns
- **Confidence Scoring** - Each finding rated by confidence level

#### Vulnerability Detection
- **CORS Misconfigurations** - Wildcard origins, null bypass, credential exposure
- **Security Header Analysis** - Missing CSP, HSTS, X-Frame-Options, etc.
- **SQL Injection Testing** - Time-based, Error-based, Boolean-based blind ✅
- **XSS Detection** - Context-aware with polyglot payloads ✅
- **Subdomain Enumeration** - Passive and active discovery with takeover detection ✅
- **Authentication Bypass** - JWT, session fixation, default credentials *(optional)*
- **WAF Detection** - Identifies security products *(optional)*

### 📊 Reporting
- **Interactive HTML Reports** - Beautiful, color-coded findings
- **JSON Export** - Machine-readable format for integration
- **CVSS Scoring** - Industry-standard severity ratings
- **PDF Reports** - Professional documentation *(optional)*

## 🚀 Installation

### Option 1: Docker (Recommended) 🐳

**Easiest Way - Pull from Docker Hub:**
```bash
# No build needed! Just pull and run
docker pull mohseenjamall/apjson:latest

# Run a scan
docker run --rm -v $(pwd)/scan_results:/app/scan_results \
  mohseenjamall/apjson:latest https://example.com

# Or with Docker Compose - create docker-compose.yml:
services:
  apjson:
    image: mohseenjamall/apjson:latest
    volumes:
      - ./scan_results:/app/scan_results
```

**Or Build from Source:**

The easiest way to get started! No need to install Go or dependencies.

```bash
# Clone the repository
git clone https://github.com/mohseenjamall/apjson.git
cd apjson

# Build the Docker image
docker build -t apjson:latest .

# Run a scan
docker run --rm -v $(pwd)/scan_results:/app/scan_results apjson:latest https://example.com
```

**Or using Docker Compose:**
```bash
docker-compose run --rm apjson https://example.com
```

📖 **Full Docker documentation:** [DOCKER.md](DOCKER.md)

---

### Option 2: Native Binary

#### Prerequisites

#### 1. Install Go (Required)

**Windows:**
```powershell
# Using winget
winget install GoLang.Go

# Or download from: https://go.dev/dl/
```

**Linux:**
```bash
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

**macOS:**
```bash
brew install go
```

Verify installation:
```bash
go version  # Should show go1.21 or higher
```

#### 2. Install Security Tools (Optional but Recommended)

```bash
# Install Nuclei for vulnerability scanning
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install Katana for web crawling
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install httpx for HTTP probing
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install subfinder for subdomain enumeration (optional)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

#  Add Go bin to PATH if not already
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

### Building APJSON

```bash
# Clone the repository
git clone https://github.com/mohseenjamall/apjson.git
cd apjson

# Download dependencies
go mod download

# Build the binary
go build -o apjson main.go

# Or install globally
go install
```

## 📖 Usage

### Docker Usage 🐳

#### Basic Scan
```bash
docker run --rm -v $(pwd)/scan_results:/app/scan_results apjson:latest https://example.com
```

#### Full Security Scan
```bash
docker run --rm \
  -v $(pwd)/scan_results:/app/scan_results \
  apjson:latest \
  --enable-secrets \
  --enable-cors \
  --enable-injection \
  --enable-subdomains \
  --threads 16 \
  --depth 4 \
  https://target.com
```

#### Using Docker Compose
```bash
# Basic scan
docker-compose run --rm apjson https://example.com

# With all features
docker-compose run --rm apjson --enable-injection --enable-subdomains https://target.com
```

---

### Native Binary Usage

#### Basic Scan

```bash
# Scan a website
./apjson https://example.com

# With custom output directory
./apjson -o ./my_results https://example.com

# Verbose mode
./apjson -v https://example.com
```

### Advanced Options

```bash
# Full feature scan
./apjson \
  --threads 16 \
  --depth 5 \
  --enable-secrets \
  --enable-cors \
  --enable-subdomains \
  --enable-injection \
  --pdf-report \
  https://example.com

# Stealth mode (slower, less detectabale)
./apjson --stealth-mode https://example.com

# Authentication bypass testing (use with caution!)
./apjson --enable-auth-tests https://example.com
```

### Configuration File

Create `~/.apjson.yaml`:

```yaml
max_threads: 16
crawl_depth: 4
scan_timeout: 900
output_dir: "./scans"
verbose: true

# Feature toggles
enable_secrets: true
enable_cors: true
enable_subdomains: false
enable_auth_tests: false  # Requires explicit authorization
enable_injection: true
enable_ssl_scan: true
enable_waf_detect: true

# Reporting
pdf_report: true
cvss_scoring: true

# Stealth settings
stealth_mode: false
requests_per_second: 10
request_delay_ms: 100
```

Then run:
```bash
./apjson --config ~/.apjson.yaml https://example.com
```

## 📋 Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --threads` | 8 | Maximum concurrent threads |
| `-d, --depth` | 3 | Crawl depth |
| `--timeout` | 600 | Scan timeout (seconds) |
| `-o, --output` | `./scan_results` | Output directory |
| `-v, --verbose` | false | Verbose output |
| `--enable-secrets` | true | Enable secret detection |
| `--enable-cors` | true | Enable CORS testing |
| `--enable-subdomains` | false | Enable subdomain enumeration |
| `--enable-auth-tests` | false | Enable auth bypass tests |
| `--enable-injection` | true | Enable injection testing |
| `--enable-ssl-scan` | false | Enable SSL/TLS scanning |
| `--enable-waf-detect` | true | Enable WAF detection |
| `--stealth-mode` | false | Enable stealth scanning |
| `--pdf-report` | false | Generate PDF report |
| `--cvss-scoring` | true | Calculate CVSS scores |

## 📂 Output Structure

```
example.com_20231206_143022/
├── js_files/               # Downloaded JavaScript files
│   └── downloaded/
├── api_endpoints/          # Discovered API endpoints
├── reports/                # Generated reports
│   ├── report.html         # Interactive HTML report
│   ├── scan_summary.json   # Machine-readable results
│   └── report.pdf          # PDF report (if enabled)
└── screenshots/            # Visual evidence (future)
```

## 🔍 Detection Capabilities

### Secrets Detected

| Category | Examples |
|----------|----------|
| **Cloud** | AWS Access/Secret Keys, GCP API Keys, Azure Connection Strings |
| **Version Control** | GitHub PATs, GitHub Tokens, GitLab Tokens |
| **APIs** | Stripe, Twilio, SendGrid, Mailgun, Slack |
| **Databases** | MongoDB, MySQL, PostgreSQL connection strings |
| **Crypto** | RSA/DSA/EC Private Keys, PGP Keys |
| **Auth** | JWT Tokens, OAuth Tokens, API Keys |
| **High Entropy** | Unknown base64-encoded secrets |

### CORS Issues Detected

- Wildcard origin (`*`) with credentials
- Null origin bypass
- Untrusted origin reflection
- HTTP origin on HTTPS site
- Missing security headers

## ⚠️ Legal & Ethical Use

**CRITICAL:** Only use this tool on websites and applications you own or have explicit written permission to test.

- Unauthorized security testing may be **illegal** in many jurisdictions
- This tool can generate significant traffic and trigger security alerts
- Features like `--enable-auth-tests` perform aggressive testing
- Always obtain proper authorization before scanning

## 🛠️ Development

### Project Structure

```
apjson/
├── main.go                 # Entry point
├── cmd/                    # CLI commands
│   └── root.go
├── pkg/                    # Core packages
│   ├── config/             # Configuration management
│   ├── scanner/            # Main scanner orchestrator
│   ├── secrets/            # Secret detection
│   ├── cors/               # CORS testing
│   ├── report/             # Report generation
│   └── ...                 # Additional modules
└── go.mod                  # Go module file
```

### Running Tests

```bash
go test ./...
```

### Building for Multiple Platforms

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o apjson.exe

# Linux
GOOS=linux GOARCH=amd64 go build -o apjson

# macOS
GOOS=darwin GOARCH=amd64 go build -o apjson
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b new-feature`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin new-feature`
5. Submit a pull request

## 📝 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) - Nuclei, Katana, httpx, subfinder
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- [Fatih Color](https://github.com/fatih/color) - Terminal colors

## 📧 Contact

**Author:** Mohsen Jamal  
**Repository:** [github.com/mohseenjamall/apjson](https://github.com/mohseenjamall/apjson)

---

**Disclaimer:** This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this program.
