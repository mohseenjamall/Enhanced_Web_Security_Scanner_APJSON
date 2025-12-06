# Installation Guide

## Quick Start (Windows)

### 1. Install Go

Open PowerShell as Administrator and run:

```powershell
# Install Go using winget
winget install GoLang.Go

# Verify installation
go version
```

If the command is not found, restart your terminal or add Go to PATH:

```powershell
# Add to PATH (replace with your Go installation path if different)
$env:Path += ";C:\Program Files\Go\bin"
[Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::User)
```

### 2. Install Security Tools

```powershell
# Install required tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Optional: Subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Add Go bin directory to PATH
$GOPATH = go env GOPATH
$env:Path += ";$GOPATH\bin"
[Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::User)
```

### 3. Build APJSON

```powershell
# Navigate to project directory
cd d:\MCP&Claude\APJS

# Download dependencies
go mod download

# Build the scanner
go build -o apjson.exe main.go

# Test it
.\apjson.exe --help
```

## Alternative: Direct Binary Download (Coming Soon)

Pre-compiled binaries will be available from the GitHub releases page:
- Windows (64-bit)
- Linux (64-bit)
- macOS (64-bit)

## Troubleshooting

### "go: command not found"

**Solution:** Go is not in your PATH. Restart your terminal or manually add it:

```powershell
[Environment]::SetEnvironmentVariable("Path", "$env:Path;C:\Program Files\Go\bin", [EnvironmentVariableTarget]::User)
```

### "cannot find package"

**Solution:** Run `go mod download` to fetch dependencies.

### Permission Errors

**Solution:** Run PowerShell as Administrator when installing tools.

### Tools Not Found After Installation

**Solution:** Add Go's bin directory to PATH:

```powershell
$GOPATH = go env GOPATH
[Environment]::SetEnvironmentVariable("Path", "$env:Path;$GOPATH\bin", [EnvironmentVariableTarget]::User)
```

Then restart your terminal.

## Next Steps

Once installed, try your first scan:

```powershell
# Basic scan
.\apjson.exe https://example.com

# With all features
.\apjson.exe --enable-secrets --enable-cors --enable-injection -v https://example.com
```

See [README.md](README.md) for full usage instructions.
