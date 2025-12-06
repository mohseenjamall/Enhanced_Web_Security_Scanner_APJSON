# Docker Usage Guide

## 🐳 Quick Start

### Build the Image
```bash
docker build -t apjson:latest .
```

### Run a Scan
```bash
docker run --rm -v $(pwd)/scan_results:/app/scan_results apjson:latest https://example.com
```

---

## 📦 Docker Compose

### Basic Usage
```bash
# Run scan
docker-compose run --rm apjson https://example.com

# With options
docker-compose run --rm apjson --enable-secrets --enable-cors https://target.com
```

### Full Scan Example
```bash
docker-compose run --rm apjson \
  --enable-secrets \
  --enable-cors \
  --enable-injection \
  --enable-subdomains \
  --threads 12 \
  --depth 3 \
  https://target.com
```

---

## 🛠️ Advanced Usage

### Custom Configuration
```bash
# Create config file
mkdir -p config
cat > config/scan.yaml <<EOF
target_url: https://example.com
enable_secrets: true
enable_cors: true
threads: 16
depth: 4
EOF

# Run with config
docker run --rm \
  -v $(pwd)/scan_results:/app/scan_results \
  -v $(pwd)/config:/app/config:ro \
  apjson:latest --config /app/config/scan.yaml
```

### Interactive Shell
```bash
docker run --rm -it --entrypoint /bin/sh apjson:latest
```

### View Scan Results
```bash
# Results are in ./scan_results
ls -la scan_results/

# View JSON report
cat scan_results/*/reports/scan_summary.json | jq
```

---

## 🔐 Security Best Practices

### Run as Non-Root
✅ Already configured in Dockerfile (user: apjson)

### Read-Only Filesystem
```bash
docker run --rm --read-only \
  -v $(pwd)/scan_results:/app/scan_results \
  apjson:latest https://example.com
```

### Network Isolation
```bash
docker run --rm --network=none \
  -v $(pwd)/scan_results:/app/scan_results \
  apjson:latest https://example.com
```

---

## 📊 Resource Limits

### CPU and Memory
```bash
docker run --rm \
  --cpus="2.0" \
  --memory="1g" \
  -v $(pwd)/scan_results:/app/scan_results \
  apjson:latest https://example.com
```

---

## 🚀 CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    docker run --rm \
      -v ${{ github.workspace }}/results:/app/scan_results \
      apjson:latest ${{ secrets.TARGET_URL }}
```

### GitLab CI
```yaml
security_scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t apjson .
    - docker run --rm -v $(pwd)/results:/app/scan_results apjson $TARGET_URL
  artifacts:
    paths:
      - results/
```

---

## 🏗️ Building for Production

### Multi-Platform Build
```bash
docker buildx build --platform linux/amd64,linux/arm64 -t apjson:latest .
```

### Push to Registry
```bash
# Tag
docker tag apjson:latest mohseenjamall/apjson:latest
docker tag apjson:latest mohseenjamall/apjson:v1.0.0

# Push
docker push mohseenjamall/apjson:latest
docker push mohseenjamall/apjson:v1.0.0
```

### Pull from Registry
```bash
docker pull mohseenjamall/apjson:latest
```

---

## 🔍 Troubleshooting

### Check Image Size
```bash
docker images apjson:latest
```

### Inspect Container
```bash
docker run --rm apjson:latest --version
docker run --rm apjson:latest --help
```

### View Logs
```bash
docker logs apjson-scanner
```

### Clean Up
```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune

# Remove everything
docker system prune -a
```

---

## 📝 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OUTPUT_DIR` | `/app/scan_results` | Scan results directory |
| `THREADS` | `8` | Number of threads |
| `DEPTH` | `3` | Crawl depth |
| `TIMEOUT` | `600` | Scan timeout (seconds) |

---

## 🎯 Examples

### Example 1: Quick Scan
```bash
docker run --rm -v ./results:/app/scan_results apjson:latest https://example.com
```

### Example 2: Full Pentest
```bash
docker run --rm \
  -v ./results:/app/scan_results \
  apjson:latest \
  --enable-secrets \
  --enable-cors \
  --enable-injection \
  --enable-subdomains \
  --threads 16 \
  --depth 4 \
  --verbose \
  https://target.com
```

### Example 3: Subdomain Only
```bash
docker run --rm \
  -v ./results:/app/scan_results \
  apjson:latest \
  --enable-subdomains \
  https://example.com
```

---

## ⚠️ Legal Notice

**IMPORTANT:** Only scan targets you own or have explicit permission to test. Unauthorized security testing is illegal.

---

## 📚 Additional Resources

- **Main README:** [README.md](README.md)
- **Installation Guide:** [INSTALL.md](INSTALL.md)
- **Testing Results:** [TESTING_RESULTS.md](TESTING_RESULTS.md)
