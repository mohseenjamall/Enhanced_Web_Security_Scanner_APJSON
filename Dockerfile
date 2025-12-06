# Multi-stage build for optimized image size
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o apjson main.go

# Final stage - minimal image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates curl

# Install external security tools (optional)
RUN apk --no-cache add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing \
    && wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip \
    && unzip -q subfinder_2.6.3_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.3_linux_amd64.zip \
    && chmod +x /usr/local/bin/subfinder

# Create non-root user
RUN addgroup -g 1000 apjson && \
    adduser -D -u 1000 -G apjson apjson

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/apjson .

# Create output directory
RUN mkdir -p /app/scan_results && \
    chown -R apjson:apjson /app

# Switch to non-root user
USER apjson

# Set environment variables
ENV OUTPUT_DIR=/app/scan_results

# Expose port (if needed for future web interface)
# EXPOSE 8080

# Volume for scan results
VOLUME ["/app/scan_results"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /app/apjson --help || exit 1

# Entry point
ENTRYPOINT ["/app/apjson"]

# Default command (show help)
CMD ["--help"]
