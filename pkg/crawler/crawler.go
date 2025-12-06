package crawler

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mohseenjamall/apjson/pkg/config"
)

// Crawler handles web crawling and file discovery
type Crawler struct {
	config    *config.Config
	targetURL string
	outputDir string
	client    *http.Client
}

// CrawlResults contains discovered URLs and files
type CrawlResults struct {
	AllURLs      []string
	JSFiles      []string
	JSONFiles    []string
	APIEndpoints []string
	ParamURLs    []string
}

// NewCrawler creates a new crawler instance
func NewCrawler(cfg *config.Config, targetURL, outputDir string) *Crawler {
	return &Crawler{
		config:    cfg,
		targetURL: targetURL,
		outputDir: outputDir,
		client: &http.Client{
			Timeout: time.Duration(cfg.DownloadTimeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Crawl performs web crawling using Katana if available, otherwise fallback
func (c *Crawler) Crawl() (*CrawlResults, error) {
	// Try using Katana first
	if c.isKatanaAvailable() {
		return c.crawlWithKatana()
	}

	// Fallback to simple crawling
	return c.crawlWithSimpleMethod()
}

// isKatanaAvailable checks if Katana is installed
func (c *Crawler) isKatanaAvailable() bool {
	cmd := exec.Command("katana", "-version")
	err := cmd.Run()
	return err == nil
}

// crawlWithKatana uses Katana for comprehensive crawling
func (c *Crawler) crawlWithKatana() (*CrawlResults, error) {
	results := &CrawlResults{
		AllURLs:      make([]string, 0),
		JSFiles:      make([]string, 0),
		JSONFiles:    make([]string, 0),
		APIEndpoints: make([]string, 0),
		ParamURLs:    make([]string, 0),
	}

	tempFile := filepath.Join(c.outputDir, "katana_output.txt")
	
	// Build Katana command
	args := []string{
		"-u", c.targetURL,
		"-d", fmt.Sprintf("%d", c.config.CrawlDepth),
		"-c", fmt.Sprintf("%d", c.config.MaxThreads),
		"-jc",    // JavaScript crawling
		"-silent",
		"-o", tempFile,
	}

	// Execute Katana
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.ScanTimeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "katana", args...)
	
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("katana execution failed: %w", err)
	}

	// Read results
	file, err := os.Open(tempFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open katana output: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urlStr := strings.TrimSpace(scanner.Text())
		if urlStr == "" {
			continue
		}
		
		results.AllURLs = append(results.AllURLs, urlStr)
		c.categorizeURL(urlStr, results)
	}

	return results, nil
}

// crawlWithSimpleMethod fallback crawler using HTTP client
func (c *Crawler) crawlWithSimpleMethod() (*CrawlResults, error) {
	results := &CrawlResults{
		AllURLs:      make([]string, 0),
		JSFiles:      make([]string, 0),
		JSONFiles:    make([]string, 0),
		APIEndpoints: make([]string, 0),
		ParamURLs:    make([]string, 0),
	}

	visited := make(map[string]bool)
	queue := []string{c.targetURL}
	depth := 0

	for len(queue) > 0 && depth < c.config.CrawlDepth {
		currentURL := queue[0]
		queue = queue[1:]

		if visited[currentURL] {
			continue
		}
		visited[currentURL] = true
		results.AllURLs = append(results.AllURLs, currentURL)

		// Categorize URL
		c.categorizeURL(currentURL, results)

		// Fetch and extract links (simplified)
		links := c.extractLinks(currentURL)
		for _, link := range links {
			absURL := c.makeAbsolute(currentURL, link)
			if absURL != "" && !visited[absURL] {
				queue = append(queue, absURL)
			}
		}

		depth++
	}

	return results, nil
}

// categorizeURL categorizes URL into appropriate lists
func (c *Crawler) categorizeURL(urlStr string, results *CrawlResults) {
	// Check for JS files
	if strings.HasSuffix(urlStr, ".js") || strings.Contains(urlStr, ".js?") {
		results.JSFiles = append(results.JSFiles, urlStr)
	}

	// Check for JSON files
	if strings.HasSuffix(urlStr, ".json") || strings.Contains(urlStr, ".json?") {
		results.JSONFiles = append(results.JSONFiles, urlStr)
	}

	// Check for API endpoints
	apiPatterns := []string{
		"/api/", "/v1/", "/v2/", "/v3/", "/rest/", 
		"/graphql", "/swagger", "/endpoint", "/service",
	}
	lowerURL := strings.ToLower(urlStr)
	for _, pattern := range apiPatterns {
		if strings.Contains(lowerURL, pattern) {
			results.APIEndpoints = append(results.APIEndpoints, urlStr)
			break
		}
	}

	// Check for parameterized URLs
	if strings.Contains(urlStr, "?") && strings.Contains(urlStr, "=") {
		results.ParamURLs = append(results.ParamURLs, urlStr)
	}
}

// extractLinks extracts links from HTML content
func (c *Crawler) extractLinks(urlStr string) []string {
	links := make([]string, 0)

	resp, err := c.client.Get(urlStr)
	if err != nil {
		return links
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return links
	}

	// Simple regex-based link extraction
	linkRegex := regexp.MustCompile(`href=["']([^"']+)["']`)
	scriptRegex := regexp.MustCompile(`src=["']([^"']+\.js[^"']*)["']`)
	
	// Extract href links
	matches := linkRegex.FindAllStringSubmatch(string(body), -1)
	for _, match := range matches {
		if len(match) > 1 {
			links = append(links, match[1])
		}
	}

	// Extract script src
	matches = scriptRegex.FindAllStringSubmatch(string(body), -1)
	for _, match := range matches {
		if len(match) > 1 {
			links = append(links, match[1])
		}
	}

	return links
}

// makeAbsolute converts relative URL to absolute
func (c *Crawler) makeAbsolute(baseURL, relativeURL string) string {
	if strings.HasPrefix(relativeURL, "http://") || strings.HasPrefix(relativeURL, "https://") {
		return relativeURL
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	rel, err := url.Parse(relativeURL)
	if err != nil {
		return ""
	}

	return base.ResolveReference(rel).String()
}

// DownloadFiles downloads JS and JSON files
func (c *Crawler) DownloadFiles(jsFiles, jsonFiles []string, downloadDir string) (int, error) {
	totalFiles := len(jsFiles) + len(jsonFiles)
	if totalFiles == 0 {
		return 0, nil
	}

	// Create download directory
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return 0, fmt.Errorf("failed to create download directory: %w", err)
	}

	downloaded := 0
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore for limiting concurrent downloads
	sem := make(chan struct{}, c.config.MaxThreads)

	// Download function
	downloadFile := func(fileURL, ext string) {
		defer wg.Done()
		sem <- struct{}{}        // Acquire
		defer func() { <-sem }() // Release

		// Create safe filename
		hash := fmt.Sprintf("%x", time.Now().UnixNano())
		filename := filepath.Join(downloadDir, hash+ext)

		// Download with timeout
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.DownloadTimeout)*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
		if err != nil {
			return
		}

		req.Header.Set("User-Agent", c.config.UserAgent)

		resp, err := c.client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return
		}

		// Write to file
		out, err := os.Create(filename)
		if err != nil {
			return
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			os.Remove(filename)
			return
		}

		mu.Lock()
		downloaded++
		mu.Unlock()
	}

	// Download JS files
	for _, jsURL := range jsFiles {
		wg.Add(1)
		go downloadFile(jsURL, ".js")
	}

	// Download JSON files
	for _, jsonURL := range jsonFiles {
		wg.Add(1)
		go downloadFile(jsonURL, ".json")
	}

	wg.Wait()

	return downloaded, nil
}
