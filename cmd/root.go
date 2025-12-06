package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/mohseenjamall/apjson/pkg/config"
	"github.com/mohseenjamall/apjson/pkg/scanner"
)

var (
	cfgFile string
	cfg     *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "apjson [URL]",
	Short: "Enhanced Web Security Scanner",
	Long: `A comprehensive penetration testing tool for web application security assessment.
Features include: secret detection, CORS testing, subdomain enumeration, vulnerability scanning, and more.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runScan,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.apjson.yaml)")
	rootCmd.PersistentFlags().IntP("threads", "t", 8, "Maximum number of concurrent threads")
	rootCmd.PersistentFlags().IntP("depth", "d", 3, "Crawl depth")
	rootCmd.PersistentFlags().IntP("timeout", "", 600, "Scan timeout in seconds")
	rootCmd.PersistentFlags().StringP("output", "o", "./scan_results", "Output directory")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
	
	// Feature flags
	rootCmd.PersistentFlags().Bool("enable-secrets", true, "Enable secret detection")
	rootCmd.PersistentFlags().Bool("enable-cors", true, "Enable CORS testing")
	rootCmd.PersistentFlags().Bool("enable-subdomains", false, "Enable subdomain enumeration")
	rootCmd.PersistentFlags().Bool("enable-auth-tests", false, "Enable authentication bypass testing")
	rootCmd.PersistentFlags().Bool("enable-injection", true, "Enable injection testing")
	rootCmd.PersistentFlags().Bool("enable-ssl-scan", false, "Enable SSL/TLS scanning")
	rootCmd.PersistentFlags().Bool("enable-waf-detect", true, "Enable WAF detection")
	rootCmd.PersistentFlags().Bool("enable-graphql", true, "Enable GraphQL testing")
	rootCmd.PersistentFlags().Bool("stealth-mode", false, "Enable stealth mode with rate limiting")
	
	// Reporting flags
	rootCmd.PersistentFlags().Bool("pdf-report", false, "Generate PDF report")
	rootCmd.PersistentFlags().Bool("cvss-scoring", true, "Calculate CVSS scores")
}

func initConfig() {
	cfg = config.NewConfig()
	
	if cfgFile != "" {
		cfg.ConfigFile = cfgFile
		if err := cfg.LoadFromFile(cfgFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
	}
	
	// Override config with command-line flags
	if err := cfg.LoadFromFlags(rootCmd); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading flags: %v\n", err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	targetURL := args[0]
	
	// Create scanner instance
	s, err := scanner.New(cfg, targetURL)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}
	
	// Run the scan
	return s.Execute()
}
