package main

import (
	"fmt"
	"os"

	"github.com/mohseenjamall/apjson/cmd"
)

const (
	version = "3.0.0"
	banner  = `
╔═══════════════════════════════════════════════╗
║   Enhanced Web Security Scanner v%s        ║
║   Advanced Penetration Testing Tool          ║
╚═══════════════════════════════════════════════╝
`
)

func main() {
	fmt.Printf(banner, version)
	
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
