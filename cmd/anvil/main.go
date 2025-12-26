// Package main provides the entry point for the anvil-go simulator.
package main

import (
	"fmt"
	"os"
)

// Version is set at build time via ldflags.
var Version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("anvil-go version %s\n", Version)
		os.Exit(0)
	}

	fmt.Println("anvil-go - StableNet Local Development Node")
	fmt.Printf("Version: %s\n", Version)
	fmt.Println()
	fmt.Println("Coming soon...")

	// TODO: Implement Phase 1
	// 1. Parse CLI flags
	// 2. Load configuration
	// 3. Initialize backend
	// 4. Start RPC server
	// 5. Wait for shutdown signal
}
