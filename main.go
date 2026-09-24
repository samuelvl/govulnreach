package main

import (
	"fmt"
	"os"

	"github.com/samuelvl/govulnreach/cmd"
)

func main() {
	if err := cmd.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "govulnreach failed: %v\n", err)
		os.Exit(1)
	}
}
