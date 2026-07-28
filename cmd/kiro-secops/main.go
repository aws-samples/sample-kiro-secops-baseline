// Command kiro-secops installs and operates the Kiro DevSecOps baseline.
// Single binary, stdlib-only, cross-platform. The payload is embedded via //go:embed
// (see internal/assets). All logic lives in internal/app.
package main

import (
	"os"

	"kiro-secops/internal/app"
)

func main() { os.Exit(app.Run(os.Args[1:])) }
