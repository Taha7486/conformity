// Command conformity turns Kyverno PolicyReports, cosign attestations and Rekor log
// entries into a control-by-control compliance report (Markdown and JSON).
package main

import (
	"fmt"
	"os"
)

const version = "0.0.0-dev"

const usage = `conformity: compliance evidence for a Forge cluster.

Usage:
  conformity version
  conformity help

Subcommands for reports are not implemented yet.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("conformity", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "conformity: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}
