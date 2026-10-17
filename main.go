// Command conformity turns Kyverno PolicyReports, cosign attestations and Rekor log
// entries into a control-by-control compliance report (Markdown and JSON).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Taha7486/conformity/internal/report"
	"github.com/Taha7486/conformity/internal/source"
	"github.com/Taha7486/conformity/internal/supply"
)

const version = "0.1.0-dev"

const usage = `conformity: compliance evidence for a Forge cluster.

Usage:
  conformity report [flags]   build the report
  conformity version
  conformity help

Flags of report:
  --dir PATH         read saved policies and PolicyReports (YAML or JSON) from PATH
                     instead of a cluster
  --kubeconfig FILE  kubeconfig to use (default: KUBECONFIG, then ~/.kube/config)
  --context NAME     kubeconfig context (default: the current one)
  --skip-images      do not run cosign; the report rests on the PolicyReports alone
  --cosign PATH      cosign binary (default: cosign from PATH)
  --cosign-timeout D time limit for one cosign call (default 90s)
  --retries N        repeat a cosign call that ended in an error (network, TUF) N times
                     (default 1); a FAIL is never repeated
  --max-scan-age D   oldest vulnerability scan that still counts as fresh (default 720h,
                     the window of the ecr-vuln policy)
  --format text|json|md  output on stdout (default text)
  --out DIR          also write report.md and report.json into DIR
  --strict           exit with code 3 when any control is FAIL (default: exit 0)
  --now TIME         RFC 3339 time to stamp the report with (default: the clock)
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
	case "report":
		if err := runReport(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "conformity:", err)
			if errors.Is(err, errStrict) {
				os.Exit(3)
			}
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "conformity: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	dir := fs.String("dir", "", "")
	kubeconfig := fs.String("kubeconfig", "", "")
	kctx := fs.String("context", "", "")
	format := fs.String("format", "text", "")
	out := fs.String("out", "", "")
	nowFlag := fs.String("now", "", "")
	skipImages := fs.Bool("skip-images", false, "")
	cosignPath := fs.String("cosign", "cosign", "")
	cosignTimeout := fs.Duration("cosign-timeout", 90*time.Second, "")
	maxScanAge := fs.Duration("max-scan-age", 720*time.Hour, "")
	retries := fs.Int("retries", 1, "")
	strict := fs.Bool("strict", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *format != "text" && *format != "json" && *format != "md" {
		return fmt.Errorf("--format must be text, json or md, got %q", *format)
	}
	if *dir != "" && (*kubeconfig != "" || *kctx != "") {
		return fmt.Errorf("--dir cannot be combined with --kubeconfig or --context")
	}
	now := time.Now().UTC()
	if *nowFlag != "" {
		t, err := time.Parse(time.RFC3339, *nowFlag)
		if err != nil {
			return fmt.Errorf("--now: %w", err)
		}
		now = t
	}

	var src source.Source = source.Cluster{Kubeconfig: *kubeconfig, Context: *kctx, Pods: !*skipImages}
	if *dir != "" {
		src = source.Dir{Path: *dir}
	}
	snap, err := src.Load(context.Background())
	if err != nil {
		return err
	}
	opt := report.Options{Now: now, Tool: "conformity " + version, MaxScanAge: *maxScanAge, Retries: *retries, RetryDelay: 3 * time.Second,
		Progress: func(msg string) { fmt.Fprintln(os.Stderr, "conformity:", msg) }}
	if !*skipImages {
		opt.Cosign = supply.Exec{Path: *cosignPath, Timeout: *cosignTimeout}
	}
	rep, err := report.EvaluateWith(context.Background(), snap, opt)
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.MkdirAll(*out, 0o755); err != nil {
			return err
		}
		for name, write := range map[string]func(*os.File) error{
			"report.json": func(f *os.File) error { return report.WriteJSON(f, rep) },
			"report.md":   func(f *os.File) error { return report.WriteMarkdown(f, rep) },
		} {
			f, err := os.Create(filepath.Join(*out, name))
			if err != nil {
				return err
			}
			if err := write(f); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
	var err2 error
	switch *format {
	case "json":
		err2 = report.WriteJSON(os.Stdout, rep)
	case "md":
		err2 = report.WriteMarkdown(os.Stdout, rep)
	default:
		err2 = report.WriteText(os.Stdout, rep)
	}
	if err2 != nil {
		return err2
	}
	if *strict && rep.Summary.Fail > 0 {
		return errStrict
	}
	return nil
}

// errStrict makes main exit with code 3: the report was made, and at least one control is FAIL.
var errStrict = fmt.Errorf("%w", errors.New("at least one control is FAIL (--strict)"))
