package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Taha7486/conformity/internal/catalog"
)

// MaxFindingsPerControl caps the findings table of one control in the Markdown report; the
// JSON report always has them all.
const MaxFindingsPerControl = 20

// esc makes untrusted text (pod names, Kyverno messages, cosign errors) safe inside a
// Markdown table cell or line: no table breaks, links, emphasis, code spans or HTML.
func esc(s string) string {
	s = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\t", " ").Replace(s)
	return strings.NewReplacer(
		"\\", "\\\\", "|", "\\|", "`", "\\`", "<", "&lt;", ">", "&gt;", "&", "&amp;",
		"[", "\\[", "]", "\\]", "*", "\\*", "_", "\\_", "~", "\\~",
	).Replace(s)
}

// code puts text in a code span; backticks cannot be escaped inside one, so they are replaced.
func code(s string) string {
	s = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\t", " ", "`", "'", "|", "\\|").Replace(s)
	return "`" + s + "`"
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

// WriteMarkdown writes the report for a human reader. Everything in it is also in the JSON.
func WriteMarkdown(w io.Writer, r *Report) error {
	var b strings.Builder
	p := func(f string, a ...interface{}) { fmt.Fprintf(&b, f, a...) }

	p("# Compliance report\n\n")
	p("- Generated: %s\n- Source: %s\n- Tool: %s", esc(r.GeneratedAt), esc(r.Source), esc(r.Tool))
	if r.Cosign != "" {
		p(", cosign %s", esc(r.Cosign))
	}
	p("\n- Report format: schema %s (`report.json` holds the same data and every finding)\n\n", esc(r.SchemaVersion))

	s := r.Summary
	p("## Summary\n\n")
	switch {
	case s.Fail > 0:
		p("**Overall: FAIL.** %d of %d controls fail.\n\n", s.Fail, s.Controls)
	case s.Controls == 0:
		p("**Overall: NO DATA.** No policy carries a control annotation.\n\n")
	case s.NoData > 0 || s.Skipped > 0:
		p("**Overall: no failing control**, but %d have no data or were skipped.\n\n", s.NoData+s.Skipped)
	default:
		p("**Overall: PASS.** All %d controls pass.\n\n", s.Controls)
	}
	p("| PASS | FAIL | SKIPPED | NO DATA | Controls |\n|---|---|---|---|---|\n| %d | %d | %d | %d | %d |\n\n", s.Pass, s.Fail, s.Skipped, s.NoData, s.Controls)
	p("How to read a status: a control is **FAIL** if any result of its policies is fail, warn or error (a check that warned or could not run is not a pass), or if an image check on it failed or could not be done; **PASS** if it has at least one passing result and none of those; **SKIPPED** if every result was skipped; **NO DATA** if there is no result at all (no resource in scope, or no report yet).\n\n")

	for _, fw := range []string{catalog.CIS, catalog.PSS, catalog.FORGE} {
		var rows []ControlRow
		for _, c := range r.Controls {
			if c.Framework == fw {
				rows = append(rows, c)
			}
		}
		if len(rows) == 0 {
			continue
		}
		p("## Controls: %s\n\n", frameworkTitle(fw))
		p("| Control | Status | Kyverno results (pass / not pass) | Image checks (pass / not pass) | Policies |\n|---|---|---|---|---|\n")
		for _, c := range rows {
			img := "-"
			if c.ImageChecks != nil {
				img = fmt.Sprintf("%d / %d", c.ImageChecks.Pass, c.ImageChecks.Fail+c.ImageChecks.Error)
			}
			name := c.ID
			if c.Title != "" && fw == catalog.FORGE {
				name = c.ID + " " + c.Title
			}
			p("| %s | **%s** | %d / %d | %s | %s |\n", esc(name), c.Status, c.Counts.Pass,
				c.Counts.Fail+c.Counts.Warn+c.Counts.Error, img, esc(strings.Join(c.Policies, ", ")))
		}
		p("\n")
	}

	any := false
	for _, c := range r.Controls {
		if len(c.Findings) == 0 {
			continue
		}
		if !any {
			p("## Findings\n\nEvery result that kept a control from passing. A Deployment and its Pod each have a report, and a policy that enforces several controls counts under each of them, so one cause can appear more than once.\n\n")
			any = true
		}
		p("### %s\n\n| Policy | Resource | Result | Message |\n|---|---|---|---|\n", esc(c.Key()))
		for i, f := range c.Findings {
			if i == MaxFindingsPerControl {
				p("\n%d more in `report.json`.\n", len(c.Findings)-i)
				break
			}
			p("| %s | %s | %s | %s |\n", esc(f.Policy), esc(f.Resource), esc(f.Result), esc(truncate(f.Message, 200)))
		}
		p("\n")
	}

	if len(r.Images) > 0 || r.Scope.ImagesFound > 0 {
		p("## Image evidence\n\n")
		p("%d images in use; %d fall under an image policy and were checked again with cosign (vulnerability scans must be at most %s old). cosign verified signatures, attestations and the Rekor log entries; conformity read the certificate and log entry out of the bundles attached to each image.\n\n",
			r.Scope.ImagesFound, r.Scope.ImagesChecked, esc(r.Scope.MaxScanAge))
		for _, im := range r.Images {
			p("### %s\n\n", code(im.Ref))
			pin := "The digest was not known, so the tag was resolved when the report was made."
			if im.Pinned {
				pin = "The digest is known (pod spec or runtime)."
			}
			p("Used by: %s. %s\n\n", esc(strings.Join(im.UsedBy, ", ")), pin)
			if im.BundleError != "" {
				p("Bundles could not be downloaded, so there is no certificate or Rekor evidence below: %s\n\n", esc(truncate(im.BundleError, 200)))
			}
			for _, c := range im.Checks {
				p("- **%s** (%s): **%s**", esc(c.Control), esc(c.Kind), c.Status)
				if c.Detail != "" {
					p(" - %s", esc(truncate(c.Detail, 300)))
				}
				p("\n")
				for _, a := range c.Attestations {
					p("  - %s", code(a.PredicateType))
					if a.ScanFinishedOn != "" {
						p(", scan finished %s", esc(a.ScanFinishedOn))
					}
					if a.Signer != nil {
						p(", signer %s", code(a.Signer.Subject))
					}
					if a.Rekor != nil {
						p(", Rekor log index %s", esc(a.Rekor.LogIndex))
						if a.Rekor.IntegratedTime != "" {
							p(" logged %s", esc(a.Rekor.IntegratedTime))
						}
						if a.Rekor.ProofMatchesCheckpoint != nil && !*a.Rekor.ProofMatchesCheckpoint {
							p(" (proof fields differ from the signed checkpoint)")
						}
					} else {
						p(", no Rekor evidence found")
					}
					p("\n")
				}
				if c.NewestScanAge != "" {
					p("  - newest verified scan is %s old (limit %s)\n", esc(c.NewestScanAge), esc(c.MaxScanAge))
				}
			}
			p("\n")
		}
	}

	if len(r.Disagreements) > 0 {
		p("## Disagreements between Kyverno and conformity\n\nKyverno writes one result per policy and pod. These pods got a different answer from conformity's own check of the same policy.\n\n")
		p("| Policy | Pod | Image | Kyverno | Kyverno message | conformity |\n|---|---|---|---|---|---|\n")
		for _, d := range r.Disagreements {
			var cs []string
			for k, v := range d.Conformity {
				cs = append(cs, k+" "+v)
			}
			sort.Strings(cs)
			p("| %s | %s | %s | %s | %s | %s |\n", esc(d.Policy), esc(d.Resource), code(d.Image), esc(d.Kyverno),
				esc(truncate(d.KyvernoMessage, 200)), esc(strings.Join(cs, ", ")))
		}
		p("\n")
	}

	p("## Scope and limits\n\n")
	sc := r.Scope
	p("- %d PolicyReports, %d results, %d resources", sc.Reports, sc.Results, sc.ResourcesEvaluated)
	if sc.OldestResult != "" {
		p("; results written between %s and %s", esc(sc.OldestResult), esc(sc.NewestResult))
		if gen, err := time.Parse(time.RFC3339, r.GeneratedAt); err == nil {
			if newest, err := time.Parse(time.RFC3339, sc.NewestResult); err == nil {
				p(" (newest is %s older than this report)", gen.Sub(newest).Round(time.Minute))
			}
		}
	}
	p("\n")
	if sc.ResultsNoPolicy > 0 {
		p("- %d results belong to policies without a control annotation and are not part of any control.\n", sc.ResultsNoPolicy)
	}
	if len(r.Unmapped) > 0 {
		p("- Policies without a `forge.dev/controls` annotation: %s.\n", esc(strings.Join(r.Unmapped, ", ")))
	}
	for _, g := range r.Gaps {
		p("- %s\n", esc(g))
	}
	p("\n### Policies\n\n| Policy | Kind | Ready | Actions | Controls |\n|---|---|---|---|---|\n")
	groups := map[string][]string{}
	for _, pol := range r.Policies {
		ready := "no"
		if pol.Ready {
			ready = "yes"
		}
		p("| %s | %s | %s | %s | %s |\n", esc(pol.Name), esc(pol.Kind), ready, esc(strings.Join(pol.Actions, ", ")), esc(strings.Join(pol.Controls, "; ")))
		if len(pol.ExcludedNamespaces) > 0 {
			k := strings.Join(pol.ExcludedNamespaces, ", ")
			groups[k] = append(groups[k], pol.Name)
		}
	}
	if len(groups) > 0 {
		p("\nNamespaces a policy leaves out:\n\n")
		var keys []string
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p("- %s: %d policies (%s)\n", esc(k), len(groups[k]), esc(strings.Join(groups[k], ", ")))
		}
	}

	p("\n### Inputs\n\n%d documents were read. SHA-256 over the sorted list (kind, namespace/name, SHA-256 of each document with managedFields left out): %s. The list is in `report.json`.\n", len(r.Inputs), code(r.InputsSHA256))

	_, err := io.WriteString(w, b.String())
	return err
}

func frameworkTitle(fw string) string {
	switch fw {
	case catalog.CIS:
		return "CIS Kubernetes Benchmark (numbering of v1.9)"
	case catalog.PSS:
		return "Pod Security Standards"
	default:
		return "Forge supply-chain controls"
	}
}
