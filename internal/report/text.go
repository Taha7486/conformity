package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a plain table for reading in a terminal. The Markdown report comes later.
func WriteText(w io.Writer, r *Report) error {
	fmt.Fprintf(w, "conformity report, %s\nsource: %s\n\n", r.GeneratedAt, r.Source)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTROL\tSTATUS\tPASS\tFAIL\tIMAGES ok/bad\tPOLICIES")
	for _, c := range r.Controls {
		img := "-"
		if c.ImageChecks != nil {
			img = fmt.Sprintf("%d/%d", c.ImageChecks.Pass, c.ImageChecks.Fail+c.ImageChecks.Error)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n", c.Key(), c.Status, c.Counts.Pass,
			c.Counts.Fail+c.Counts.Warn+c.Counts.Error, img, strings.Join(c.Policies, ","))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	s := r.Summary
	fmt.Fprintf(w, "\n%d controls: %d pass, %d fail, %d skipped, %d no data\n", s.Controls, s.Pass, s.Fail, s.Skipped, s.NoData)
	fmt.Fprintf(w, "%d results from %d reports over %d resources", r.Scope.Results, r.Scope.Reports, r.Scope.ResourcesEvaluated)
	if r.Scope.OldestResult != "" {
		fmt.Fprintf(w, " (%s to %s)", r.Scope.OldestResult, r.Scope.NewestResult)
	}
	fmt.Fprintln(w)
	if len(r.Unmapped) > 0 {
		fmt.Fprintf(w, "policies without %s: %s\n", "forge.dev/controls", strings.Join(r.Unmapped, ", "))
	}
	if r.Scope.ImagesFound > 0 || len(r.Images) > 0 {
		fmt.Fprintf(w, "\n%d images in use, %d checked with %s (vulnerability scans fresh within %s)\n",
			r.Scope.ImagesFound, r.Scope.ImagesChecked, r.Cosign, r.Scope.MaxScanAge)
		for _, im := range r.Images {
			fmt.Fprintf(w, "IMAGE %s  used by %s\n", im.Ref, strings.Join(im.UsedBy, ", "))
			for _, c := range im.Checks {
				fmt.Fprintf(w, "  %-10s %-9s %s", c.Control, c.Kind, c.Status)
				if c.Detail != "" {
					fmt.Fprintf(w, "  (%s)", c.Detail)
				}
				for _, a := range c.Attestations {
					if a.Rekor != nil {
						fmt.Fprintf(w, "  rekor %s", a.Rekor.LogIndex)
					}
				}
				fmt.Fprintln(w)
			}
		}
	}
	for _, d := range r.Disagreements {
		var cs []string
		for k, v := range d.Conformity {
			cs = append(cs, k+" "+v)
		}
		sort.Strings(cs)
		fmt.Fprintf(w, "DISAGREEMENT %s  %s: Kyverno %s (%s); conformity %s\n", d.Policy, d.Resource, d.Kyverno, d.KyvernoMessage, strings.Join(cs, ", "))
	}
	noted := false
	for _, c := range r.Controls {
		if c.Note != "" && !noted {
			fmt.Fprintf(w, "NOTE %s\n", c.Note)
			noted = true
		}
	}
	for _, c := range r.Controls {
		for _, f := range c.Findings {
			fmt.Fprintf(w, "FINDING %s  %s  %s  %s\n", c.Key(), f.Policy, f.Resource, f.Result)
		}
	}
	return nil
}
