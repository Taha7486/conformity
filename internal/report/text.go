package report

import (
	"encoding/json"
	"fmt"
	"io"
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
	fmt.Fprintln(tw, "CONTROL\tSTATUS\tPASS\tFAIL\tPOLICIES")
	for _, c := range r.Controls {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", c.Key(), c.Status, c.Counts.Pass,
			c.Counts.Fail+c.Counts.Warn+c.Counts.Error, strings.Join(c.Policies, ","))
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
	for _, c := range r.Controls {
		for _, f := range c.Findings {
			fmt.Fprintf(w, "FINDING %s  %s  %s  %s\n", c.Key(), f.Policy, f.Resource, f.Result)
		}
	}
	return nil
}
