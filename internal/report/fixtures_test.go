package report

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Taha7486/conformity/internal/source"
)

// Fixtures in testdata/input were captured on 2026-10-17 from a one-node kind cluster
// (Kubernetes 1.35.8, Kyverno 1.19.1): the 17 pod policies of forge-gitops, pods created
// BEFORE the policies so that the background scan reports failures, and the three ecr-*
// image policies copied from forge-gitops (never applied on kind, so no reports).
var update = flag.Bool("update", false, "rewrite the golden files")

func load(t *testing.T, dirs ...string) *source.Snapshot {
	t.Helper()
	all := &source.Snapshot{Origin: "fixtures"}
	for _, d := range dirs {
		s, err := source.Dir{Path: filepath.Join("..", "..", "testdata", "input", d)}.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		all.Policies = append(all.Policies, s.Policies...)
		all.Reports = append(all.Reports, s.Reports...)
		all.Pods = append(all.Pods, s.Pods...)
		all.Ignored += s.Ignored
	}
	return all
}

func TestKindSnapshotGolden(t *testing.T) {
	rep, err := Evaluate(load(t, "kind-snapshot", "ecr-policies"), now, "test")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("..", "..", "testdata", "golden", "kind-snapshot.report.json")
	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, buf.Bytes()) {
		t.Error("report differs from the golden file; if the change is intended, run go test ./internal/report -update")
	}
}

// Facts about the captured data, checked directly so a wrong golden file cannot hide them.
func TestKindSnapshotFacts(t *testing.T) {
	rep, err := Evaluate(load(t, "kind-snapshot", "ecr-policies"), now, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Policies) != 20 {
		t.Errorf("policies = %d, want 20 (17 pod + 3 image)", len(rep.Policies))
	}
	ready := 0
	for _, p := range rep.Policies {
		if p.Ready {
			ready++
		}
	}
	if ready != 17 { // the 17 applied pod policies; the 3 ecr-* files were never applied
		t.Errorf("ready policies = %d, want 17", ready)
	}
	if len(rep.Unmapped) != 0 {
		t.Errorf("policies without controls: %v", rep.Unmapped)
	}
	// 12 reports x 17 policies = 204 results; kubectl showed pass+fail = 17 per report.
	if rep.Scope.Reports != 12 || rep.Scope.Results != 204 || rep.Scope.ResourcesEvaluated != 12 {
		t.Errorf("scope = %+v", rep.Scope)
	}
	// 20 failing (policy, resource) pairs: the sum of the "FAIL" column kubectl printed.
	type pr struct{ policy, resource string }
	fails := map[pr]bool{}
	for _, c := range rep.Controls {
		for _, f := range c.Findings {
			fails[pr{f.Policy, f.Resource}] = true
		}
	}
	if len(fails) != 20 {
		t.Errorf("distinct failing policy/resource pairs = %d, want 20", len(fails))
	}
	for key, want := range map[string]string{
		"CIS 5.2.2": StatusFail, "CIS 5.2.12": StatusPass, "CIS 5.4.1": StatusPass,
		"FORGE SC-1": StatusNoData, "FORGE SC-2": StatusNoData, "FORGE SC-3": StatusNoData,
	} {
		if got := statusOf(rep, key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	var priv *ControlRow
	for i := range rep.Controls {
		if rep.Controls[i].Key() == "CIS 5.2.2" {
			priv = &rep.Controls[i]
		}
	}
	if priv == nil || len(priv.Findings) != 3 {
		t.Fatalf("CIS 5.2.2 findings = %+v", priv)
	}
}

// A report with the PolicyReports removed must not look like a pass.
func TestNoReportsMeansNoData(t *testing.T) {
	s := load(t, "kind-snapshot")
	s.Reports = nil
	rep, err := Evaluate(s, now, "test")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.NoData != rep.Summary.Controls || rep.Summary.Pass != 0 {
		t.Errorf("summary = %+v", rep.Summary)
	}
}

// Dropping one report changes the counts: the tool reports what it was given.
func TestDroppingOneReportChangesTheResult(t *testing.T) {
	full, _ := Evaluate(load(t, "kind-snapshot"), now, "test")
	s := load(t, "kind-snapshot")
	var keep = s.Reports[:0]
	for _, r := range s.Reports {
		if r.GetName() != "20fca42b-6800-4051-b668-ff9f8849cd5d" { // Pod pt/fail-container
			keep = append(keep, r)
		}
	}
	s.Reports = keep
	less, err := Evaluate(s, now, "test")
	if err != nil {
		t.Fatal(err)
	}
	if less.Scope.Reports != full.Scope.Reports-1 || less.Scope.Results != full.Scope.Results-17 {
		t.Errorf("scope %+v vs %+v", less.Scope, full.Scope)
	}
	if len(findingsFor(less, "CIS 5.2.2")) != len(findingsFor(full, "CIS 5.2.2"))-1 {
		t.Error("the finding for the dropped pod must disappear")
	}
}

func findingsFor(r *Report, key string) []Finding {
	for _, c := range r.Controls {
		if c.Key() == key {
			return c.Findings
		}
	}
	return nil
}

func readFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
