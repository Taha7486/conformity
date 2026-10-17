package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run calls runReport with stdout silenced and returns what it wrote.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old }()
	runErr := runReport(args)
	f.Close()
	b, _ := os.ReadFile(f.Name())
	return string(b), runErr
}

const failing = "testdata/input/kind-snapshot"

func passingDir(t *testing.T) string {
	d := t.TempDir()
	must := func(name, body string) {
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("policy.yaml", "apiVersion: policies.kyverno.io/v1\nkind: ValidatingPolicy\nmetadata:\n  name: p\n  annotations:\n    forge.dev/controls: \"CIS 1.1\"\nspec: {}\n")
	must("report.yaml", "apiVersion: wgpolicyk8s.io/v1alpha2\nkind: PolicyReport\nmetadata: {name: r, namespace: ns}\nscope: {kind: Pod, name: a, namespace: ns, uid: u}\nresults:\n- {policy: p, rule: r, result: pass, timestamp: {seconds: 1760000000}}\n")
	return d
}

func TestStrictExitsOnlyWhenAControlFails(t *testing.T) {
	if _, err := run(t, "--dir", failing, "--skip-images"); err != nil {
		t.Errorf("without --strict a failing report is still success: %v", err)
	}
	if _, err := run(t, "--dir", failing, "--skip-images", "--strict"); !errors.Is(err, errStrict) {
		t.Errorf("--strict with failing controls: err = %v", err)
	}
	if _, err := run(t, "--dir", passingDir(t), "--skip-images", "--strict"); err != nil {
		t.Errorf("--strict with only passing controls: %v", err)
	}
}

func TestFormats(t *testing.T) {
	md, err := run(t, "--dir", failing, "--skip-images", "--format", "md", "--now", "2026-10-17T12:00:00Z")
	if err != nil || !strings.HasPrefix(md, "# Compliance report") {
		t.Errorf("md: %v %.40q", err, md)
	}
	js, err := run(t, "--dir", failing, "--skip-images", "--format", "json", "--now", "2026-10-17T12:00:00Z")
	if err != nil || !strings.HasPrefix(js, "{") {
		t.Errorf("json: %v %.40q", err, js)
	}
	if _, err := run(t, "--dir", failing, "--skip-images", "--format", "html"); err == nil {
		t.Error("an unknown format must be refused")
	}
}

func TestOutWritesBothFilesMatchingStdout(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sub", "dir")
	md, err := run(t, "--dir", failing, "--skip-images", "--format", "md", "--now", "2026-10-17T12:00:00Z", "--out", out)
	if err != nil {
		t.Fatal(err)
	}
	gotMD, err := os.ReadFile(filepath.Join(out, "report.md"))
	if err != nil || string(gotMD) != md {
		t.Errorf("report.md differs from stdout (%v)", err)
	}
	js, err := run(t, "--dir", failing, "--skip-images", "--format", "json", "--now", "2026-10-17T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	gotJS, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil || string(gotJS) != js {
		t.Errorf("report.json differs from stdout (%v)", err)
	}
}

func TestBadFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--dir", failing, "--context", "x"},
		{"--dir", failing, "--now", "yesterday"},
		{"--dir", failing, "extra"},
		{"--dir", "testdata/does-not-exist"},
	} {
		if _, err := run(t, args...); err == nil {
			t.Errorf("%v: want an error", args)
		}
	}
}

// The committed example that needs no network must be what the tool produces now; otherwise
// the example has rotted. (examples/kind-ivp used the real cosign and cannot be tested offline.)
func TestCommittedOfflineExampleIsCurrent(t *testing.T) {
	out := t.TempDir()
	if _, err := run(t, "--dir", "testdata/input/kind-snapshot", "--skip-images", "--now", "2026-10-17T15:00:00Z", "--out", out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.md", "report.json"} {
		want, err := os.ReadFile(filepath.Join("examples", "kind-snapshot", name))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(filepath.Join(out, name))
		if string(want) != string(got) {
			t.Errorf("examples/kind-snapshot/%s is out of date: regenerate it (see the README)", name)
		}
	}
}
