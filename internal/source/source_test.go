package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const pol = "apiVersion: policies.kyverno.io/v1\nkind: ValidatingPolicy\nmetadata:\n  name: %s\n"
const rep = "apiVersion: wgpolicyk8s.io/v1alpha2\nkind: PolicyReport\nmetadata:\n  name: r\n  namespace: ns\n"

func TestDirClassifiesMultiDocListsAndJSON(t *testing.T) {
	d := t.TempDir()
	write(t, d, "a.yaml", strings.Replace(pol, "%s", "p1", 1)+"---\n"+strings.Replace(pol, "%s", "p2", 1)+"---\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: other\n")
	write(t, d, "list.yaml", "apiVersion: v1\nkind: List\nitems:\n- "+strings.ReplaceAll(strings.TrimSpace(rep), "\n", "\n  ")+"\n")
	write(t, d, "p.json", `{"apiVersion":"policies.kyverno.io/v1","kind":"ImageValidatingPolicy","metadata":{"name":"p3"}}`)
	write(t, d, "notes.txt", "not read")
	s, err := Dir{Path: d}.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Policies) != 3 || len(s.Reports) != 1 || s.Ignored != 1 {
		t.Errorf("policies=%d reports=%d ignored=%d", len(s.Policies), len(s.Reports), s.Ignored)
	}
}

func TestDirRejectsBrokenInput(t *testing.T) {
	for name, body := range map[string]string{
		"no kind":    "metadata:\n  name: x\n",
		"bad yaml":   "kind: [unterminated\n",
		"bad json":   "{\"kind\": ",
		"scalar doc": "just text\n",
	} {
		d := t.TempDir()
		write(t, d, "x.yaml", body)
		if _, err := (Dir{Path: d}).Load(context.Background()); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestHashIgnoresManagedFieldsButNotContent(t *testing.T) {
	d := t.TempDir()
	write(t, d, "a.yaml", strings.Replace(pol, "%s", "p", 1))
	write(t, d, "b.yaml", strings.Replace(pol, "%s", "p", 1)+"  managedFields:\n  - manager: kubectl\n")
	write(t, d, "c.yaml", strings.Replace(pol, "%s", "q", 1))
	var h [3]string
	for i, f := range []string{"a.yaml", "b.yaml", "c.yaml"} {
		dd := t.TempDir()
		data, _ := os.ReadFile(filepath.Join(d, f))
		write(t, dd, "x.yaml", string(data))
		s, err := Dir{Path: dd}.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		h[i], _ = Hash(s.Policies[0])
	}
	if h[0] != h[1] || h[0] == h[2] {
		t.Errorf("hashes = %v", h)
	}
}
