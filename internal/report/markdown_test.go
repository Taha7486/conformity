package report

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "golden", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs from the golden file; if the change is intended, run go test ./internal/report -update", name)
	}
}

func markdown(t *testing.T, r *Report) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := WriteMarkdown(&b, r); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestMarkdownGoldenPolicyReportsOnly(t *testing.T) {
	rep, err := Evaluate(load(t, "kind-snapshot", "ecr-policies"), now, "test")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "kind-snapshot.report.md", markdown(t, rep))
}

func TestMarkdownGoldenWithImageEvidence(t *testing.T) {
	rep, err := withCosign(t, golden(t), "2026-10-17T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "spike-images.report.md", markdown(t, rep))
}

func TestMarkdownGoldenRealKyvernoImagePolicy(t *testing.T) {
	rec := golden(t)
	rec.failRefs = map[string]bool{lookalikeRef: true}
	n, _ := time.Parse(time.RFC3339, "2026-10-17T15:50:00Z")
	rep, err := EvaluateWith(context.Background(), load(t, "kind-ivp"), Options{Now: n, Tool: "test", Cosign: rec})
	if err != nil {
		t.Fatal(err)
	}
	md := markdown(t, rep)
	checkGolden(t, "kind-ivp.report.md", md)
	for _, want := range []string{"## Disagreements between Kyverno and conformity", "does not have a digest", "Rekor log index 3048288702"} {
		if !bytes.Contains(md, []byte(want)) {
			t.Errorf("report lacks %q", want)
		}
	}
}

// Pod names and Kyverno or cosign messages are untrusted text. Nothing in them may break a
// table row, make a link, or inject HTML.
func TestMarkdownEscapesUntrustedText(t *testing.T) {
	evil := "a|b `code` <script>alert(1)</script> [click](http://evil) *bold* _it_ ~x~\nnew line & more"
	pol := policyDoc(t, "p", "CIS 1.1")
	rep := reportDoc(t, "ns", "p=fail")
	// put the evil text in the message and the pod name
	results := rep.Object["results"].([]interface{})
	results[0].(map[string]interface{})["message"] = evil
	rep.Object["scope"].(map[string]interface{})["name"] = "pod|[x](y)"
	r, err := eval(t, []*unstructured.Unstructured{pol}, []*unstructured.Unstructured{rep})
	if err != nil {
		t.Fatal(err)
	}
	md := string(markdown(t, r))
	for _, bad := range []string{"<script>", "[click](http", "[x](y)", "`code`"} {
		if strings.Contains(md, bad) {
			t.Errorf("unescaped %q in:\n%s", bad, md)
		}
	}
	// The finding row must still have exactly the 4 columns: 5 unescaped pipes.
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| p | Pod ns/pod") {
			unescaped := strings.Count(strings.ReplaceAll(line, "\\|", ""), "|")
			if unescaped != 5 {
				t.Errorf("row has %d pipes: %s", unescaped, line)
			}
			return
		}
	}
	t.Errorf("finding row not found in:\n%s", md)
}

func TestMarkdownCapsFindingsPerControl(t *testing.T) {
	// 25 results for one pod and policy is odd but legal; use distinct pods instead
	var reps []*unstructured.Unstructured
	for i := 0; i < MaxFindingsPerControl+5; i++ {
		reps = append(reps, reportDocPod(t, fmt.Sprintf("pod-%02d", i), "p=fail"))
	}
	r, err := eval(t, []*unstructured.Unstructured{policyDoc(t, "p", "CIS 1.1")}, reps)
	if err != nil {
		t.Fatal(err)
	}
	md := string(markdown(t, r))
	if strings.Count(md, "| p | Pod ns/pod-") != MaxFindingsPerControl || !strings.Contains(md, "5 more in `report.json`") {
		t.Errorf("cap not applied:\n%s", md)
	}
	if len(r.Controls[0].Findings) != MaxFindingsPerControl+5 {
		t.Error("the JSON keeps every finding")
	}
}

func reportDocPod(t *testing.T, pod string, result string) *unstructured.Unstructured {
	parts := strings.Split(result, "=")
	return doc(t, "apiVersion: wgpolicyk8s.io/v1alpha2\nkind: PolicyReport\nmetadata: {name: r-"+pod+", namespace: ns}\nscope: {kind: Pod, name: "+pod+", namespace: ns, uid: u-"+pod+"}\nresults:\n- {policy: "+parts[0]+", rule: r, result: "+parts[1]+", timestamp: {seconds: 1760000000}}\n")
}

func TestMarkdownOverallLines(t *testing.T) {
	cases := []struct {
		name string
		pols []*unstructured.Unstructured
		reps []*unstructured.Unstructured
		want string
	}{
		{"fail", []*unstructured.Unstructured{policyDoc(t, "p", "CIS 1.1")}, []*unstructured.Unstructured{reportDocPod(t, "a", "p=fail")}, "**Overall: FAIL.** 1 of 1 controls fail."},
		{"pass", []*unstructured.Unstructured{policyDoc(t, "p", "CIS 1.1")}, []*unstructured.Unstructured{reportDocPod(t, "a", "p=pass")}, "**Overall: PASS.** All 1 controls pass."},
		{"no data", []*unstructured.Unstructured{policyDoc(t, "p", "CIS 1.1")}, nil, "**Overall: no failing control**, but 1 have no data or were skipped."},
		{"no controls", []*unstructured.Unstructured{policyDoc(t, "p", "")}, nil, "**Overall: NO DATA.** No policy carries a control annotation."},
	}
	for _, c := range cases {
		r, err := eval(t, c.pols, c.reps)
		if err != nil {
			t.Fatal(err)
		}
		if md := string(markdown(t, r)); !strings.Contains(md, c.want) {
			t.Errorf("%s: want %q in\n%s", c.name, c.want, md)
		}
	}
}

func TestMarkdownIsDeterministic(t *testing.T) {
	a, _ := withCosign(t, golden(t), "2026-10-17T12:00:00Z")
	b, _ := withCosign(t, golden(t), "2026-10-17T12:00:00Z")
	if !bytes.Equal(markdown(t, a), markdown(t, b)) {
		t.Error("two runs differ")
	}
}

func TestInputsDigestChangesWithTheInputs(t *testing.T) {
	full, _ := Evaluate(load(t, "kind-snapshot"), now, "t")
	s := load(t, "kind-snapshot")
	s.Reports = s.Reports[1:]
	less, _ := Evaluate(s, now, "t")
	again, _ := Evaluate(load(t, "kind-snapshot"), now, "t")
	if full.InputsSHA256 == "" || full.InputsSHA256 != again.InputsSHA256 || full.InputsSHA256 == less.InputsSHA256 {
		t.Errorf("digests: %s %s %s", full.InputsSHA256, again.InputsSHA256, less.InputsSHA256)
	}
}

func TestCodeSpanCannotBeBrokenOut(t *testing.T) {
	if got := code("a`b|c\nd"); got != "`a'b\\|c d`" {
		t.Errorf("code() = %q", got)
	}
}
