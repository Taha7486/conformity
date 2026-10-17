package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Taha7486/conformity/internal/source"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

// These tests use small hand-written documents (marked synthetic). The fixtures captured
// from a real cluster are used in fixtures_test.go.

func doc(t *testing.T, y string) *unstructured.Unstructured {
	t.Helper()
	u := &unstructured.Unstructured{}
	if err := yaml.Unmarshal([]byte(y), &u.Object); err != nil {
		t.Fatal(err)
	}
	return u
}

func policyDoc(t *testing.T, name, controls string) *unstructured.Unstructured {
	ann := ""
	if controls != "" {
		ann = "\n  annotations:\n    forge.dev/controls: \"" + controls + "\""
	}
	return doc(t, "apiVersion: policies.kyverno.io/v1\nkind: ValidatingPolicy\nmetadata:\n  name: "+name+ann+"\nspec:\n  validationActions: [Deny, Audit]\n")
}

func reportDoc(t *testing.T, ns string, results ...string) *unstructured.Unstructured {
	y := "apiVersion: wgpolicyk8s.io/v1alpha2\nkind: PolicyReport\nmetadata:\n  name: r-" + ns + "\n  namespace: " + ns + "\nscope:\n  kind: Pod\n  name: p1\n  namespace: " + ns + "\n  uid: u-" + ns + "\nresults:\n"
	for _, r := range results {
		parts := strings.Split(r, "=") // policy=result
		y += "- policy: " + parts[0] + "\n  rule: r\n  result: " + parts[1] + "\n  timestamp: {seconds: 1760000000}\n"
	}
	return doc(t, y)
}

var now = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func eval(t *testing.T, pols, reps []*unstructured.Unstructured) (*Report, error) {
	return Evaluate(&source.Snapshot{Origin: "synthetic", Policies: pols, Reports: reps}, now, "test")
}

func statusOf(r *Report, key string) string {
	for _, c := range r.Controls {
		if c.Key() == key {
			return c.Status
		}
	}
	return "MISSING"
}

func TestStatusRules(t *testing.T) {
	pols := []*unstructured.Unstructured{
		policyDoc(t, "p-pass", "CIS 1.1"), policyDoc(t, "p-fail", "CIS 1.2"),
		policyDoc(t, "p-mixed", "CIS 1.3"), policyDoc(t, "p-skip", "CIS 1.4"),
		policyDoc(t, "p-none", "CIS 1.5"), policyDoc(t, "p-warn", "CIS 1.6"),
		policyDoc(t, "p-err", "CIS 1.7"),
	}
	reps := []*unstructured.Unstructured{
		reportDoc(t, "a", "p-pass=pass", "p-fail=fail", "p-mixed=pass", "p-skip=skip", "p-warn=warn", "p-err=error"),
		reportDoc(t, "b", "p-pass=pass", "p-mixed=fail"),
	}
	r, err := eval(t, pols, reps)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"CIS 1.1": StatusPass, "CIS 1.2": StatusFail, "CIS 1.3": StatusFail,
		"CIS 1.4": StatusSkip, "CIS 1.5": StatusNoData, "CIS 1.6": StatusFail, "CIS 1.7": StatusFail}
	for k, v := range want {
		if got := statusOf(r, k); got != v {
			t.Errorf("%s = %s, want %s", k, got, v)
		}
	}
	if r.Summary != (Summary{Controls: 7, Pass: 1, Fail: 4, Skipped: 1, NoData: 1}) {
		t.Errorf("summary = %+v", r.Summary)
	}
}

func TestOneControlTwoPolicies(t *testing.T) {
	pols := []*unstructured.Unstructured{policyDoc(t, "a", "CIS 5.2.7"), policyDoc(t, "b", "CIS 5.2.7; PSS restricted: X")}
	r, err := eval(t, pols, []*unstructured.Unstructured{reportDoc(t, "ns", "a=pass", "b=fail")})
	if err != nil {
		t.Fatal(err)
	}
	if statusOf(r, "CIS 5.2.7") != StatusFail || statusOf(r, "PSS restricted: X") != StatusFail {
		t.Errorf("controls = %+v", r.Controls)
	}
	if len(r.Controls) != 2 {
		t.Errorf("want 2 controls, got %d", len(r.Controls))
	}
}

func TestBadAnnotationFailsClosed(t *testing.T) {
	_, err := eval(t, []*unstructured.Unstructured{policyDoc(t, "ok", "CIS 1.1"), policyDoc(t, "bad", "CIS five")}, nil)
	if err == nil || !strings.Contains(err.Error(), `policy "bad"`) {
		t.Errorf("err = %v", err)
	}
}

func TestUnmappedPolicyAndForeignResults(t *testing.T) {
	r, err := eval(t, []*unstructured.Unstructured{policyDoc(t, "mapped", "CIS 1.1"), policyDoc(t, "plain", "")},
		[]*unstructured.Unstructured{reportDoc(t, "ns", "mapped=pass", "plain=fail", "other=fail")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Unmapped) != 1 || r.Unmapped[0] != "plain" {
		t.Errorf("unmapped = %v", r.Unmapped)
	}
	if r.Scope.ResultsNoPolicy != 2 || r.Scope.Results != 3 {
		t.Errorf("scope = %+v", r.Scope)
	}
	if statusOf(r, "CIS 1.1") != StatusPass {
		t.Errorf("foreign failures must not change a control")
	}
}

func TestUnknownResultValueIsAnError(t *testing.T) {
	_, err := eval(t, []*unstructured.Unstructured{policyDoc(t, "p", "CIS 1.1")},
		[]*unstructured.Unstructured{reportDoc(t, "ns", "p=passed")})
	if err == nil {
		t.Error("want an error for result \"passed\"")
	}
}

func TestDeterministicForSameInput(t *testing.T) {
	pols := []*unstructured.Unstructured{policyDoc(t, "b", "CIS 1.2"), policyDoc(t, "a", "CIS 1.1")}
	reps := []*unstructured.Unstructured{reportDoc(t, "ns", "a=pass", "b=fail")}
	var out [2]strings.Builder
	for i := range out {
		r, err := eval(t, pols, reps)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteJSON(&out[i], r); err != nil {
			t.Fatal(err)
		}
	}
	if out[0].String() != out[1].String() {
		t.Error("two runs on the same input differ")
	}
}

// A FAIL must come with the evidence: every fail, warn and error result is listed.
func TestEveryBadResultIsAFinding(t *testing.T) {
	pols := []*unstructured.Unstructured{policyDoc(t, "p-fail", "CIS 1.1"), policyDoc(t, "p-warn", "CIS 1.2"),
		policyDoc(t, "p-err", "CIS 1.3"), policyDoc(t, "p-ok", "CIS 1.4")}
	r, err := eval(t, pols, []*unstructured.Unstructured{reportDoc(t, "ns", "p-fail=fail", "p-warn=warn", "p-err=error", "p-ok=pass")})
	if err != nil {
		t.Fatal(err)
	}
	for key, n := range map[string]int{"CIS 1.1": 1, "CIS 1.2": 1, "CIS 1.3": 1, "CIS 1.4": 0} {
		if got := len(findingsFor(r, key)); got != n {
			t.Errorf("%s: %d findings, want %d", key, got, n)
		}
	}
}
