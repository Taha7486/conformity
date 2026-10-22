package report

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Taha7486/conformity/internal/supply"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const digest = "sha256:f5eb8b57a454ab073acb0cea7d6bedfb27d37f48a327ecd65fdb7d9ea5c7c7d5"

// recorder is a cosign stand-in: answers come from the real captured output (golden fixtures
// of internal/supply) through a small table, and every call is recorded.
type recorder struct {
	failRefs map[string]bool // images for which verification always fails like a wrong identity
	// onlySubject, when set, is the only signer identity for which verification succeeds.
	onlySubject string
	calls       [][]string
	byCmd       map[string]supply.Result // "download", "verify", "verify-attestation <type>"
	version     string
}

func (r *recorder) Run(_ context.Context, args ...string) (supply.Result, error) {
	r.calls = append(r.calls, args)
	key := args[0]
	if key == "verify-attestation" {
		key += " " + args[2]
	}
	if key == "version" {
		return supply.Result{Stdout: []byte("GitVersion:    " + r.version + "\n")}, nil
	}
	if r.onlySubject != "" && (key == "verify" || strings.HasPrefix(key, "verify-attestation")) {
		for i, a := range args {
			if a == "--certificate-identity" && args[i+1] != r.onlySubject {
				return supply.Result{ExitCode: 1, Stderr: []byte("Error: no matching attestations: failed to verify certificate identity: no matching CertificateIdentity found")}, nil
			}
		}
	}
	if r.failRefs[args[len(args)-1]] {
		switch {
		case key == "download":
			return supply.Result{}, nil
		case key == "verify" || strings.HasPrefix(key, "verify-attestation"):
			return supply.Result{ExitCode: 1, Stderr: []byte("Error: no matching attestations: failed to verify certificate identity: no matching CertificateIdentity found")}, nil
		}
	}
	if res, ok := r.byCmd[key]; ok {
		return res, nil
	}
	return supply.Result{ExitCode: 1, Stderr: []byte("Error: unexpected call " + key)}, nil
}

func (r *recorder) count(sub string) int {
	n := 0
	for _, c := range r.calls {
		if strings.Contains(strings.Join(c, " "), sub) {
			n++
		}
	}
	return n
}

func golden(t *testing.T) *recorder {
	read := func(n string) []byte { return readFile(t, "cosign", "golden", n) }
	return &recorder{version: "v3.1.3", onlySubject: "https://github.com/Taha7486/forge-spike-r1/.github/workflows/r1-sign-golden.yml@refs/heads/main", byCmd: map[string]supply.Result{
		"download":                              {Stdout: read("bundles.jsonl")},
		"verify":                                {Stdout: read("verify.json")},
		"verify-attestation " + supply.PredSBOM: {Stdout: read("verify-attestation-sbom.jsonl")},
		"verify-attestation " + supply.PredVuln: {Stdout: read("verify-attestation-vuln.jsonl")},
	}}
}

func withCosign(t *testing.T, rec supply.Runner, nowS string) (*Report, error) {
	t.Helper()
	snap := load(t, "spike-policy", "pods")
	n, _ := time.Parse(time.RFC3339, nowS)
	return EvaluateWith(context.Background(), snap, Options{Now: n, Tool: "test", Cosign: rec})
}

func controlRow(r *Report, key string) *ControlRow {
	for i := range r.Controls {
		if r.Controls[i].Key() == key {
			return &r.Controls[i]
		}
	}
	return nil
}

func TestImageChecksOnRealPodFixture(t *testing.T) {
	rec := golden(t)
	rep, err := withCosign(t, rec, "2026-10-17T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Cosign != "v3.1.3" {
		t.Errorf("cosign version = %q", rep.Cosign)
	}
	// The pod fixture has the golden image twice (tag, resolved by imageID, and pinned: the same
	// reference), alpine, and the kind system images. Only golden matches the policy glob.
	if rep.Scope.ImagesChecked != 1 || rep.Scope.ImagesFound < 5 {
		t.Errorf("scope = %+v", rep.Scope)
	}
	if len(rep.Images) != 1 {
		t.Fatalf("images = %d", len(rep.Images))
	}
	im := rep.Images[0]
	if im.Ref != "ghcr.io/taha7486/forge-spike-r1@"+digest || !im.Pinned || len(im.UsedBy) != 2 || len(im.Checks) != 3 {
		t.Errorf("image = %+v", im)
	}
	for _, c := range im.Checks {
		if c.Status != supply.Pass {
			t.Errorf("%s: %s %s", c.Control, c.Status, c.Detail)
		}
	}
	for _, key := range []string{"FORGE SC-1", "FORGE SC-2", "FORGE SC-3"} {
		row := controlRow(rep, key)
		if row == nil || row.Status != StatusPass || row.ImageChecks == nil || row.ImageChecks.Pass != 1 {
			t.Errorf("%s = %+v", key, row)
		}
	}
	// cosign calls: one version, one download, one verify (signature), two verify-attestation.
	want := map[string]int{"version": 1, "download": 1, "verify": 1, "verify-attestation": 2}
	got := map[string]int{}
	for _, c := range rec.calls {
		got[c[0]]++
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("cosign %s called %d times, want %d (%v)", k, got[k], v, rec.calls)
		}
	}
	if len(rec.calls) != 5 {
		t.Errorf("calls = %v", rec.calls)
	}
	// The inputs list the two pods that were used, and no others.
	pods := 0
	for _, in := range rep.Inputs {
		if in.Kind == "Pod" {
			pods++
		}
	}
	if pods != 2 {
		t.Errorf("pod inputs = %d, want 2", pods)
	}
}

func TestStaleScanFailsTheControl(t *testing.T) {
	rep, err := withCosign(t, golden(t), "2026-12-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	row := controlRow(rep, "FORGE SC-3")
	if row.Status != StatusFail || row.ImageChecks.Fail != 1 || len(row.Findings) != 1 || !strings.Contains(row.Findings[0].Message, "limit") {
		t.Errorf("SC-3 = %+v", row)
	}
	if controlRow(rep, "FORGE SC-1").Status != StatusPass {
		t.Error("a stale scan must not fail the signature control")
	}
}

func TestWrongIdentityInThePolicyFailsAllThree(t *testing.T) {
	rec := golden(t)
	wrong := supply.Result{ExitCode: 1, Stderr: readFile(t, "cosign", "golden", "stderr-wrongid.txt")}
	rec.byCmd["verify"], rec.byCmd["verify-attestation "+supply.PredSBOM], rec.byCmd["verify-attestation "+supply.PredVuln] = wrong, wrong, wrong
	rep, err := withCosign(t, rec, "2026-10-17T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"FORGE SC-1", "FORGE SC-2", "FORGE SC-3"} {
		if row := controlRow(rep, key); row.Status != StatusFail || row.ImageChecks.Fail != 1 {
			t.Errorf("%s = %+v", key, row)
		}
	}
}

func TestToolTroubleIsReportedAsErrorNotFail(t *testing.T) {
	rec := golden(t)
	down := supply.Result{ExitCode: 1, Stderr: readFile(t, "cosign", "golden", "stderr-nohost.txt")}
	rec.byCmd["verify"] = down
	rep, err := withCosign(t, rec, "2026-10-17T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	row := controlRow(rep, "FORGE SC-1")
	if row.Status != StatusFail || row.ImageChecks.Error != 1 || row.ImageChecks.Fail != 0 || row.Findings[0].Result != "error" {
		t.Errorf("SC-1 = %+v", row)
	}
}

func TestMissingBundlesKeepTheVerdict(t *testing.T) {
	rec := golden(t)
	rec.byCmd["download"] = supply.Result{ExitCode: 1, Stderr: []byte("Error: GET https://ghcr.io: boom")}
	rep, err := withCosign(t, rec, "2026-10-17T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Images[0].BundleError == "" || controlRow(rep, "FORGE SC-2").Status != StatusPass {
		t.Errorf("image = %+v", rep.Images[0])
	}
	for _, c := range rep.Images[0].Checks {
		for _, a := range c.Attestations {
			if a.Binding != "none" || a.Rekor != nil {
				t.Errorf("without bundles there is no Rekor evidence: %+v", a)
			}
		}
	}
}

func TestDisagreementWithKyvernoIsReported(t *testing.T) {
	snap := load(t, "spike-policy", "pods")
	// Kyverno says "pass" for the SBOM policy on pod demo/golden-tag; cosign (here) says the
	// attestation is missing.
	snap.Reports = append(snap.Reports, doc(t, `apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata: {name: r1, namespace: demo}
scope: {kind: Pod, name: golden-tag, namespace: demo, uid: u1}
results:
- {policy: spike-ivp, rule: r, result: pass, timestamp: {seconds: 1760000000}}
`))
	rec := golden(t)
	rec.byCmd["verify-attestation "+supply.PredSBOM] = supply.Result{ExitCode: 1, Stderr: readFile(t, "cosign", "golden", "stderr-unsigned.txt")}
	delete(rec.byCmd, "verify-attestation "+supply.PredSBOM+"|x")
	n, _ := time.Parse(time.RFC3339, "2026-10-17T12:00:00Z")
	rep, err := EvaluateWith(context.Background(), snap, Options{Now: n, Tool: "test", Cosign: rec})
	if err != nil {
		t.Fatal(err)
	}
	// Kyverno writes ONE result per policy and pod. Its "pass" disagrees with the failing SC-2
	// check, so there is one disagreement for the policy (not one per control) that shows all three.
	if len(rep.Disagreements) != 1 {
		t.Fatalf("disagreements = %+v", rep.Disagreements)
	}
	d := rep.Disagreements[0]
	if d.Policy != "spike-ivp" || d.Resource != "Pod demo/golden-tag" || d.Kyverno != "pass" ||
		d.Conformity["FORGE SC-1"] != supply.Pass || d.Conformity["FORGE SC-2"] != supply.Fail || d.Conformity["FORGE SC-3"] != supply.Pass {
		t.Errorf("disagreement = %+v", d)
	}
}

// This is what the kind cluster showed (2026-10-17): the background scan fails a pod whose spec
// has a tag but no digest ("does not have a digest"), while conformity resolves the digest from
// the runtime's imageID and verifies it.
func TestKyvernoFailWithoutDigestVersusConformityPass(t *testing.T) {
	snap := load(t, "spike-policy", "pods")
	snap.Reports = append(snap.Reports, doc(t, `apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata: {name: r1, namespace: demo}
scope: {kind: Pod, name: golden-tag, namespace: demo, uid: u1}
results:
- {policy: spike-ivp, rule: spike-ivp, result: fail, source: KyvernoImageValidatingPolicy, message: "image ghcr.io/taha7486/forge-spike-r1:golden does not have a digest", timestamp: {seconds: 1760000000}}
`))
	n, _ := time.Parse(time.RFC3339, "2026-10-17T12:00:00Z")
	rep, err := EvaluateWith(context.Background(), snap, Options{Now: n, Tool: "test", Cosign: golden(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Disagreements) != 1 || rep.Disagreements[0].Kyverno != "fail" || !strings.Contains(rep.Disagreements[0].KyvernoMessage, "does not have a digest") {
		t.Errorf("disagreements = %+v", rep.Disagreements)
	}
	// The Kyverno failure also shows as a finding, and keeps the control from passing.
	if row := controlRow(rep, "FORGE SC-1"); row.Status != StatusFail || row.Counts.Fail != 1 {
		t.Errorf("SC-1 = %+v", row)
	}
}

func TestAgreeingFailuresAreNotADisagreement(t *testing.T) {
	snap := load(t, "spike-policy", "pods")
	snap.Reports = append(snap.Reports, doc(t, `apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata: {name: r1, namespace: demo}
scope: {kind: Pod, name: golden-tag, namespace: demo, uid: u1}
results:
- {policy: spike-ivp, rule: spike-ivp, result: fail, message: "x", timestamp: {seconds: 1760000000}}
`))
	rec := golden(t)
	wrong := supply.Result{ExitCode: 1, Stderr: readFile(t, "cosign", "golden", "stderr-wrongid.txt")}
	rec.byCmd["verify"] = wrong
	n, _ := time.Parse(time.RFC3339, "2026-10-17T12:00:00Z")
	rep, err := EvaluateWith(context.Background(), snap, Options{Now: n, Tool: "test", Cosign: rec})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Disagreements) != 0 {
		t.Errorf("disagreements = %+v", rep.Disagreements)
	}
}

// Kyverno reports "pass" for every pod an image policy does not apply to. Those must not be
// counted as passes of the FORGE controls.
func TestOutOfScopePodsDoNotInflateTheKyvernoCounts(t *testing.T) {
	snap := load(t, "spike-policy", "pods")
	snap.Reports = append(snap.Reports,
		doc(t, `apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata: {name: r1, namespace: demo}
scope: {kind: Pod, name: golden-pinned, namespace: demo, uid: u1}
results:
- {policy: spike-ivp, rule: spike-ivp, result: pass, message: success, timestamp: {seconds: 1760000000}}
`),
		doc(t, `apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata: {name: r2, namespace: demo}
scope: {kind: Pod, name: unsigned, namespace: demo, uid: u2}
results:
- {policy: spike-ivp, rule: spike-ivp, result: pass, message: success, timestamp: {seconds: 1760000000}}
`),
		doc(t, `apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata: {name: r3, namespace: kube-system}
scope: {kind: Pod, name: etcd, namespace: kube-system, uid: u3}
results:
- {policy: spike-ivp, rule: spike-ivp, result: pass, message: success, timestamp: {seconds: 1760000000}}
`))
	n, _ := time.Parse(time.RFC3339, "2026-10-17T12:00:00Z")
	rep, err := EvaluateWith(context.Background(), snap, Options{Now: n, Tool: "test", Cosign: golden(t)})
	if err != nil {
		t.Fatal(err)
	}
	if row := controlRow(rep, "FORGE SC-1"); row.Counts.Pass != 1 {
		t.Errorf("only golden-pinned is in scope: %+v", row.Counts)
	}
	if rep.Scope.Results != 3 {
		t.Errorf("the scope still counts every result read: %+v", rep.Scope)
	}
	// Without the image stage nothing tells which pods are in scope, so the three passes are
	// not evidence and the control has no data.
	plain, _ := Evaluate(snap, n, "t")
	if row := controlRow(plain, "FORGE SC-1"); row.Counts.Pass != 0 || row.Status != StatusNoData || row.Note != SkippedImagesNote {
		t.Errorf("policy-report-only row = %+v", row)
	}
}

// A Kyverno fail on an image control is real even without the image stage: only the
// passes are dropped.
func TestSkippedImageStageKeepsKyvernoFailures(t *testing.T) {
	snap := load(t, "spike-policy", "pods")
	snap.Reports = append(snap.Reports,
		doc(t, `apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata: {name: r1, namespace: demo}
scope: {kind: Pod, name: golden-pinned, namespace: demo, uid: u1}
results:
- {policy: spike-ivp, rule: spike-ivp, result: pass, message: success, timestamp: {seconds: 1760000000}}
`),
		doc(t, `apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata: {name: r2, namespace: demo}
scope: {kind: Pod, name: unsigned, namespace: demo, uid: u2}
results:
- {policy: spike-ivp, rule: spike-ivp, result: fail, message: "no signatures found", timestamp: {seconds: 1760000000}}
`))
	rep, err := Evaluate(snap, now, "t")
	if err != nil {
		t.Fatal(err)
	}
	row := controlRow(rep, "FORGE SC-1")
	if row.Status != StatusFail || row.Counts.Pass != 0 || row.Counts.Fail != 1 || len(row.Findings) != 1 || row.Note == "" {
		t.Errorf("SC-1 = %+v", row)
	}
}

// Controls that are not image controls keep their Kyverno passes and carry no note.
func TestSkippedImageStageLeavesOtherControlsAlone(t *testing.T) {
	rep, err := Evaluate(load(t, "spike-policy", "pods"), now, "t")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Controls {
		if c.Framework != "FORGE" && c.Note != "" {
			t.Errorf("%s carries a note: %q", c.Key(), c.Note)
		}
	}
}

func TestEcrPoliciesUseTheirOwnIdentity(t *testing.T) {
	snap := load(t, "ecr-policies")
	snap.Pods = append(snap.Pods, doc(t, `apiVersion: v1
kind: Pod
metadata: {name: web, namespace: apps}
spec:
  containers:
  - {name: app, image: "ACCOUNT_ID.dkr.ecr.eu-west-3.amazonaws.com/forge/podinfo:1.0"}
status:
  containerStatuses:
  - {name: app, imageID: "ACCOUNT_ID.dkr.ecr.eu-west-3.amazonaws.com/forge/podinfo@`+digest+`"}
`))
	rec := &recorder{version: "v3.1.3", byCmd: map[string]supply.Result{}}
	n, _ := time.Parse(time.RFC3339, "2026-10-17T12:00:00Z")
	rep, err := EvaluateWith(context.Background(), snap, Options{Now: n, Tool: "test", Cosign: rec})
	if err != nil {
		t.Fatal(err)
	}
	if rec.count("--certificate-identity https://github.com/Taha7486/forge-factory/.github/workflows/sign-attest.yml@refs/heads/main") != 3 {
		t.Errorf("calls = %v", rec.calls)
	}
	// The recorder answers "unexpected call" with exit 1: not a known absence message, so ERROR.
	for _, key := range []string{"FORGE SC-1", "FORGE SC-2", "FORGE SC-3"} {
		if row := controlRow(rep, key); row.Status != StatusFail || row.ImageChecks.Error != 1 {
			t.Errorf("%s = %+v", key, row)
		}
	}
}

func TestPodsOutsideEveryGlobAreNotChecked(t *testing.T) {
	snap := load(t, "ecr-policies", "pods") // spike and kind images; the ECR globs match none
	rec := golden(t)
	n, _ := time.Parse(time.RFC3339, "2026-10-17T12:00:00Z")
	rep, err := EvaluateWith(context.Background(), snap, Options{Now: n, Tool: "test", Cosign: rec})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Scope.ImagesChecked != 0 || rep.Scope.ImagesFound == 0 || len(rep.Images) != 0 {
		t.Errorf("scope = %+v", rep.Scope)
	}
	if rec.count("download") != 0 || rec.count("verify") != 0 {
		t.Errorf("cosign must not be called for images outside the policies: %v", rec.calls)
	}
	if controlRow(rep, "FORGE SC-1").Status != StatusNoData {
		t.Error("with nothing checked the FORGE controls have no data")
	}
}

func TestUnsupportedPolicyShapesStopTheRun(t *testing.T) {
	good := `apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: p
  annotations: {forge.dev/controls: "FORGE SC-1: x"}
spec:
  matchImageReferences: [{glob: "ghcr.io/x/*"}]
  attestors:
  - name: a
    cosign:
      keyless:
        identities: [{subject: "s", issuer: "i"}]
`
	cases := map[string]string{
		"regexp identity":      strings.Replace(good, `{subject: "s", issuer: "i"}`, `{subjectRegExp: "s.*", issuer: "i"}`, 1),
		"extra id field":       strings.Replace(good, `{subject: "s", issuer: "i"}`, `{subject: "s", issuer: "i", issuerRegExp: "x"}`, 1),
		"key attestor":         strings.Replace(good, "keyless:\n        identities: [{subject: \"s\", issuer: \"i\"}]", "key: {data: abc}", 1),
		"expression glob":      strings.Replace(good, `{glob: "ghcr.io/x/*"}`, `{expression: "true"}`, 1),
		"glob plus expression": strings.Replace(good, `{glob: "ghcr.io/x/*"}`, `{glob: "ghcr.io/x/*", expression: "true"}`, 1),
		"no globs":             strings.Replace(good, `[{glob: "ghcr.io/x/*"}]`, `[]`, 1),
		"unknown control":      strings.Replace(good, "SC-1", "SC-9", 1),
		"wrong kind":           strings.Replace(good, "ImageValidatingPolicy", "ValidatingPolicy", 1),
	}
	for name, y := range cases {
		snap := load(t)
		snap.Policies = []*unstructured.Unstructured{doc(t, y)}
		_, err := EvaluateWith(context.Background(), snap, Options{Now: now, Tool: "t", Cosign: &recorder{version: "v3.1.3"}})
		if err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	snap := load(t)
	snap.Policies = []*unstructured.Unstructured{doc(t, good)}
	if _, err := EvaluateWith(context.Background(), snap, Options{Now: now, Tool: "t", Cosign: &recorder{version: "v3.1.3"}}); err != nil {
		t.Errorf("the good policy must be accepted: %v", err)
	}
}

func TestCosignMissingStopsTheRun(t *testing.T) {
	snap := load(t, "spike-policy", "pods")
	_, err := EvaluateWith(context.Background(), snap, Options{Now: now, Tool: "t", Cosign: supply.Exec{Path: "/nonexistent/cosign"}})
	if err == nil || !strings.Contains(err.Error(), "--skip-images") {
		t.Errorf("err = %v", err)
	}
}

func TestSkippingImagesLeavesThePolicyReportAlone(t *testing.T) {
	a, err := Evaluate(load(t, "spike-policy", "pods"), now, "t")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Images) != 0 || a.Cosign != "" || controlRow(a, "FORGE SC-1").Status != StatusNoData || controlRow(a, "FORGE SC-1").ImageChecks != nil {
		t.Errorf("report = %+v", a.Scope)
	}
}

func TestSpikeImageReportGolden(t *testing.T) {
	rep, err := withCosign(t, golden(t), "2026-10-17T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "testdata", "golden", "spike-images.report.json")
	if *update {
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want := readFile(t, "golden", "spike-images.report.json"); !bytes.Equal(want, buf.Bytes()) {
		t.Error("report differs from the golden file; if the change is intended, run go test ./internal/report -update")
	}
}

// The fixtures in testdata/input/kind-ivp come from a kind cluster with Kyverno 1.19.1 and a
// real ImageValidatingPolicy (2026-10-17). Pods: golden-tag and lookalike and unsigned were
// created BEFORE the policy, golden-after through the admission webhook (which added the
// digest). Cosign is the fake runner here; the live run against the same cluster is in the
// session log.
const lookalikeRef = "ghcr.io/taha7486/forge-spike-r1@sha256:bc86a3fd0a92eb9455a9641709fa9bf62e93d8f1c63620fb3ac4583f162536df"

func TestRealKyvernoImagePolicyReports(t *testing.T) {
	rec := golden(t)
	rec.failRefs = map[string]bool{lookalikeRef: true}
	n, _ := time.Parse(time.RFC3339, "2026-10-17T15:50:00Z")
	rep, err := EvaluateWith(context.Background(), load(t, "kind-ivp"), Options{Now: n, Tool: "test", Cosign: rec})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Scope.ImagesChecked != 2 || rep.Scope.ImagesFound < 5 {
		t.Errorf("scope = %+v", rep.Scope)
	}
	// Kyverno: golden-after pass, golden-tag fail (no digest), lookalike fail. The "pass" results
	// for the kube-system pods and alpine are out of the policy's scope and are not counted.
	for _, key := range []string{"FORGE SC-1", "FORGE SC-2", "FORGE SC-3"} {
		row := controlRow(rep, key)
		if row.Counts.Pass != 1 || row.Counts.Fail != 2 || row.Status != StatusFail {
			t.Errorf("%s = %+v", key, row.Counts)
		}
		if row.ImageChecks.Pass != 1 || row.ImageChecks.Fail != 1 || row.ImageChecks.Error != 0 {
			t.Errorf("%s image checks = %+v", key, row.ImageChecks)
		}
	}
	if len(rep.Disagreements) != 1 {
		t.Fatalf("disagreements = %+v", rep.Disagreements)
	}
	d := rep.Disagreements[0]
	if d.Resource != "Pod demo/golden-tag" || d.Kyverno != "fail" || !strings.Contains(d.KyvernoMessage, "does not have a digest") ||
		d.Conformity["FORGE SC-1"] != supply.Pass {
		t.Errorf("disagreement = %+v", d)
	}
	// golden-tag and golden-after share one image (digest from imageID, and from the webhook's
	// "tag@digest" spec).
	for _, im := range rep.Images {
		if im.Ref == "ghcr.io/taha7486/forge-spike-r1@"+digest && (len(im.UsedBy) != 2 || !im.Pinned) {
			t.Errorf("golden image = %+v", im)
		}
	}
}

// A policy edited after Kyverno wrote its reports: the reports (controllers stopped) still say
// "pass" for golden-after, while the policy now accepts only the lookalike workflow.
func TestStaleKyvernoReportAgainstChangedPolicy(t *testing.T) {
	snap := load(t, "kind-ivp")
	snap.Policies = load(t, "kind-ivp-stale-policy").Policies
	n, _ := time.Parse(time.RFC3339, "2026-10-17T16:00:00Z")
	rep, err := EvaluateWith(context.Background(), snap, Options{Now: n, Tool: "test", Cosign: golden(t)})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, d := range rep.Disagreements {
		if d.Resource == "Pod demo/golden-after" {
			found = true
			if d.Kyverno != "pass" || d.Conformity["FORGE SC-1"] != supply.Fail || d.Conformity["FORGE SC-3"] != supply.Fail {
				t.Errorf("disagreement = %+v", d)
			}
		}
	}
	if !found {
		t.Errorf("the stale pass for golden-after must be reported: %+v", rep.Disagreements)
	}
}

// SC-4 (the registry rule) is a plain ValidatingPolicy with no cosign check: its PolicyReport
// results are the evidence, also when the image stage runs for the other FORGE controls.
func TestRegistryRuleIsReportOnlyNextToImagePolicies(t *testing.T) {
	snap := load(t, "ecr-policies")
	snap.Policies = append(snap.Policies, doc(t, `apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: forge-ecr-registry
  annotations: {forge.dev/controls: "FORGE SC-4: Images come only from the allowed registry"}
spec:
  validationActions: [Deny, Audit]
`))
	snap.Pods = append(snap.Pods, doc(t, `apiVersion: v1
kind: Pod
metadata: {name: web, namespace: apps}
spec:
  containers:
  - {name: app, image: "ACCOUNT_ID.dkr.ecr.eu-west-3.amazonaws.com/forge/podinfo:1.0"}
status:
  containerStatuses:
  - {name: app, imageID: "ACCOUNT_ID.dkr.ecr.eu-west-3.amazonaws.com/forge/podinfo@`+digest+`"}
`))
	snap.Reports = append(snap.Reports,
		doc(t, `apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata: {name: ok, namespace: apps}
scope: {kind: Pod, name: web, namespace: apps, uid: u1}
results:
- {policy: forge-ecr-registry, result: pass, message: success, timestamp: {seconds: 1760000000}}
`),
		doc(t, `apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata: {name: bad, namespace: apps}
scope: {kind: Pod, name: hub, namespace: apps, uid: u2}
results:
- {policy: forge-ecr-registry, result: fail, message: "images must come from the ECR forge/ prefix (FORGE SC-4), not: docker.io/library/nginx:1.27", timestamp: {seconds: 1760000000}}
`))
	rec := &recorder{version: "v3.1.3", byCmd: map[string]supply.Result{}}
	n, _ := time.Parse(time.RFC3339, "2026-10-17T12:00:00Z")
	rep, err := EvaluateWith(context.Background(), snap, Options{Now: n, Tool: "test", Cosign: rec})
	if err != nil {
		t.Fatalf("a registry rule next to image policies must not stop the run: %v", err)
	}
	row := controlRow(rep, "FORGE SC-4")
	if row == nil || row.Status != StatusFail || row.Counts.Pass != 1 || row.Counts.Fail != 1 || row.ImageChecks != nil {
		t.Fatalf("SC-4 = %+v", row)
	}
	if f := findingsFor(rep, "FORGE SC-4"); len(f) != 1 || !strings.Contains(f[0].Message, "docker.io/library/nginx") {
		t.Errorf("findings = %+v", f)
	}
	if rec.count("--certificate-identity") != 3 {
		t.Errorf("the image policies still get their three cosign checks: %v", rec.calls)
	}
	for _, key := range []string{"FORGE SC-1", "FORGE SC-2", "FORGE SC-3"} {
		if r := controlRow(rep, key); r.ImageChecks == nil {
			t.Errorf("%s lost its image checks", key)
		}
	}
}

// Without the image stage (--skip-images) SC-4 reads the same way.
func TestRegistryRuleWithoutImageStage(t *testing.T) {
	snap := load(t)
	snap.Policies = []*unstructured.Unstructured{doc(t, `apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: forge-ecr-registry
  annotations: {forge.dev/controls: "FORGE SC-4: Images come only from the allowed registry"}
spec: {}
`)}
	snap.Reports = append(snap.Reports, doc(t, `apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata: {name: ok, namespace: apps}
scope: {kind: Pod, name: web, namespace: apps, uid: u1}
results:
- {policy: forge-ecr-registry, result: pass, message: success, timestamp: {seconds: 1760000000}}
`))
	rep, err := Evaluate(snap, now, "t")
	if err != nil {
		t.Fatal(err)
	}
	if row := controlRow(rep, "FORGE SC-4"); row == nil || row.Status != StatusPass {
		t.Errorf("SC-4 = %+v", row)
	}
}
