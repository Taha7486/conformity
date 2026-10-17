package supply

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixtures in testdata/cosign/golden are real cosign v3.1.3 output (trimmed, see the README
// there). The fake runner answers each cosign call from them.

const digest = "sha256:f5eb8b57a454ab073acb0cea7d6bedfb27d37f48a327ecd65fdb7d9ea5c7c7d5"
const ref = "ghcr.io/taha7486/forge-spike-r1@" + digest

var pinned = Identity{
	Subject: "https://github.com/Taha7486/forge-spike-r1/.github/workflows/r1-sign-golden.yml@refs/heads/main",
	Issuer:  "https://token.actions.githubusercontent.com",
}

func fx(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cosign", "golden", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fake answers by the cosign subcommand (and --type for verify-attestation).
type fake struct {
	calls   [][]string
	answers map[string]Result
	err     error
}

func (f *fake) Run(_ context.Context, args ...string) (Result, error) {
	f.calls = append(f.calls, args)
	if f.err != nil {
		return Result{}, f.err
	}
	key := args[0]
	if key == "verify-attestation" {
		key += " " + args[2]
	}
	if key == "verify" || strings.HasPrefix(key, "verify-attestation") {
		// the identity decides: only the pinned one is accepted unless an answer is keyed with it
		for i, a := range args {
			if a == "--certificate-identity" {
				if r, ok := f.answers[key+"|"+args[i+1]]; ok {
					return r, nil
				}
			}
		}
	}
	r, ok := f.answers[key]
	if !ok {
		return Result{ExitCode: 1, Stderr: []byte("Error: unexpected call " + key)}, nil
	}
	return r, nil
}

func goldenAnswers(t *testing.T) map[string]Result {
	return map[string]Result{
		"download":                 {Stdout: fx(t, "bundles.jsonl")},
		"verify|" + pinned.Subject: {Stdout: fx(t, "verify.json")},
		"verify-attestation " + PredSBOM + "|" + pinned.Subject: {Stdout: fx(t, "verify-attestation-sbom.jsonl")},
		"verify-attestation " + PredVuln + "|" + pinned.Subject: {Stdout: fx(t, "verify-attestation-vuln.jsonl")},
		"verify":                         {ExitCode: 1, Stderr: fx(t, "stderr-wrongid.txt")},
		"verify-attestation " + PredSBOM: {ExitCode: 1, Stderr: fx(t, "stderr-wrongid.txt")},
		"verify-attestation " + PredVuln: {ExitCode: 1, Stderr: fx(t, "stderr-wrongid.txt")},
	}
}

func checker(f Runner, now string) *Checker {
	n, _ := time.Parse(time.RFC3339, now)
	return &Checker{Runner: f, Now: n, MaxScanAge: 720 * time.Hour}
}

func bundles(t *testing.T, c *Checker) []Bundle {
	t.Helper()
	b, err := c.Bundles(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBundleParsing(t *testing.T) {
	c := checker(&fake{answers: goldenAnswers(t)}, "2026-10-17T12:00:00Z")
	bs := bundles(t, c)
	if len(bs) != 5 {
		t.Fatalf("bundles = %d, want 5", len(bs))
	}
	cert, err := bs[0].Cert()
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject != pinned.Subject || cert.Issuer != pinned.Issuer || cert.NotBefore != "2026-10-02T05:04:10Z" || cert.NotAfter != "2026-10-02T05:14:10Z" {
		t.Errorf("cert = %+v", cert)
	}
	r := bs[0].Rekor()
	if r.ProofMatchesCheckpoint == nil || !*r.ProofMatchesCheckpoint {
		t.Errorf("proof must match the checkpoint in the untouched bundle: %+v", r)
	}
	if r.LogIndex != "3048288286" || r.IntegratedTime != "2026-10-02T05:04:10Z" || !r.InclusionProof || !r.InclusionPromise || r.Kind != "dsse 0.0.1" || r.TreeSize != "2926384039" {
		t.Errorf("rekor = %+v", r)
	}
}

func TestSignaturePass(t *testing.T) {
	c := checker(&fake{answers: goldenAnswers(t)}, "2026-10-17T12:00:00Z")
	o := c.Check(context.Background(), ref, Signature, []Identity{pinned}, bundles(t, c))
	if o.Status != Pass || o.Digest != digest {
		t.Fatalf("outcome = %+v", o)
	}
	if len(o.Attestations) != 2 || o.Attestations[0].Binding != "certificate-identity" || o.Attestations[0].Rekor == nil {
		t.Errorf("evidence = %+v", o.Attestations)
	}
}

func TestSBOMPass(t *testing.T) {
	c := checker(&fake{answers: goldenAnswers(t)}, "2026-10-17T12:00:00Z")
	o := c.Check(context.Background(), ref, SBOM, []Identity{pinned}, bundles(t, c))
	if o.Status != Pass || len(o.Attestations) != 1 {
		t.Fatalf("outcome = %+v", o)
	}
	a := o.Attestations[0]
	if a.Binding != "dsse-signature" || a.Rekor == nil || a.Rekor.LogIndex != "3048288702" || a.Signer == nil || a.Signer.Subject != pinned.Subject {
		t.Errorf("attestation = %+v", a)
	}
}

func TestVulnFreshAndStale(t *testing.T) {
	// Two verified scans: 2026-10-02T05:04:09.76Z and 06:06:38.12Z. Limit 720h (30 days), so the
	// newest scan goes stale at 2026-11-01T06:06:38.12Z; the times below sit a second either side.
	for _, tc := range []struct {
		now, want string
	}{
		{"2026-10-17T12:00:00Z", Pass}, // 15 days
		{"2026-11-01T06:06:37Z", Pass}, // a second inside the limit
		{"2026-11-01T06:06:39Z", Fail}, // a second outside it
		{"2026-12-01T00:00:00Z", Fail},
	} {
		c := checker(&fake{answers: goldenAnswers(t)}, tc.now)
		o := c.Check(context.Background(), ref, Vuln, []Identity{pinned}, bundles(t, c))
		if o.Status != tc.want {
			t.Errorf("now=%s: %s (%s), want %s", tc.now, o.Status, o.Detail, tc.want)
		}
		if len(o.Attestations) != 2 || o.Attestations[0].ScanFinishedOn != "2026-10-02T06:06:38Z" {
			t.Errorf("now=%s: newest scan must come first: %+v", tc.now, o.Attestations)
		}
	}
	c := checker(&fake{answers: goldenAnswers(t)}, "2026-12-01T00:00:00Z")
	o := c.Check(context.Background(), ref, Vuln, []Identity{pinned}, nil)
	if !strings.Contains(o.Detail, "limit 720h0m0s") {
		t.Errorf("detail = %q", o.Detail)
	}
}

func TestFailuresFromRealCosignText(t *testing.T) {
	for _, tc := range []struct{ file, want string }{
		{"stderr-wrongid.txt", Fail},
		{"stderr-unsigned.txt", Fail},
		{"stderr-nottype.txt", Fail},
		{"stderr-alpine-va.txt", Fail},
		{"stderr-alpine-vf.txt", Fail},
		{"stderr-missing.txt", Error},
		{"stderr-nohost.txt", Error},
	} {
		got, detail := Classify(Result{ExitCode: 1, Stderr: fx(t, tc.file)})
		if got != tc.want || detail == "" || strings.Contains(detail, "\n") {
			t.Errorf("%s: %s %q, want %s", tc.file, got, detail, tc.want)
		}
	}
	if s, _ := Classify(Result{ExitCode: 1, Stderr: []byte("Error: getting trusted root from TUF: network is unreachable")}); s != Error {
		t.Errorf("a TUF failure must be ERROR, got %s", s)
	}
	if s, _ := Classify(Result{ExitCode: 137}); s != Error {
		t.Errorf("an unexplained exit must be ERROR, got %s", s)
	}
}

func TestWrongIdentityIsAFailure(t *testing.T) {
	f := &fake{answers: goldenAnswers(t)}
	c := checker(f, "2026-10-17T12:00:00Z")
	other := Identity{Subject: "https://github.com/Taha7486/forge-spike-r1-lookalike/.github/workflows/r1-sign-golden.yml@refs/heads/main", Issuer: pinned.Issuer}
	for _, k := range []Kind{Signature, SBOM, Vuln} {
		if o := c.Check(context.Background(), ref, k, []Identity{other}, nil); o.Status != Fail {
			t.Errorf("%s: %+v", k, o)
		}
	}
}

func TestOneOfSeveralIdentitiesIsEnough(t *testing.T) {
	c := checker(&fake{answers: goldenAnswers(t)}, "2026-10-17T12:00:00Z")
	other := Identity{Subject: "https://example.com/other", Issuer: pinned.Issuer}
	if o := c.Check(context.Background(), ref, SBOM, []Identity{other, pinned}, nil); o.Status != Pass {
		t.Errorf("outcome = %+v", o)
	}
}

func TestErrorOutranksFailure(t *testing.T) {
	a := goldenAnswers(t)
	a["verify|https://example.com/net"] = Result{ExitCode: 1, Stderr: fx(t, "stderr-nohost.txt")}
	c := checker(&fake{answers: a}, "2026-10-17T12:00:00Z")
	other := Identity{Subject: "https://example.com/other", Issuer: pinned.Issuer}
	net := Identity{Subject: "https://example.com/net", Issuer: pinned.Issuer}
	if o := c.Check(context.Background(), ref, Signature, []Identity{other, net}, nil); o.Status != Error {
		t.Errorf("a fail plus an error must be ERROR: %+v", o)
	}
}

func TestRunnerErrorIsError(t *testing.T) {
	c := checker(&fake{err: errors.New("cosign timed out after 1m0s")}, "2026-10-17T12:00:00Z")
	o := c.Check(context.Background(), ref, SBOM, []Identity{pinned}, nil)
	if o.Status != Error || !strings.Contains(o.Detail, "timed out") {
		t.Errorf("outcome = %+v", o)
	}
	if _, err := c.Bundles(context.Background(), ref); err == nil {
		t.Error("Bundles must return the runner error")
	}
}

func TestNoIdentityIsError(t *testing.T) {
	c := checker(&fake{answers: goldenAnswers(t)}, "2026-10-17T12:00:00Z")
	if o := c.Check(context.Background(), ref, SBOM, nil, nil); o.Status != Error {
		t.Errorf("outcome = %+v", o)
	}
}

func TestWithoutBundlesTheVerdictStandsButEvidenceIsMissing(t *testing.T) {
	c := checker(&fake{answers: goldenAnswers(t)}, "2026-10-17T12:00:00Z")
	o := c.Check(context.Background(), ref, SBOM, []Identity{pinned}, nil)
	if o.Status != Pass || len(o.Attestations) != 1 || o.Attestations[0].Binding != "none" || o.Attestations[0].Rekor != nil {
		t.Errorf("outcome = %+v", o)
	}
}

func TestAttestationAboutAnotherDigestFails(t *testing.T) {
	c := checker(&fake{answers: goldenAnswers(t)}, "2026-10-17T12:00:00Z")
	other := "ghcr.io/taha7486/forge-spike-r1@sha256:" + strings.Repeat("0", 64)
	o := c.Check(context.Background(), other, SBOM, []Identity{pinned}, nil)
	if o.Status != Fail || !strings.Contains(o.Detail, "another digest") {
		t.Errorf("outcome = %+v", o)
	}
	o = c.Check(context.Background(), other, Signature, []Identity{pinned}, nil)
	if o.Status != Fail || !strings.Contains(o.Detail, "signature payload names") {
		t.Errorf("outcome = %+v", o)
	}
}

func envLine(statement string) []byte {
	return []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"` + base64.StdEncoding.EncodeToString([]byte(statement)) + `","signatures":[{"sig":"x"}]}` + "\n")
}

func TestPredicateContentIsChecked(t *testing.T) {
	sub := `"subject":[{"name":"x","digest":{"sha256":"` + strings.TrimPrefix(digest, "sha256:") + `"}}]`
	for name, tc := range map[string]struct {
		kind Kind
		pred string
		st   string
	}{
		"sbom not cyclonedx":  {SBOM, PredSBOM, `{"_type":"x",` + sub + `,"predicateType":"` + PredSBOM + `","predicate":{"bomFormat":"SPDX"}}`},
		"sbom without format": {SBOM, PredSBOM, `{"_type":"x",` + sub + `,"predicateType":"` + PredSBOM + `","predicate":{}}`},
		"vuln no scan time":   {Vuln, PredVuln, `{"_type":"x",` + sub + `,"predicateType":"` + PredVuln + `","predicate":{"metadata":{}}}`},
		"vuln bad scan time":  {Vuln, PredVuln, `{"_type":"x",` + sub + `,"predicateType":"` + PredVuln + `","predicate":{"metadata":{"scanFinishedOn":"yesterday"}}}`},
		"wrong predicate":     {SBOM, PredSBOM, `{"_type":"x",` + sub + `,"predicateType":"https://example.com/p","predicate":{}}`},
	} {
		a := map[string]Result{"verify-attestation " + tc.pred + "|" + pinned.Subject: {Stdout: envLine(tc.st)}}
		c := checker(&fake{answers: a}, "2026-10-17T12:00:00Z")
		if o := c.Check(context.Background(), ref, tc.kind, []Identity{pinned}, nil); o.Status != Fail {
			t.Errorf("%s: %+v", name, o)
		}
	}
}

func TestUnpinnedRefLearnsTheDigest(t *testing.T) {
	c := checker(&fake{answers: goldenAnswers(t)}, "2026-10-17T12:00:00Z")
	tag := "ghcr.io/taha7486/forge-spike-r1:golden"
	for _, k := range []Kind{Signature, SBOM, Vuln} {
		if o := c.Check(context.Background(), tag, k, []Identity{pinned}, nil); o.Status != Pass || o.Digest != digest {
			t.Errorf("%s: %+v", k, o)
		}
	}
}

func TestExecRunner(t *testing.T) {
	r := Exec{Path: "sh", Timeout: 5 * time.Second}
	res, err := r.Run(context.Background(), "-c", "echo out; echo err >&2; exit 3")
	if err != nil || res.ExitCode != 3 || strings.TrimSpace(string(res.Stdout)) != "out" || strings.TrimSpace(string(res.Stderr)) != "err" {
		t.Errorf("res=%+v err=%v", res, err)
	}
	if _, err := (Exec{Path: "sh", Timeout: 100 * time.Millisecond}).Run(context.Background(), "-c", "sleep 5"); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v", err)
	}
	if _, err := (Exec{Path: "/nonexistent/cosign"}).Run(context.Background(), "version"); err == nil {
		t.Error("a missing binary must be an error")
	}
}

func TestCheckpointValuesWinOverProofFields(t *testing.T) {
	c := checker(&fake{answers: goldenAnswers(t)}, "2026-10-17T12:00:00Z")
	b := bundles(t, c)[0]
	b.VerificationMaterial.TlogEntries[0].InclusionProof.TreeSize = "2926384040" // tampered; cosign still accepted +1 in the tamper test
	r := b.Rekor()
	if r.TreeSize != "2926384039" || r.ProofMatchesCheckpoint == nil || *r.ProofMatchesCheckpoint {
		t.Errorf("rekor = %+v", r)
	}
	b.VerificationMaterial.TlogEntries[0].InclusionProof.Checkpoint = nil
	if r := b.Rekor(); r.TreeSize != "2926384040" || r.ProofMatchesCheckpoint != nil {
		t.Errorf("without a checkpoint the proof fields are used: %+v", r)
	}
	for _, bad := range []string{"", "origin\n", "origin\nnotanumber\nroot\n\nsig", "origin\n5\n\n\nsig"} {
		if _, _, ok := parseCheckpoint(bad); ok {
			t.Errorf("parseCheckpoint(%q) must fail", bad)
		}
	}
}

// flaky fails the first n calls with a network error, then answers like fake.
type flaky struct {
	fake
	failFirst int
	n         int
}

func (f *flaky) Run(ctx context.Context, args ...string) (Result, error) {
	f.n++
	if f.n <= f.failFirst {
		return Result{ExitCode: 1, Stderr: []byte("Error: getting trusted root from TUF: dial tcp: network is unreachable")}, nil
	}
	return f.fake.Run(ctx, args...)
}

func TestErrorIsRetriedButFailIsNot(t *testing.T) {
	f := &flaky{fake: fake{answers: goldenAnswers(t)}, failFirst: 1}
	c := checker(f, "2026-10-17T12:00:00Z")
	c.Retries = 1
	if o := c.Check(context.Background(), ref, SBOM, []Identity{pinned}, nil); o.Status != Pass || f.n != 2 {
		t.Errorf("one retry must rescue a one-off error: %+v after %d calls", o, f.n)
	}
	f = &flaky{fake: fake{answers: goldenAnswers(t)}, failFirst: 5}
	c = checker(f, "2026-10-17T12:00:00Z")
	c.Retries = 2
	if o := c.Check(context.Background(), ref, SBOM, []Identity{pinned}, nil); o.Status != Error || f.n != 3 {
		t.Errorf("an error that stays is ERROR after 1+2 calls: %+v after %d calls", o, f.n)
	}
	// A FAIL is a verdict: asking again would not change it.
	other := Identity{Subject: "https://example.com/other", Issuer: pinned.Issuer}
	f = &flaky{fake: fake{answers: goldenAnswers(t)}}
	c = checker(f, "2026-10-17T12:00:00Z")
	c.Retries = 3
	if o := c.Check(context.Background(), ref, SBOM, []Identity{other}, nil); o.Status != Fail || f.n != 1 {
		t.Errorf("FAIL must not be retried: %+v after %d calls", o, f.n)
	}
	// Bundles are retried too.
	f = &flaky{fake: fake{answers: goldenAnswers(t)}, failFirst: 1}
	c = checker(f, "2026-10-17T12:00:00Z")
	c.Retries = 1
	if b, err := c.Bundles(context.Background(), ref); err != nil || len(b) != 5 || f.n != 2 {
		t.Errorf("bundles: %d, %v after %d calls", len(b), err, f.n)
	}
}
