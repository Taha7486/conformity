package supply

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Live tests run the real cosign against public images on GHCR and Docker Hub. They need
// network access and cosign on PATH, so they only run with CONFORMITY_LIVE=1:
//
//	CONFORMITY_LIVE=1 go test ./internal/supply -run Live -v
//
// The positive cases use the public spike image (see testdata/cosign/README.md). Its
// vulnerability scans date from 2026-10-02, so the freshness cases pass --now explicitly.
func live(t *testing.T) *Checker {
	if os.Getenv("CONFORMITY_LIVE") != "1" {
		t.Skip("set CONFORMITY_LIVE=1 to run against the real cosign and registries")
	}
	n, _ := time.Parse(time.RFC3339, "2026-10-17T12:00:00Z")
	return &Checker{Runner: Exec{Path: "cosign", Timeout: 120 * time.Second}, Now: n, MaxScanAge: 720 * time.Hour}
}

// retry once on ERROR: the TUF CDN and the home network are flaky (see the spike README).
func (c *Checker) retry(ctx context.Context, ref string, k Kind, ids []Identity, b []Bundle) Outcome {
	o := c.Check(ctx, ref, k, ids, b)
	if o.Status == Error {
		o = c.Check(ctx, ref, k, ids, b)
	}
	return o
}

func TestLiveGoldenImage(t *testing.T) {
	c := live(t)
	ctx := context.Background()
	b, err := c.Bundles(ctx, ref)
	if err != nil || len(b) != 5 {
		t.Fatalf("bundles = %d, %v", len(b), err)
	}
	for _, k := range []Kind{Signature, SBOM, Vuln} {
		o := c.retry(ctx, ref, k, []Identity{pinned}, b)
		if o.Status != Pass || o.Digest != digest {
			t.Errorf("%s: %+v", k, o)
		}
		for _, a := range o.Attestations {
			if a.Rekor == nil || a.Signer == nil || a.Signer.Subject != pinned.Subject {
				t.Errorf("%s: evidence missing: %+v", k, a)
			}
			if k != Signature && a.Binding != "dsse-signature" {
				t.Errorf("%s: binding %s", k, a.Binding)
			}
		}
	}
}

func TestLiveTagResolvesToTheSameDigest(t *testing.T) {
	c := live(t)
	o := c.retry(context.Background(), "ghcr.io/taha7486/forge-spike-r1:golden", SBOM, []Identity{pinned}, nil)
	if o.Status != Pass || o.Digest != digest {
		t.Errorf("%+v", o)
	}
}

func TestLiveStaleScan(t *testing.T) {
	c := live(t)
	c.Now, _ = time.Parse(time.RFC3339, "2026-12-01T00:00:00Z")
	o := c.retry(context.Background(), ref, Vuln, []Identity{pinned}, nil)
	if o.Status != Fail || len(o.Attestations) != 2 {
		t.Errorf("%+v", o)
	}
}

func TestLiveWrongIdentities(t *testing.T) {
	c := live(t)
	ctx := context.Background()
	lookalike := Identity{Subject: "https://github.com/Taha7486/forge-spike-r1-lookalike/.github/workflows/r1-sign-golden.yml@refs/heads/main", Issuer: pinned.Issuer}
	wrongIssuer := Identity{Subject: pinned.Subject, Issuer: "https://accounts.google.com"}
	for name, id := range map[string]Identity{"lookalike repo": lookalike, "right subject, wrong issuer": wrongIssuer} {
		for _, k := range []Kind{Signature, SBOM, Vuln} {
			if o := c.retry(ctx, ref, k, []Identity{id}, nil); o.Status != Fail {
				t.Errorf("%s / %s: %+v", name, k, o)
			}
		}
	}
}

// An image signed by somebody else (upstream podinfo has its own keyless signature) and an image
// with no signature at all are both a plain failure for the pinned identity.
func TestLiveOtherSignerAndUnsigned(t *testing.T) {
	c := live(t)
	ctx := context.Background()
	for _, img := range []string{"ghcr.io/stefanprodan/podinfo:6.15.0", "docker.io/library/alpine:3.20"} {
		for _, k := range []Kind{Signature, SBOM, Vuln} {
			if o := c.retry(ctx, img, k, []Identity{pinned}, nil); o.Status != Fail {
				t.Errorf("%s / %s: %+v", img, k, o)
			}
		}
	}
}

func TestLiveRegistryTroubleIsError(t *testing.T) {
	c := live(t)
	ctx := context.Background()
	for _, img := range []string{"ghcr.io/taha7486/forge-spike-r1:does-not-exist", "no-such-registry.invalid/x/y@" + digest} {
		if o := c.Check(ctx, img, SBOM, []Identity{pinned}, nil); o.Status != Error {
			t.Errorf("%s: %+v", img, o)
		}
	}
}

// What does "cosign verified the log inclusion offline" mean? This test hands the real cosign a
// local copy of a real bundle (cosign verify-blob-attestation --bundle) after changing one thing
// at a time. The untouched copy must pass, every change must be refused. Findings of
// 2026-10-17 are in the README ("What cosign checks").
func TestLiveCosignRejectsTamperedRekorEvidence(t *testing.T) {
	c := live(t)
	ctx := context.Background()
	bs, err := c.Bundles(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	var sbom *Bundle
	for i := range bs {
		if st, err := bs[i].DSSE.Statement(); err == nil && st.PredicateType == PredSBOM {
			sbom = &bs[i]
		}
	}
	if sbom == nil {
		t.Fatal("no SBOM bundle on the golden image")
	}
	// Tamper with the raw JSON of the real download; Bundle only models part of the file.
	res, err := c.Runner.Run(ctx, "download", "attestation", ref)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	for _, line := range bytes.Split(res.Stdout, []byte("\n")) {
		var d map[string]interface{}
		if json.Unmarshal(line, &d) == nil {
			if env, _ := d["dsseEnvelope"].(map[string]interface{}); env != nil && env["payload"] == sbom.DSSE.Payload {
				doc = d
			}
		}
	}
	if doc == nil {
		t.Fatal("SBOM bundle not found in the raw download")
	}
	entry := func(d map[string]interface{}) map[string]interface{} {
		return d["verificationMaterial"].(map[string]interface{})["tlogEntries"].([]interface{})[0].(map[string]interface{})
	}
	flip := func(s string) string {
		i := len(s) / 2
		r := []byte(s)
		if r[i] == 'A' {
			r[i] = 'B'
		} else {
			r[i] = 'A'
		}
		return string(r)
	}
	cases := []struct {
		name   string
		want   bool // true: cosign must accept
		tamper func(d map[string]interface{})
	}{
		{"untouched", true, func(d map[string]interface{}) {}},
		{"proof root hash", false, func(d map[string]interface{}) {
			p := entry(d)["inclusionProof"].(map[string]interface{})
			p["rootHash"] = flip(p["rootHash"].(string))
		}},
		{"proof path hash", false, func(d map[string]interface{}) {
			p := entry(d)["inclusionProof"].(map[string]interface{})
			h := p["hashes"].([]interface{})
			h[0] = flip(h[0].(string))
		}},
		{"checkpoint root", false, func(d map[string]interface{}) {
			p := entry(d)["inclusionProof"].(map[string]interface{})["checkpoint"].(map[string]interface{})
			lines := strings.Split(p["envelope"].(string), "\n")
			lines[2] = flip(lines[2])
			p["envelope"] = strings.Join(lines, "\n")
		}},
		{"signed entry timestamp", false, func(d map[string]interface{}) {
			p := entry(d)["inclusionPromise"].(map[string]interface{})
			p["signedEntryTimestamp"] = flip(p["signedEntryTimestamp"].(string))
		}},
		{"integrated time", false, func(d map[string]interface{}) { entry(d)["integratedTime"] = "1790917451" }},
		{"log index", false, func(d map[string]interface{}) { entry(d)["logIndex"] = "3048288703" }},
		{"no log entry", false, func(d map[string]interface{}) {
			d["verificationMaterial"].(map[string]interface{})["tlogEntries"] = []interface{}{}
		}},
		{"signed payload", false, func(d map[string]interface{}) {
			env := d["dsseEnvelope"].(map[string]interface{})
			env["payload"] = flip(env["payload"].(string))
		}},
	}
	dir := t.TempDir()
	blob := filepath.Join(dir, "blob.txt")
	if err := os.WriteFile(blob, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		b, _ := json.Marshal(doc)
		var d map[string]interface{}
		_ = json.Unmarshal(b, &d) // deep copy
		tc.tamper(d)
		out, _ := json.Marshal(d)
		path := filepath.Join(dir, "bundle.json")
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		// --check-claims=false only skips comparing the statement's subject with the blob.
		r, err := c.Runner.Run(ctx, "verify-blob-attestation", "--bundle", path, "--check-claims=false",
			"--certificate-identity", pinned.Subject, "--certificate-oidc-issuer", pinned.Issuer, "--type", PredSBOM, blob)
		if err != nil {
			t.Fatal(err)
		}
		if accepted := r.ExitCode == 0; accepted != tc.want {
			t.Errorf("%s: accepted=%v, want %v (%s)", tc.name, accepted, tc.want, firstError(r.Stderr))
		}
	}
}
