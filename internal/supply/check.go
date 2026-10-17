package supply

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Predicate types of the attestations the Forge factory writes (ADR-001).
const (
	PredSBOM = "https://cyclonedx.org/bom"
	PredVuln = "https://cosign.sigstore.dev/attestation/vuln/v1"
	PredSign = "https://sigstore.dev/cosign/sign/v1"
)

// Kind is what a check proves about an image.
type Kind string

const (
	Signature Kind = "signature" // a valid keyless signature from the pinned identity
	SBOM      Kind = "sbom"      // a verified CycloneDX SBOM attestation
	Vuln      Kind = "vuln"      // a verified vulnerability scan attestation, fresh enough
)

// Status of a check. Error means cosign could not decide (network, registry, TUF); it is
// not a verdict on the image.
const (
	Pass  = "PASS"
	Fail  = "FAIL"
	Error = "ERROR"
)

// Identity is an exact signer identity, as in a Kyverno keyless attestor.
type Identity struct {
	Subject string
	Issuer  string
}

// Attestation is one verified signature or attestation with its evidence.
type Attestation struct {
	PredicateType  string    `json:"predicateType"`
	Signer         *CertInfo `json:"signer,omitempty"`
	Rekor          *Rekor    `json:"rekor,omitempty"`
	ScanFinishedOn string    `json:"scanFinishedOn,omitempty"`
	// Binding says how the Rekor entry was tied to what cosign verified: "dsse-signature"
	// (the verified envelope and the bundle carry the same signature) or
	// "certificate-identity" (a bundle of the right type and subject whose certificate has the
	// pinned identity; used for signatures, where cosign verify prints no envelope) or "none"
	// (no matching bundle was found).
	Binding string `json:"binding"`
}

// Outcome is the verdict of one check on one image.
type Outcome struct {
	Status       string        `json:"status"`
	Detail       string        `json:"detail,omitempty"`
	Digest       string        `json:"digest,omitempty"`
	Attestations []Attestation `json:"attestations,omitempty"`
	// Vuln checks only: age of the newest verified scan and the limit.
	NewestScanAge string `json:"newestScanAge,omitempty"`
	MaxScanAge    string `json:"maxScanAge,omitempty"`
}

// Checker runs the checks.
type Checker struct {
	Runner     Runner
	Now        time.Time
	MaxScanAge time.Duration
	// Retries is how many times a call that ended in ERROR is repeated (network and TUF
	// hiccups are common), RetryDelay apart. A FAIL is never retried.
	Retries    int
	RetryDelay time.Duration
}

func (c *Checker) wait(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(c.RetryDelay):
	}
}

// Bundles downloads the bundles attached to an image. They are NOT verified; they only
// supply the certificate and Rekor evidence for what cosign verify-attestation accepted.
func (c *Checker) Bundles(ctx context.Context, ref string) ([]Bundle, error) {
	var res Result
	var err error
	for attempt := 0; ; attempt++ {
		res, err = c.Runner.Run(ctx, "download", "attestation", ref)
		if (err == nil && res.ExitCode == 0) || attempt >= c.Retries {
			break
		}
		c.wait(ctx)
	}
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("cosign download attestation: %s", firstError(res.Stderr))
	}
	return ParseLines[Bundle](res.Stdout)
}

// Check runs one check against ref with any of the identities. bundles may be nil. An ERROR
// is retried up to Retries times.
func (c *Checker) Check(ctx context.Context, ref string, kind Kind, ids []Identity, bundles []Bundle) Outcome {
	o := c.check(ctx, ref, kind, ids, bundles)
	for attempt := 0; o.Status == Error && attempt < c.Retries; attempt++ {
		c.wait(ctx)
		o = c.check(ctx, ref, kind, ids, bundles)
	}
	return o
}

func (c *Checker) check(ctx context.Context, ref string, kind Kind, ids []Identity, bundles []Bundle) Outcome {
	if len(ids) == 0 {
		return Outcome{Status: Error, Detail: "no signer identity to check against"}
	}
	var firstFail, firstErr *Outcome
	for _, id := range ids {
		var o Outcome
		switch kind {
		case Signature:
			o = c.checkSignature(ctx, ref, id, bundles)
		case SBOM:
			o = c.checkAttestation(ctx, ref, id, PredSBOM, kind, bundles)
		case Vuln:
			o = c.checkAttestation(ctx, ref, id, PredVuln, kind, bundles)
		default:
			return Outcome{Status: Error, Detail: fmt.Sprintf("unknown check %q", kind)}
		}
		switch o.Status {
		case Pass:
			return o
		case Error:
			if firstErr == nil {
				o := o
				firstErr = &o
			}
		default:
			if firstFail == nil {
				o := o
				firstFail = &o
			}
		}
	}
	if firstErr != nil { // cannot conclude: an error outranks a failure
		return *firstErr
	}
	return *firstFail
}

func identityArgs(id Identity) []string {
	return []string{"--certificate-identity", id.Subject, "--certificate-oidc-issuer", id.Issuer}
}

// Classify turns a failed cosign run into FAIL (cosign looked and found the evidence
// missing or wrong) or ERROR (cosign could not look).
func Classify(res Result) (status, detail string) {
	e := string(res.Stderr)
	for _, marker := range []string{"no matching attestations", "none of the attestations matched the predicate type", "no signatures found"} {
		if strings.Contains(e, marker) {
			return Fail, firstError(res.Stderr)
		}
	}
	return Error, firstError(res.Stderr)
}

func (c *Checker) checkSignature(ctx context.Context, ref string, id Identity, bundles []Bundle) Outcome {
	args := append([]string{"verify"}, identityArgs(id)...)
	res, err := c.Runner.Run(ctx, append(args, ref)...)
	if err != nil {
		return Outcome{Status: Error, Detail: err.Error()}
	}
	if res.ExitCode != 0 {
		s, d := Classify(res)
		return Outcome{Status: s, Detail: d}
	}
	var payloads []struct {
		Critical struct {
			Image struct {
				Digest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
	}
	if err := json.Unmarshal(res.Stdout, &payloads); err != nil || len(payloads) == 0 {
		return Outcome{Status: Error, Detail: "cosign verify succeeded but printed no signature payloads"}
	}
	digest := payloads[0].Critical.Image.Digest
	want := digestOf(ref)
	if want != "" && digest != want {
		return Outcome{Status: Fail, Digest: digest, Detail: fmt.Sprintf("signature payload names %s, not %s", digest, want)}
	}
	o := Outcome{Status: Pass, Digest: digest}
	for i := range bundles {
		b := &bundles[i]
		st, err := b.DSSE.Statement()
		if err != nil || st.PredicateType != PredSign || !st.HasDigest(digest) {
			continue
		}
		cert, err := b.Cert()
		if err != nil || cert.Subject != id.Subject || cert.Issuer != id.Issuer {
			continue
		}
		o.Attestations = append(o.Attestations, Attestation{PredicateType: PredSign, Signer: cert, Rekor: b.Rekor(), Binding: "certificate-identity"})
	}
	return o
}

func (c *Checker) checkAttestation(ctx context.Context, ref string, id Identity, pred string, kind Kind, bundles []Bundle) Outcome {
	args := append([]string{"verify-attestation", "--type", pred}, identityArgs(id)...)
	res, err := c.Runner.Run(ctx, append(args, ref)...)
	if err != nil {
		return Outcome{Status: Error, Detail: err.Error()}
	}
	if res.ExitCode != 0 {
		s, d := Classify(res)
		return Outcome{Status: s, Detail: d}
	}
	envs, err := ParseLines[Envelope](res.Stdout)
	if err != nil || len(envs) == 0 {
		return Outcome{Status: Error, Detail: "cosign verify-attestation succeeded but printed no attestation"}
	}
	bySig := map[string]*Bundle{}
	for i := range bundles {
		if s := bundles[i].DSSE.firstSig(); s != "" {
			bySig[s] = &bundles[i]
		}
	}
	o := Outcome{Status: Pass}
	var newest time.Time
	var problems []string
	for _, env := range envs {
		st, err := env.Statement()
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if st.PredicateType != pred {
			problems = append(problems, "predicate type "+st.PredicateType)
			continue
		}
		digest := sha256Of(st)
		if want := digestOf(ref); want != "" && !st.HasDigest(want) {
			problems = append(problems, "attestation is about another digest than "+want)
			continue
		}
		a := Attestation{PredicateType: pred, Binding: "none"}
		switch kind {
		case SBOM:
			var p struct {
				BomFormat string `json:"bomFormat"`
			}
			if json.Unmarshal(st.Predicate, &p) != nil || p.BomFormat != "CycloneDX" {
				problems = append(problems, "SBOM predicate is not CycloneDX")
				continue
			}
		case Vuln:
			var p struct {
				Metadata struct {
					ScanFinishedOn string `json:"scanFinishedOn"`
				} `json:"metadata"`
			}
			if json.Unmarshal(st.Predicate, &p) != nil {
				problems = append(problems, "vulnerability predicate is not readable")
				continue
			}
			t, err := time.Parse(time.RFC3339Nano, p.Metadata.ScanFinishedOn)
			if err != nil {
				problems = append(problems, "scanFinishedOn missing or not a time: "+p.Metadata.ScanFinishedOn)
				continue
			}
			a.ScanFinishedOn = t.UTC().Format(time.RFC3339)
			if t.After(newest) {
				newest = t
			}
		}
		if b := bySig[env.firstSig()]; b != nil && b.DSSE.Payload == env.Payload {
			a.Rekor, a.Binding = b.Rekor(), "dsse-signature"
			a.Signer, _ = b.Cert()
		}
		if o.Digest == "" {
			o.Digest = digest
		}
		o.Attestations = append(o.Attestations, a)
	}
	if len(o.Attestations) == 0 {
		return Outcome{Status: Fail, Detail: "no usable attestation: " + strings.Join(problems, "; ")}
	}
	if kind == Vuln {
		age := c.Now.Sub(newest)
		o.NewestScanAge, o.MaxScanAge = age.Round(time.Minute).String(), c.MaxScanAge.String()
		if age > c.MaxScanAge {
			o.Status = Fail
			o.Detail = fmt.Sprintf("newest verified scan finished %s ago, limit %s", o.NewestScanAge, o.MaxScanAge)
		}
	}
	sort.SliceStable(o.Attestations, func(i, j int) bool { return o.Attestations[i].ScanFinishedOn > o.Attestations[j].ScanFinishedOn })
	return o
}

// digestOf returns "sha256:..." from a reference with a digest, else "".
func digestOf(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[i+1:]
	}
	return ""
}

func sha256Of(s *Statement) string {
	for _, sub := range s.Subject {
		if v, ok := sub.Digest["sha256"]; ok {
			return "sha256:" + v
		}
	}
	return ""
}

// firstError returns the first "Error:" line of cosign's stderr, or the first line.
func firstError(stderr []byte) string {
	lines := strings.Split(strings.TrimSpace(string(stderr)), "\n")
	pick := ""
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Error:") {
			pick = strings.TrimSpace(strings.TrimPrefix(l, "Error:"))
			break
		}
	}
	if pick == "" && len(lines) > 0 {
		pick = strings.TrimSpace(lines[0])
	}
	if pick == "" {
		pick = "no message from cosign"
	}
	if len(pick) > 300 {
		pick = pick[:300] + "..."
	}
	return pick
}
