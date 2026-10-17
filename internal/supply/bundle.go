package supply

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Bundle is the part of a Sigstore bundle (v0.3) that the report uses.
type Bundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		Certificate struct {
			RawBytes []byte `json:"rawBytes"`
		} `json:"certificate"`
		TlogEntries []TlogEntry `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	DSSE Envelope `json:"dsseEnvelope"`
}

// TlogEntry is one Rekor entry as stored in a bundle.
type TlogEntry struct {
	LogIndex string `json:"logIndex"`
	LogID    struct {
		KeyID string `json:"keyId"`
	} `json:"logId"`
	KindVersion struct {
		Kind    string `json:"kind"`
		Version string `json:"version"`
	} `json:"kindVersion"`
	IntegratedTime   string    `json:"integratedTime"`
	InclusionPromise *struct{} `json:"inclusionPromise"`
	InclusionProof   *struct {
		TreeSize   string `json:"treeSize"`
		RootHash   string `json:"rootHash"`
		Checkpoint *struct {
			Envelope string `json:"envelope"`
		} `json:"checkpoint"`
	} `json:"inclusionProof"`
}

// Envelope is a DSSE envelope, the form cosign prints for an attestation and stores in a bundle.
type Envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		Sig string `json:"sig"`
	} `json:"signatures"`
}

// Statement is an in-toto statement, the payload of an attestation.
type Statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`
}

// Statement decodes the envelope payload.
func (e Envelope) Statement() (*Statement, error) {
	raw, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("payload is not base64: %w", err)
	}
	var s Statement
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("payload is not an in-toto statement: %w", err)
	}
	return &s, nil
}

// HasDigest is true when the statement is about the given digest ("sha256:abc...").
func (s *Statement) HasDigest(digest string) bool {
	for _, sub := range s.Subject {
		for alg, v := range sub.Digest {
			if alg+":"+v == digest {
				return true
			}
		}
	}
	return false
}

// firstSig is the first signature, the key used to match a verified envelope to its bundle.
func (e Envelope) firstSig() string {
	if len(e.Signatures) == 0 {
		return ""
	}
	return e.Signatures[0].Sig
}

// ParseLines reads one JSON document per line (cosign's output for bundles and envelopes).
func ParseLines[T any](b []byte) ([]T, error) {
	var out []T
	for i, line := range bytes.Split(b, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(line, &v); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// CertInfo is what the report shows of a signing certificate.
type CertInfo struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer,omitempty"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

var (
	oidIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// Cert parses the certificate of a bundle: signer identity (the URI or e-mail SAN), the
// OIDC issuer extension and the validity window. Cosign's certificates live ten minutes.
func (b *Bundle) Cert() (*CertInfo, error) {
	der := b.VerificationMaterial.Certificate.RawBytes
	if len(der) == 0 {
		return nil, fmt.Errorf("bundle has no certificate")
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	info := &CertInfo{NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339)}
	switch {
	case len(c.URIs) > 0:
		info.Subject = c.URIs[0].String()
	case len(c.EmailAddresses) > 0:
		info.Subject = c.EmailAddresses[0]
	default:
		return nil, fmt.Errorf("certificate has no URI or e-mail SAN")
	}
	for _, ext := range c.Extensions {
		switch {
		case ext.Id.Equal(oidIssuerV2):
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err == nil {
				info.Issuer = s
			}
		case ext.Id.Equal(oidIssuerV1) && info.Issuer == "":
			info.Issuer = string(ext.Value)
		}
	}
	return info, nil
}

// Rekor is the transparency-log evidence in a bundle. Verified says who checked it.
type Rekor struct {
	LogIndex         string `json:"logIndex"`
	IntegratedTime   string `json:"integratedTime,omitempty"`
	LogID            string `json:"logId"`
	Kind             string `json:"kind"`
	InclusionProof   bool   `json:"inclusionProof"`
	InclusionPromise bool   `json:"inclusionPromise"`
	// TreeSize and RootHash come from the log's signed checkpoint when the bundle has one
	// (cosign checks that signature), else from the proof fields. ProofMatchesCheckpoint is
	// false when the proof's own treeSize or rootHash differ from the checkpoint's. Cosign
	// does not catch every such difference: a treeSize off by a few still verified in tests.
	TreeSize               string `json:"treeSize,omitempty"`
	RootHash               string `json:"rootHash,omitempty"`
	ProofMatchesCheckpoint *bool  `json:"proofMatchesCheckpoint,omitempty"`
}

// Rekor returns the first log entry of the bundle, or nil if it has none.
func (b *Bundle) Rekor() *Rekor {
	if len(b.VerificationMaterial.TlogEntries) == 0 {
		return nil
	}
	t := b.VerificationMaterial.TlogEntries[0]
	r := &Rekor{LogIndex: t.LogIndex, LogID: t.LogID.KeyID, Kind: t.KindVersion.Kind + " " + t.KindVersion.Version,
		InclusionPromise: t.InclusionPromise != nil, InclusionProof: t.InclusionProof != nil}
	if secs, err := strconv.ParseInt(t.IntegratedTime, 10, 64); err == nil && secs > 0 {
		r.IntegratedTime = time.Unix(secs, 0).UTC().Format(time.RFC3339)
	}
	if p := t.InclusionProof; p != nil {
		r.TreeSize, r.RootHash = p.TreeSize, p.RootHash
		if p.Checkpoint != nil {
			if size, root, ok := parseCheckpoint(p.Checkpoint.Envelope); ok {
				match := size == p.TreeSize && root == p.RootHash
				r.TreeSize, r.RootHash, r.ProofMatchesCheckpoint = size, root, &match
			}
		}
	}
	return r
}

// parseCheckpoint reads the tree size and root hash from a signed checkpoint note: the first
// line is the origin, then the size, then the base64 root hash, then a blank line and the
// signatures. The signatures are NOT checked here.
func parseCheckpoint(envelope string) (size, root string, ok bool) {
	lines := strings.Split(envelope, "\n")
	if len(lines) < 4 {
		return "", "", false
	}
	if _, err := strconv.ParseUint(lines[1], 10, 64); err != nil || lines[2] == "" {
		return "", "", false
	}
	return lines[1], lines[2], true
}
