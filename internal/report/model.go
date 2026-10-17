// Package report evaluates policies and PolicyReports into a control-by-control report.
package report

import (
	"github.com/Taha7486/conformity/internal/catalog"
	"github.com/Taha7486/conformity/internal/supply"
)

// SchemaVersion changes when the JSON layout changes in a way a reader would notice.
const SchemaVersion = "1"

// Status of one control.
const (
	StatusPass   = "PASS"
	StatusFail   = "FAIL"
	StatusSkip   = "SKIPPED"
	StatusNoData = "NO DATA"
)

// Report is the whole output. Its JSON form is the contract; field names are stable.
type Report struct {
	SchemaVersion string          `json:"schemaVersion"`
	GeneratedAt   string          `json:"generatedAt"`
	Tool          string          `json:"tool"`
	Cosign        string          `json:"cosignVersion,omitempty"`
	Source        string          `json:"source"`
	Summary       Summary         `json:"summary"`
	Controls      []ControlRow    `json:"controls"`
	Policies      []PolicyInfo    `json:"policies"`
	Unmapped      []string        `json:"policiesWithoutControls"`
	Scope         Scope           `json:"scope"`
	Gaps          []string        `json:"knownGaps"`
	Images        []ImageEvidence `json:"images,omitempty"`
	Disagreements []Disagreement  `json:"disagreements,omitempty"`
	InputsSHA256  string          `json:"inputsSha256"`
	Inputs        []InputDigest   `json:"inputs"`
}

// Summary counts controls by status.
type Summary struct {
	Controls int `json:"controls"`
	Pass     int `json:"pass"`
	Fail     int `json:"fail"`
	Skipped  int `json:"skipped"`
	NoData   int `json:"noData"`
}

// ControlRow is one control with the evidence behind its status.
type ControlRow struct {
	catalog.Control
	Status   string   `json:"status"`
	Policies []string `json:"policies"`
	Counts   Counts   `json:"counts"`
	// ImageChecks counts the independent cosign checks behind a FORGE control (nil otherwise).
	ImageChecks *ImageCounts `json:"imageChecks,omitempty"`
	Findings    []Finding    `json:"findings,omitempty"`
}

// Counts of PolicyReport results, by result value.
type Counts struct {
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Warn  int `json:"warn"`
	Error int `json:"error"`
	Skip  int `json:"skip"`
}

// Finding is one result that stopped a control from passing.
type Finding struct {
	Policy   string `json:"policy"`
	Rule     string `json:"rule,omitempty"`
	Result   string `json:"result"`
	Resource string `json:"resource"`
	Message  string `json:"message,omitempty"`
}

// PolicyInfo describes one policy as read.
type PolicyInfo struct {
	Name               string   `json:"name"`
	Kind               string   `json:"kind"`
	Title              string   `json:"title,omitempty"`
	Controls           []string `json:"controls"`
	Ready              bool     `json:"ready"`
	Actions            []string `json:"validationActions,omitempty"`
	ExcludedNamespaces []string `json:"excludedNamespaces,omitempty"`
}

// Scope says what the results cover, so a reader can judge what is missing.
type Scope struct {
	Reports            int    `json:"reports"`
	Results            int    `json:"results"`
	ResultsNoPolicy    int    `json:"resultsForPoliciesWithoutControls"`
	ResourcesEvaluated int    `json:"resourcesEvaluated"`
	OldestResult       string `json:"oldestResult,omitempty"`
	NewestResult       string `json:"newestResult,omitempty"`
	DocumentsIgnored   int    `json:"documentsIgnored"`
	ImagesFound        int    `json:"imagesFound,omitempty"`
	ImagesChecked      int    `json:"imagesChecked,omitempty"`
	MaxScanAge         string `json:"maxScanAge,omitempty"`
}

// InputDigest identifies one input document by the SHA-256 of its JSON form.
type InputDigest struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
}

// KnownGaps are limits of the evidence that hold whatever the data says. Sources: ADR-002
// decision 9, forge-gitops README.
var KnownGaps = []string{
	"Only controls that a Forge policy enforces appear here. This is not a full CIS Kubernetes Benchmark audit.",
	"Results exist only for resources that exist when the report is made. A pod that was refused at admission leaves no PolicyReport entry.",
	"Ephemeral containers (kubectl debug) are not covered by the pod policies.",
	"A result is as old as the last Kyverno background scan; see the oldest and newest result times.",
	"Namespaces listed as excluded by a policy are not evaluated by it.",
	"Rekor evidence (certificate, log entry, inclusion proof) is verified by cosign, not by conformity; tree size and root hash shown come from the log's signed checkpoint.",
}

// ImageCounts counts independent image checks by status.
type ImageCounts struct {
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Error int `json:"error"`
}

// ImageEvidence is what conformity found out about one image by running cosign.
type ImageEvidence struct {
	Ref    string       `json:"ref"`
	Pinned bool         `json:"pinned"`
	Specs  []string     `json:"specs"`
	UsedBy []string     `json:"usedBy"`
	Checks []ImageCheck `json:"checks"`
	// BundleError is set when the bundles could not be downloaded: the verdicts stand, the
	// certificate and Rekor evidence is missing.
	BundleError string `json:"bundleError,omitempty"`
}

// ImageCheck is one check (a FORGE control of one policy) on one image.
type ImageCheck struct {
	Control string `json:"control"`
	Policy  string `json:"policy"`
	Kind    string `json:"check"`
	supply.Outcome
}

// Disagreement records a pod on which Kyverno's PolicyReport and conformity's own checks give
// different answers for one policy. Kyverno writes one result per policy and pod, so the
// comparison is per policy: Kyverno passes only if all checks of the policy pass.
type Disagreement struct {
	Policy         string            `json:"policy"`
	Resource       string            `json:"resource"`
	Image          string            `json:"image"`
	Kyverno        string            `json:"kyverno"`
	KyvernoMessage string            `json:"kyvernoMessage,omitempty"`
	Conformity     map[string]string `json:"conformity"` // control -> PASS, FAIL or ERROR
}
