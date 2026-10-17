// Package report evaluates policies and PolicyReports into a control-by-control report.
package report

import "github.com/Taha7486/conformity/internal/catalog"

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
	SchemaVersion string        `json:"schemaVersion"`
	GeneratedAt   string        `json:"generatedAt"`
	Tool          string        `json:"tool"`
	Source        string        `json:"source"`
	Summary       Summary       `json:"summary"`
	Controls      []ControlRow  `json:"controls"`
	Policies      []PolicyInfo  `json:"policies"`
	Unmapped      []string      `json:"policiesWithoutControls"`
	Scope         Scope         `json:"scope"`
	Gaps          []string      `json:"knownGaps"`
	Inputs        []InputDigest `json:"inputs"`
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
	Status   string    `json:"status"`
	Policies []string  `json:"policies"`
	Counts   Counts    `json:"counts"`
	Findings []Finding `json:"findings,omitempty"`
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
}
