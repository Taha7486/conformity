package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Taha7486/conformity/internal/catalog"
	"github.com/Taha7486/conformity/internal/source"
	"github.com/Taha7486/conformity/internal/supply"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Options control an evaluation.
type Options struct {
	Now  time.Time
	Tool string
	// Cosign runs the image checks (signature, SBOM, vulnerability scan). Nil skips them, and
	// the report then rests on the PolicyReports alone.
	Cosign     supply.Runner
	MaxScanAge time.Duration // default 720h, the window of the ecr-vuln policy
	Retries    int           // repeat a cosign call that ended in ERROR this many times
	RetryDelay time.Duration
	Progress   func(msg string) // optional, called before each slow step
}

// Evaluate builds the report from the PolicyReports alone (no image checks).
func Evaluate(snap *source.Snapshot, now time.Time, tool string) (*Report, error) {
	return EvaluateWith(context.Background(), snap, Options{Now: now, Tool: tool})
}

// EvaluateWith builds the report. It fails (rather than guess) when a policy has an
// annotation it cannot parse, or when a report document cannot be read.
func EvaluateWith(ctx context.Context, snap *source.Snapshot, opt Options) (*Report, error) {
	policies, unmapped, err := readPolicies(snap.Policies)
	if err != nil {
		return nil, err
	}
	results, scope, err := readResults(snap.Reports)
	if err != nil {
		return nil, err
	}
	scope.DocumentsIgnored = snap.Ignored

	byPolicy := map[string][]result{}
	for _, r := range results {
		byPolicy[r.Policy] = append(byPolicy[r.Policy], r)
	}
	mapped := map[string]bool{}
	for _, p := range policies {
		mapped[p.Name] = true
	}
	for name, rs := range byPolicy {
		if !mapped[name] {
			scope.ResultsNoPolicy += len(rs)
		}
	}

	// control key -> policies enforcing it
	controls := map[string]catalog.Control{}
	owners := map[string][]string{}
	for _, p := range policies {
		for _, c := range p.controls {
			controls[c.Key()] = c
			owners[c.Key()] = append(owners[c.Key()], p.Name)
		}
	}
	var ordered []catalog.Control
	for _, c := range controls {
		ordered = append(ordered, c)
	}
	catalog.Sort(ordered)

	rep := &Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   opt.Now.UTC().Format(time.RFC3339),
		Tool:          opt.Tool,
		Source:        snap.Origin,
		Scope:         scope,
		Gaps:          KnownGaps,
		Unmapped:      unmapped,
	}
	rows := map[string]*ControlRow{}
	for _, c := range ordered {
		row := ControlRow{Control: c, Policies: owners[c.Key()]}
		sort.Strings(row.Policies)
		for _, pn := range row.Policies {
			for _, r := range byPolicy[pn] {
				row.Counts.add(r.Result)
				if bad(r.Result) {
					row.Findings = append(row.Findings, Finding{Policy: r.Policy, Rule: r.Rule,
						Result: r.Result, Resource: r.Resource, Message: r.Message})
				}
			}
		}
		rep.Controls = append(rep.Controls, row)
	}
	for i := range rep.Controls {
		rows[rep.Controls[i].Key()] = &rep.Controls[i]
	}
	for _, p := range policies {
		info := p.PolicyInfo
		for _, c := range p.controls {
			info.Controls = append(info.Controls, c.Key())
		}
		rep.Policies = append(rep.Policies, info)
	}
	sort.Slice(rep.Policies, func(i, j int) bool { return rep.Policies[i].Name < rep.Policies[j].Name })

	var usedPods []*unstructured.Unstructured
	if opt.Cosign != nil {
		usedPods, err = checkImages(ctx, rep, rows, policies, results, snap, opt)
		if err != nil {
			return nil, err
		}
	} else {
		skipImageControls(rep)
	}

	for i := range rep.Controls {
		row := &rep.Controls[i]
		sort.Slice(row.Findings, func(a, b int) bool {
			x, y := row.Findings[a], row.Findings[b]
			if x.Resource != y.Resource {
				return x.Resource < y.Resource
			}
			if x.Policy != y.Policy {
				return x.Policy < y.Policy
			}
			return x.Rule < y.Rule
		})
		row.Status = status(row.Counts, row.ImageChecks)
		rep.Summary.Controls++
		switch row.Status {
		case StatusPass:
			rep.Summary.Pass++
		case StatusFail:
			rep.Summary.Fail++
		case StatusSkip:
			rep.Summary.Skipped++
		default:
			rep.Summary.NoData++
		}
	}

	rep.Inputs, err = digests(snap.Policies, snap.Reports, usedPods)
	if err != nil {
		return nil, err
	}
	rep.InputsSHA256 = aggregate(rep.Inputs)
	return rep, nil
}

// bad is true for results that stop a control from passing. warn and error count: a
// control cannot be called passing when a check warned or could not be evaluated.
func bad(r string) bool { return r == "fail" || r == "warn" || r == "error" }

func (c *Counts) add(r string) {
	switch r {
	case "pass":
		c.Pass++
	case "fail":
		c.Fail++
	case "warn":
		c.Warn++
	case "error":
		c.Error++
	case "skip":
		c.Skip++
	}
}

func status(c Counts, ic *ImageCounts) string {
	var imgBad, imgPass int
	if ic != nil {
		imgBad, imgPass = ic.Fail+ic.Error, ic.Pass
	}
	switch {
	case c.Fail+c.Warn+c.Error+imgBad > 0:
		return StatusFail
	case c.Pass+imgPass > 0:
		return StatusPass
	case c.Skip > 0:
		return StatusSkip
	default:
		return StatusNoData
	}
}

type policy struct {
	PolicyInfo
	controls []catalog.Control
	obj      *unstructured.Unstructured
}

func readPolicies(docs []*unstructured.Unstructured) ([]policy, []string, error) {
	var out []policy
	var unmapped []string
	var errs []string
	seen := map[string]bool{}
	for _, d := range docs {
		name := d.GetName()
		if seen[name] {
			errs = append(errs, fmt.Sprintf("policy %q appears twice", name))
			continue
		}
		seen[name] = true
		ann := d.GetAnnotations()[catalog.Annotation]
		if ann == "" {
			unmapped = append(unmapped, name)
			continue
		}
		cs, err := catalog.Parse(ann)
		if err != nil {
			errs = append(errs, fmt.Sprintf("policy %q, annotation %s: %v", name, catalog.Annotation, err))
			continue
		}
		info := PolicyInfo{Name: name, Kind: d.GetKind(), Title: d.GetAnnotations()["policies.kyverno.io/title"]}
		info.Ready, _, _ = unstructured.NestedBool(d.Object, "status", "conditionStatus", "ready")
		info.Actions, _, _ = unstructured.NestedStringSlice(d.Object, "spec", "validationActions")
		info.ExcludedNamespaces = excludedNamespaces(d)
		out = append(out, policy{PolicyInfo: info, controls: cs, obj: d})
	}
	if len(errs) > 0 {
		return nil, nil, fmt.Errorf("cannot build the control catalog:\n  %s", strings.Join(errs, "\n  "))
	}
	sort.Strings(unmapped)
	return out, unmapped, nil
}

// excludedNamespaces reads the namespaces a policy leaves out: a NotIn rule on
// kubernetes.io/metadata.name in matchConstraints.namespaceSelector.
func excludedNamespaces(d *unstructured.Unstructured) []string {
	exprs, _, _ := unstructured.NestedSlice(d.Object, "spec", "matchConstraints", "namespaceSelector", "matchExpressions")
	var out []string
	for _, e := range exprs {
		m, ok := e.(map[string]interface{})
		if !ok || m["key"] != "kubernetes.io/metadata.name" || m["operator"] != "NotIn" {
			continue
		}
		vals, _ := m["values"].([]interface{})
		for _, v := range vals {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

type result struct {
	Policy, Rule, Result, Message, Resource string
}

// wire form of a PolicyReport (wgpolicyk8s.io/v1alpha2); only the fields used.
type wireReport struct {
	Scope   *wireRef `json:"scope"`
	Results []struct {
		Policy    string    `json:"policy"`
		Rule      string    `json:"rule"`
		Result    string    `json:"result"`
		Message   string    `json:"message"`
		Resources []wireRef `json:"resources"`
		Timestamp struct {
			Seconds int64 `json:"seconds"`
		} `json:"timestamp"`
	} `json:"results"`
}

type wireRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

func (r wireRef) String() string {
	if r.Namespace != "" {
		return fmt.Sprintf("%s %s/%s", r.Kind, r.Namespace, r.Name)
	}
	return fmt.Sprintf("%s %s", r.Kind, r.Name)
}

func readResults(docs []*unstructured.Unstructured) ([]result, Scope, error) {
	var out []result
	scope := Scope{Reports: len(docs)}
	resources := map[string]bool{}
	var oldest, newest int64
	for _, d := range docs {
		b, err := json.Marshal(d.Object)
		if err != nil {
			return nil, scope, err
		}
		var w wireReport
		if err := json.Unmarshal(b, &w); err != nil {
			return nil, scope, fmt.Errorf("report %s/%s: %w", d.GetNamespace(), d.GetName(), err)
		}
		for _, r := range w.Results {
			ref := wireRef{}
			switch {
			case len(r.Resources) > 0:
				ref = r.Resources[0]
			case w.Scope != nil:
				ref = *w.Scope
			default:
				return nil, scope, fmt.Errorf("report %s/%s: result of policy %q names no resource", d.GetNamespace(), d.GetName(), r.Policy)
			}
			switch r.Result {
			case "pass", "fail", "warn", "error", "skip":
			default:
				return nil, scope, fmt.Errorf("report %s/%s: unknown result value %q", d.GetNamespace(), d.GetName(), r.Result)
			}
			key := ref.UID
			if key == "" {
				key = ref.String()
			}
			resources[key] = true
			if t := r.Timestamp.Seconds; t > 0 {
				if oldest == 0 || t < oldest {
					oldest = t
				}
				if t > newest {
					newest = t
				}
			}
			out = append(out, result{Policy: r.Policy, Rule: r.Rule, Result: r.Result, Message: r.Message, Resource: ref.String()})
		}
	}
	scope.Results = len(out)
	scope.ResourcesEvaluated = len(resources)
	if oldest > 0 {
		scope.OldestResult = time.Unix(oldest, 0).UTC().Format(time.RFC3339)
		scope.NewestResult = time.Unix(newest, 0).UTC().Format(time.RFC3339)
	}
	return out, scope, nil
}

func digests(groups ...[]*unstructured.Unstructured) ([]InputDigest, error) {
	var out []InputDigest
	for _, group := range groups {
		for _, d := range group {
			h, err := source.Hash(d)
			if err != nil {
				return nil, err
			}
			out = append(out, InputDigest{Kind: d.GetKind(), Namespace: d.GetNamespace(), Name: d.GetName(), SHA256: h})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return out, nil
}

// aggregate is one SHA-256 over the sorted list of inputs ("kind namespace/name sha256" per
// line), so two reports made from the same documents carry the same value.
func aggregate(in []InputDigest) string {
	h := sha256.New()
	for _, d := range in {
		fmt.Fprintf(h, "%s %s/%s %s\n", d.Kind, d.Namespace, d.Name, d.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}
