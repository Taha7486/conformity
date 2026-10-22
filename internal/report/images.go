package report

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Taha7486/conformity/internal/catalog"
	"github.com/Taha7486/conformity/internal/images"
	"github.com/Taha7486/conformity/internal/source"
	"github.com/Taha7486/conformity/internal/supply"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// The FORGE controls and what each one asks cosign to prove. The IDs are owned by this tool.
var forgeChecks = map[string]supply.Kind{
	"SC-1": supply.Signature,
	"SC-2": supply.SBOM,
	"SC-3": supply.Vuln,
}

// FORGE controls that have no image check: Kyverno's PolicyReport results are the whole
// evidence. SC-4 is the registry rule, a plain ValidatingPolicy; cosign has nothing to say
// about which registry an image came from.
var forgeReportOnly = map[string]bool{
	"SC-4": true,
}

// SkippedImagesNote is shown on the image controls when the image stage did not run.
const SkippedImagesNote = "Image checks were skipped (--skip-images). Kyverno writes a pass for every pod an image policy does not apply to, and without the pod list conformity cannot tell which pods are in scope, so passes are not counted here; failures are."

// isImageControl is true for the FORGE controls that conformity proves with cosign.
func isImageControl(c catalog.Control) bool {
	_, ok := forgeChecks[c.ID]
	return c.Framework == catalog.FORGE && ok
}

// skipImageControls is the report without the image stage. A Kyverno fail on an image
// control is real (the policy matched that pod), but a pass is not evidence: it is also
// written for pods outside the policy's image scope. So only the failures are kept, and a
// control without any reads NO DATA instead of a vacuous PASS.
func skipImageControls(rep *Report) {
	for i := range rep.Controls {
		row := &rep.Controls[i]
		if !isImageControl(row.Control) {
			continue
		}
		row.Counts.Pass, row.Counts.Skip = 0, 0
		row.Note = SkippedImagesNote
	}
}

// imagePolicy is one (policy, control) pair that needs an image check.
type imagePolicy struct {
	policy   string
	control  catalog.Control
	kind     supply.Kind
	globs    []string
	identity []supply.Identity
}

// imagePolicies finds the policies that carry a FORGE control and reads, from each, the
// images it covers and the signer identities it accepts.
func imagePolicies(policies []policy) ([]imagePolicy, error) {
	var out []imagePolicy
	for _, p := range policies {
		for _, c := range p.controls {
			if c.Framework != catalog.FORGE {
				continue
			}
			if forgeReportOnly[c.ID] {
				continue
			}
			kind, ok := forgeChecks[c.ID]
			if !ok {
				return nil, fmt.Errorf("policy %q: control %s has no image check in conformity", p.Name, c.Key())
			}
			if p.obj.GetKind() != "ImageValidatingPolicy" {
				return nil, fmt.Errorf("policy %q: control %s needs an ImageValidatingPolicy, found %s", p.Name, c.Key(), p.obj.GetKind())
			}
			globs, err := globsOf(p.obj)
			if err != nil {
				return nil, fmt.Errorf("policy %q: %w", p.Name, err)
			}
			ids, err := identitiesOf(p.obj)
			if err != nil {
				return nil, fmt.Errorf("policy %q: %w", p.Name, err)
			}
			out = append(out, imagePolicy{policy: p.Name, control: c, kind: kind, globs: globs, identity: ids})
		}
	}
	return out, nil
}

func globsOf(u *unstructured.Unstructured) ([]string, error) {
	items, _, _ := unstructured.NestedSlice(u.Object, "spec", "matchImageReferences")
	var out []string
	for _, it := range items {
		m, _ := it.(map[string]interface{})
		g, _ := m["glob"].(string)
		if g == "" || len(m) != 1 {
			return nil, fmt.Errorf("matchImageReferences entry %v: only {glob: ...} is supported", it)
		}
		out = append(out, g)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no matchImageReferences")
	}
	return out, nil
}

// identitiesOf reads exact keyless identities (subject and issuer). Anything else, such as
// a regular expression or a key, is refused: guessing would weaken the check silently.
func identitiesOf(u *unstructured.Unstructured) ([]supply.Identity, error) {
	atts, _, _ := unstructured.NestedSlice(u.Object, "spec", "attestors")
	var out []supply.Identity
	for _, a := range atts {
		m, _ := a.(map[string]interface{})
		ids, found, _ := unstructured.NestedSlice(m, "cosign", "keyless", "identities")
		if !found || len(ids) == 0 {
			return nil, fmt.Errorf("attestor %v has no cosign.keyless.identities", m["name"])
		}
		for _, i := range ids {
			im, _ := i.(map[string]interface{})
			sub, _ := im["subject"].(string)
			iss, _ := im["issuer"].(string)
			if sub == "" || iss == "" || len(im) != 2 {
				return nil, fmt.Errorf("identity %v: only exact {subject, issuer} is supported", im)
			}
			out = append(out, supply.Identity{Subject: sub, Issuer: iss})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no attestors with a keyless identity")
	}
	return out, nil
}

// checkImages runs the image checks and adds their results to the control rows. It returns
// the pods whose images were checked.
func checkImages(ctx context.Context, rep *Report, rows map[string]*ControlRow, policies []policy,
	results []result, snap *source.Snapshot, opt Options) ([]*unstructured.Unstructured, error) {

	ips, err := imagePolicies(policies)
	if err != nil {
		return nil, err
	}
	maxAge := opt.MaxScanAge
	if maxAge == 0 {
		maxAge = 720 * time.Hour
	}
	rep.Scope.MaxScanAge = maxAge.String()
	if len(ips) == 0 {
		return nil, nil
	}
	v, err := supply.Version(ctx, opt.Cosign)
	if err != nil {
		return nil, fmt.Errorf("cannot run cosign (install it or use --skip-images): %w", err)
	}
	rep.Cosign = v

	found, err := images.FromPods(snap.Pods)
	if err != nil {
		return nil, err
	}
	rep.Scope.ImagesFound = len(found)

	kyverno := map[string][]result{} // policy|"Pod ns/name" -> results
	for _, r := range results {
		k := r.Policy + "|" + r.Resource
		kyverno[k] = append(kyverno[k], r)
	}
	for _, ip := range ips {
		if rows[ip.control.Key()].ImageChecks == nil {
			rows[ip.control.Key()].ImageChecks = &ImageCounts{}
		}
	}

	// Which images does each policy cover, and so which pods are in its scope?
	type match struct {
		im  images.Image
		ips []imagePolicy
	}
	var matches []match
	inScope := map[string]map[string]bool{} // policy -> "Pod ns/name" -> true
	for _, im := range found {
		var m []imagePolicy
		for _, ip := range ips {
			for _, spec := range im.Specs {
				if images.MatchAny(ip.globs, spec) {
					m = append(m, ip)
					break
				}
			}
		}
		if len(m) == 0 {
			continue
		}
		matches = append(matches, match{im, m})
		for _, ip := range m {
			if inScope[ip.policy] == nil {
				inScope[ip.policy] = map[string]bool{}
			}
			for _, pod := range im.Pods {
				inScope[ip.policy]["Pod "+pod] = true
			}
		}
	}

	// Kyverno reports "pass" for every pod an image policy does not apply to. For the FORGE
	// controls, count only the Kyverno results of pods that use an image in the policy's scope.
	for i := range rep.Controls {
		row := &rep.Controls[i]
		if row.Framework != catalog.FORGE || row.ImageChecks == nil {
			continue // not an image control: its PolicyReport counts stand as they are
		}
		row.Counts, row.Findings = Counts{}, nil
		for _, pn := range row.Policies {
			for _, r := range results {
				if r.Policy != pn || !inScope[pn][r.Resource] {
					continue
				}
				row.Counts.add(r.Result)
				if bad(r.Result) {
					row.Findings = append(row.Findings, Finding{Policy: r.Policy, Rule: r.Rule,
						Result: r.Result, Resource: r.Resource, Message: r.Message})
				}
			}
		}
	}

	checker := &supply.Checker{Runner: opt.Cosign, Now: opt.Now, MaxScanAge: maxAge, Retries: opt.Retries, RetryDelay: opt.RetryDelay}
	usedPods := map[string]bool{}
	var matchedImages []images.Image
	for _, mt := range matches {
		im, m := mt.im, mt.ips
		matchedImages = append(matchedImages, im)
		if opt.Progress != nil {
			opt.Progress(fmt.Sprintf("checking image %d: %s", len(matchedImages), im.Ref))
		}
		ev := ImageEvidence{Ref: im.Ref, Pinned: im.Pinned, Specs: im.Specs, UsedBy: im.Pods}
		bundles, berr := checker.Bundles(ctx, im.Ref)
		if berr != nil {
			ev.BundleError = berr.Error()
		}
		byPolicyStatus := map[string]map[string]string{} // policy -> control -> status
		for _, ip := range m {
			o := checker.Check(ctx, im.Ref, ip.kind, ip.identity, bundles)
			ev.Checks = append(ev.Checks, ImageCheck{Control: ip.control.Key(), Policy: ip.policy, Kind: string(ip.kind), Outcome: o})
			if byPolicyStatus[ip.policy] == nil {
				byPolicyStatus[ip.policy] = map[string]string{}
			}
			byPolicyStatus[ip.policy][ip.control.Key()] = o.Status
			row := rows[ip.control.Key()]
			switch o.Status {
			case supply.Pass:
				row.ImageChecks.Pass++
			case supply.Fail:
				row.ImageChecks.Fail++
			default:
				row.ImageChecks.Error++
			}
			if o.Status != supply.Pass {
				row.Findings = append(row.Findings, Finding{Policy: ip.policy, Rule: "cosign " + string(ip.kind),
					Result: strings.ToLower(o.Status), Resource: "image " + im.Ref, Message: o.Detail})
			}
		}
		// Kyverno writes one result per policy and pod, so compare per policy.
		var policyNames []string
		for pn := range byPolicyStatus {
			policyNames = append(policyNames, pn)
		}
		sort.Strings(policyNames)
		for _, pn := range policyNames {
			allPass := true
			for _, st := range byPolicyStatus[pn] {
				allPass = allPass && st == supply.Pass
			}
			for _, pod := range im.Pods {
				res := "Pod " + pod
				ks := kyverno[pn+"|"+res]
				if len(ks) == 0 {
					continue
				}
				kpass, kinds, msg := true, []string{}, ""
				for _, k := range ks {
					kinds = append(kinds, k.Result)
					if k.Result != "pass" {
						kpass = false
						if msg == "" {
							msg = k.Message
						}
					}
				}
				if kpass != allPass {
					rep.Disagreements = append(rep.Disagreements, Disagreement{Policy: pn, Resource: res, Image: im.Ref,
						Kyverno: strings.Join(kinds, ","), KyvernoMessage: msg, Conformity: byPolicyStatus[pn]})
				}
			}
		}
		sort.Slice(ev.Checks, func(i, j int) bool { return ev.Checks[i].Control < ev.Checks[j].Control })
		rep.Images = append(rep.Images, ev)
		for _, pod := range im.Pods {
			usedPods[pod] = true
		}
	}
	rep.Scope.ImagesChecked = len(matchedImages)
	var pods []*unstructured.Unstructured
	for _, p := range snap.Pods {
		if usedPods[p.GetNamespace()+"/"+p.GetName()] {
			pods = append(pods, p)
		}
	}
	return pods, nil
}
