// Package catalog turns the forge.dev/controls annotation of Kyverno policies into a list
// of controls. The annotation is free text written by hand, so the parser is strict: a
// segment it does not understand is an error, never a silently dropped control.
package catalog

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Annotation is the policy annotation that lists the controls a policy enforces.
const Annotation = "forge.dev/controls"

// Frameworks, in the order a report lists them.
const (
	CIS   = "CIS"
	PSS   = "PSS"
	FORGE = "FORGE"
)

// Control is one requirement a policy enforces. Title is empty for CIS controls (the
// annotation carries only the number).
type Control struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title,omitempty"`
}

// Key is the unique name of a control, for example "CIS 5.2.2" or "PSS baseline: Host Ports".
func (c Control) Key() string { return c.Framework + " " + c.ID }

var (
	cisRe   = regexp.MustCompile(`^CIS (\d+(?:\.\d+)+(?:, \d+(?:\.\d+)+)*)$`)
	pssRe   = regexp.MustCompile(`^PSS (baseline|restricted): ([^:;()]+?)(?: \(no CIS control\))?$`)
	forgeRe = regexp.MustCompile(`^FORGE (SC-\d+): (\S.*)$`)
)

// Parse reads one annotation value. Segments are separated by ";". Accepted forms:
//
//	CIS 5.2.3, 5.2.4
//	PSS baseline: Host Ports            (optionally followed by " (no CIS control)")
//	FORGE SC-1: Image signed by the pinned build workflow
func Parse(annotation string) ([]Control, error) {
	var out []Control
	seen := map[string]bool{}
	add := func(c Control) error {
		if seen[c.Key()] {
			return fmt.Errorf("control %q listed twice", c.Key())
		}
		seen[c.Key()] = true
		out = append(out, c)
		return nil
	}
	for _, seg := range strings.Split(annotation, ";") {
		seg = strings.TrimSpace(seg)
		switch {
		case cisRe.MatchString(seg):
			for _, n := range strings.Split(cisRe.FindStringSubmatch(seg)[1], ", ") {
				if err := add(Control{Framework: CIS, ID: n}); err != nil {
					return nil, err
				}
			}
		case pssRe.MatchString(seg):
			m := pssRe.FindStringSubmatch(seg)
			if err := add(Control{Framework: PSS, ID: m[1] + ": " + m[2], Title: m[2]}); err != nil {
				return nil, err
			}
		case forgeRe.MatchString(seg):
			m := forgeRe.FindStringSubmatch(seg)
			if err := add(Control{Framework: FORGE, ID: m[1], Title: m[2]}); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("cannot parse segment %q", seg)
		}
	}
	return out, nil
}

// Less orders controls: by framework (CIS, PSS, FORGE), CIS numbers numerically, the rest
// by text.
func Less(a, b Control) bool {
	if fa, fb := rank(a.Framework), rank(b.Framework); fa != fb {
		return fa < fb
	}
	if a.Framework == CIS {
		return lessNumeric(a.ID, b.ID)
	}
	return a.ID < b.ID
}

func rank(f string) int {
	switch f {
	case CIS:
		return 0
	case PSS:
		return 1
	default:
		return 2
	}
}

func lessNumeric(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, _ := strconv.Atoi(pa[i])
		nb, _ := strconv.Atoi(pb[i])
		if na != nb {
			return na < nb
		}
	}
	return len(pa) < len(pb)
}

// Sort orders controls with Less.
func Sort(cs []Control) {
	sort.Slice(cs, func(i, j int) bool { return Less(cs[i], cs[j]) })
}
