package catalog

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseAcceptsTheFormsInUse(t *testing.T) {
	cases := []struct {
		in   string
		want []Control
	}{
		{"CIS 5.1.6", []Control{{CIS, "5.1.6", ""}}},
		{"CIS 5.2.3, 5.2.4, 5.2.5; PSS baseline: Host Namespaces", []Control{
			{CIS, "5.2.3", ""}, {CIS, "5.2.4", ""}, {CIS, "5.2.5", ""},
			{PSS, "baseline: Host Namespaces", "Host Namespaces"}}},
		{"PSS baseline: AppArmor (no CIS control)", []Control{{PSS, "baseline: AppArmor", "AppArmor"}}},
		{"PSS restricted: /proc Mount Type", []Control{{PSS, "restricted: /proc Mount Type", "/proc Mount Type"}}},
		{"FORGE SC-1: Image signed by the pinned build workflow", []Control{
			{FORGE, "SC-1", "Image signed by the pinned build workflow"}}},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("Parse(%q) = %v, %v; want %v", c.in, got, err, c.want)
		}
	}
}

func TestParseRejectsWhatItDoesNotUnderstand(t *testing.T) {
	bad := []string{
		"", " ", "CIS", "CIS 5", "CIS 5.2.3,5.2.4", "CIS 5.2.3;", "cis 5.2.3",
		"PSS privileged: x", "PSS baseline:", "PSS baseline: X (no cis control)",
		"FORGE SC-1", "FORGE SC-x: y", "NIST AC-1", "CIS 5.2.3; CIS 5.2.3", "CIS 5.2.3, 5.2.3",
	}
	for _, in := range bad {
		if got, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %v, want an error", in, got)
		}
	}
}

func TestSortOrder(t *testing.T) {
	cs := []Control{{FORGE, "SC-2", ""}, {PSS, "restricted: Seccomp", ""}, {CIS, "5.2.10", ""},
		{CIS, "5.2.2", ""}, {PSS, "baseline: Host Ports", ""}, {FORGE, "SC-1", ""}, {CIS, "5.10.1", ""}}
	Sort(cs)
	var keys []string
	for _, c := range cs {
		keys = append(keys, c.Key())
	}
	want := "CIS 5.2.2|CIS 5.2.10|CIS 5.10.1|PSS baseline: Host Ports|PSS restricted: Seccomp|FORGE SC-1|FORGE SC-2"
	if strings.Join(keys, "|") != want {
		t.Errorf("order = %s", strings.Join(keys, "|"))
	}
}
