package images

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

const d1 = "sha256:f5eb8b57a454ab073acb0cea7d6bedfb27d37f48a327ecd65fdb7d9ea5c7c7d5"
const d2 = "sha256:0000000000000000000000000000000000000000000000000000000000000002"

func pod(t *testing.T, y string) *unstructured.Unstructured {
	t.Helper()
	u := &unstructured.Unstructured{}
	if err := yaml.Unmarshal([]byte(y), &u.Object); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestRepo(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/a/b":          "ghcr.io/a/b",
		"ghcr.io/a/b:golden":   "ghcr.io/a/b",
		"ghcr.io/a/b@" + d1:    "ghcr.io/a/b",
		"ghcr.io/a/b:1@" + d1:  "ghcr.io/a/b",
		"localhost:5000/a/b":   "localhost:5000/a/b",
		"localhost:5000/a/b:2": "localhost:5000/a/b",
		"alpine":               "alpine",
		"alpine:3.20":          "alpine",
	} {
		if got := Repo(in); got != want {
			t.Errorf("Repo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		glob, image string
		want        bool
	}{
		{"ghcr.io/taha7486/forge-spike-r1*", "ghcr.io/taha7486/forge-spike-r1:golden", true},
		{"ghcr.io/taha7486/forge-spike-r1*", "ghcr.io/taha7486/forge-spike-r1-lookalike:x", true}, // same as Kyverno: no slash anchor
		{"ghcr.io/taha7486/forge-spike-r1*", "ghcr.io/other/forge-spike-r1:golden", false},
		{"123.dkr.ecr.eu-west-3.amazonaws.com/forge/*", "123.dkr.ecr.eu-west-3.amazonaws.com/forge/podinfo:1", true},
		{"123.dkr.ecr.eu-west-3.amazonaws.com/forge/*", "123.dkr.ecr.eu-west-3.amazonaws.com/other/podinfo:1", false},
		{"a.b/c", "aXb/c", false}, // the dot is literal
		{"*", "anything/at:all", true},
		{"forge/*", "xx/forge/a", false},   // anchored at the start
		{"ghcr.io/a", "ghcr.io/ab", false}, // anchored at the end
		{"ghcr.io/a", "ghcr.io/a", true},
	}
	for _, c := range cases {
		if got := Match(c.glob, c.image); got != c.want {
			t.Errorf("Match(%q, %q) = %v", c.glob, c.image, got)
		}
	}
}

func TestFromPods(t *testing.T) {
	p1 := pod(t, `
apiVersion: v1
kind: Pod
metadata: {name: a, namespace: ns1}
spec:
  containers:
  - {name: app, image: "ghcr.io/x/y:tag"}
  initContainers:
  - {name: init, image: "ghcr.io/x/z@`+d2+`"}
status:
  containerStatuses:
  - {name: app, imageID: "ghcr.io/x/y@`+d1+`"}
  initContainerStatuses:
  - {name: init, imageID: "ghcr.io/x/z@`+d2+`"}
`)
	p2 := pod(t, `
apiVersion: v1
kind: Pod
metadata: {name: b, namespace: ns2}
spec:
  containers:
  - {name: app, image: "ghcr.io/x/y:other-tag"}
  - {name: side, image: "docker.io/library/alpine:3.20"}
status:
  containerStatuses:
  - {name: app, imageID: "ghcr.io/x/y@`+d1+`"}
  - {name: side, imageID: "sha256:abcdef"}
`)
	p3 := pod(t, `
apiVersion: v1
kind: Pod
metadata: {name: c, namespace: ns2}
spec:
  containers:
  - {name: app, image: "ghcr.io/x/y:tag"}
`)
	got, err := FromPods([]*unstructured.Unstructured{p1, p2, p3})
	if err != nil {
		t.Fatal(err)
	}
	want := []Image{
		{Ref: "docker.io/library/alpine:3.20", Pinned: false, Specs: []string{"docker.io/library/alpine:3.20"}, Pods: []string{"ns2/b"}},
		{Ref: "ghcr.io/x/y:tag", Pinned: false, Specs: []string{"ghcr.io/x/y:tag"}, Pods: []string{"ns2/c"}},
		{Ref: "ghcr.io/x/y@" + d1, Pinned: true, Specs: []string{"ghcr.io/x/y:other-tag", "ghcr.io/x/y:tag"}, Pods: []string{"ns1/a", "ns2/b"}},
		{Ref: "ghcr.io/x/z@" + d2, Pinned: true, Specs: []string{"ghcr.io/x/z@" + d2}, Pods: []string{"ns1/a"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestFromPodsRejectsBrokenPods(t *testing.T) {
	_, err := FromPods([]*unstructured.Unstructured{pod(t, "apiVersion: v1\nkind: Pod\nmetadata: {name: a, namespace: n}\nspec:\n  containers:\n  - {name: app}\n")})
	if err == nil {
		t.Error("want an error for a container without an image")
	}
}

// A digest written in the pod spec is what the owner pinned; it wins over the runtime's imageID.
func TestSpecDigestWinsOverImageID(t *testing.T) {
	p := pod(t, `
apiVersion: v1
kind: Pod
metadata: {name: a, namespace: ns}
spec:
  containers:
  - {name: app, image: "ghcr.io/x/y@`+d2+`"}
status:
  containerStatuses:
  - {name: app, imageID: "ghcr.io/x/y@`+d1+`"}
`)
	got, err := FromPods([]*unstructured.Unstructured{p})
	if err != nil || len(got) != 1 || got[0].Ref != "ghcr.io/x/y@"+d2 {
		t.Errorf("got %+v, %v", got, err)
	}
}

// Kyverno's admission mutation writes "repo:tag@digest"; the same image must not appear twice.
func TestTagAndDigestInSpecIsNormalised(t *testing.T) {
	a := pod(t, "apiVersion: v1\nkind: Pod\nmetadata: {name: a, namespace: ns}\nspec:\n  containers:\n  - {name: app, image: \"ghcr.io/x/y:golden@"+d1+"\"}\n")
	b := pod(t, "apiVersion: v1\nkind: Pod\nmetadata: {name: b, namespace: ns}\nspec:\n  containers:\n  - {name: app, image: \"ghcr.io/x/y@"+d1+"\"}\n")
	got, err := FromPods([]*unstructured.Unstructured{a, b})
	if err != nil || len(got) != 1 || got[0].Ref != "ghcr.io/x/y@"+d1 || len(got[0].Pods) != 2 || len(got[0].Specs) != 2 {
		t.Errorf("got %+v, %v", got, err)
	}
}
