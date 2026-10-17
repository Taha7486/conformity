// Package images finds the container images that Pods use and matches them against the
// image globs of Kyverno image policies.
package images

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Image is one image reference to check, with the pods that use it.
type Image struct {
	// Ref is what gets verified: repo@sha256:digest when the digest is known, else the
	// image string of the pod spec (a tag, resolved by the registry at check time).
	Ref string `json:"ref"`
	// Pinned is true when Ref carries a digest, taken from the pod spec or from the
	// imageID the container runtime reported.
	Pinned bool `json:"pinned"`
	// Specs are the image strings as written in the pod specs (Kyverno matches those).
	Specs []string `json:"specs"`
	// Pods are "namespace/name" of the pods that use the image.
	Pods []string `json:"usedBy"`
}

var digestRe = regexp.MustCompile(`@(sha256:[0-9a-f]{64})`)

// Repo strips a tag and a digest: "ghcr.io/a/b:1@sha256:..." gives "ghcr.io/a/b".
func Repo(image string) string {
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		image = image[:i]
	}
	return image
}

// FromPods returns every distinct image reference used by the pods (containers and init
// containers), sorted by Ref.
func FromPods(pods []*unstructured.Unstructured) ([]Image, error) {
	byRef := map[string]*Image{}
	for _, p := range pods {
		id := p.GetNamespace() + "/" + p.GetName()
		ids := imageIDs(p)
		for _, group := range []string{"containers", "initContainers"} {
			cs, _, err := unstructured.NestedSlice(p.Object, "spec", group)
			if err != nil {
				return nil, fmt.Errorf("pod %s: %w", id, err)
			}
			for _, c := range cs {
				m, ok := c.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("pod %s: container is not an object", id)
				}
				name, _ := m["name"].(string)
				spec, _ := m["image"].(string)
				if spec == "" {
					return nil, fmt.Errorf("pod %s: container %q has no image", id, name)
				}
				ref, pinned := resolve(spec, ids[name])
				im := byRef[ref]
				if im == nil {
					im = &Image{Ref: ref, Pinned: pinned}
					byRef[ref] = im
				}
				im.Specs = appendUnique(im.Specs, spec)
				im.Pods = appendUnique(im.Pods, id)
			}
		}
	}
	out := make([]Image, 0, len(byRef))
	for _, im := range byRef {
		sort.Strings(im.Specs)
		sort.Strings(im.Pods)
		out = append(out, *im)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out, nil
}

// imageIDs maps container name to the imageID the runtime reported.
func imageIDs(p *unstructured.Unstructured) map[string]string {
	out := map[string]string{}
	for _, group := range []string{"containerStatuses", "initContainerStatuses"} {
		ss, _, _ := unstructured.NestedSlice(p.Object, "status", group)
		for _, s := range ss {
			m, _ := s.(map[string]interface{})
			name, _ := m["name"].(string)
			id, _ := m["imageID"].(string)
			if name != "" && id != "" {
				out[name] = id
			}
		}
	}
	return out
}

// resolve picks the reference to verify. A digest in the spec wins; then a digest in the
// runtime's imageID, attached to the repository of the spec; else the spec as written.
func resolve(spec, imageID string) (ref string, pinned bool) {
	if m := digestRe.FindStringSubmatch(spec); m != nil {
		return Repo(spec) + "@" + m[1], true // drops a tag Kyverno left next to the digest
	}
	if m := digestRe.FindStringSubmatch(imageID); m != nil {
		return Repo(spec) + "@" + m[1], true
	}
	return spec, false
}

// Match reports whether an image string matches a Kyverno glob, where "*" stands for any
// run of characters (slashes included), as in matchImageReferences.
func Match(glob, image string) bool {
	parts := strings.Split(glob, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$").MatchString(image)
}

// MatchAny is true when the image matches at least one glob.
func MatchAny(globs []string, image string) bool {
	for _, g := range globs {
		if Match(g, image) {
			return true
		}
	}
	return false
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
