// Package source reads the inputs of a report: Kyverno policies and PolicyReports. They
// come either from a directory of saved YAML/JSON files or from a live cluster.
package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Snapshot is everything a report is computed from.
type Snapshot struct {
	Origin   string // human-readable description of where the data came from
	Policies []*unstructured.Unstructured
	Reports  []*unstructured.Unstructured
	Ignored  int // documents read but not used (other kinds)
}

// Source produces a Snapshot.
type Source interface {
	Load(ctx context.Context) (*Snapshot, error)
}

// Which kinds count as policies and as reports.
const (
	policyGroup = "policies.kyverno.io"
	reportGroup = "wgpolicyk8s.io"
)

func isPolicy(u *unstructured.Unstructured) bool {
	gvk := u.GroupVersionKind()
	return gvk.Group == policyGroup && (gvk.Kind == "ValidatingPolicy" || gvk.Kind == "ImageValidatingPolicy")
}

func isReport(u *unstructured.Unstructured) bool {
	gvk := u.GroupVersionKind()
	return gvk.Group == reportGroup && (gvk.Kind == "PolicyReport" || gvk.Kind == "ClusterPolicyReport")
}

// classify sorts documents into a snapshot; a List is expanded first.
func classify(snap *Snapshot, docs []*unstructured.Unstructured) error {
	for _, d := range docs {
		if d.IsList() {
			if err := d.EachListItem(func(o runtimeObject) error {
				u, ok := o.(*unstructured.Unstructured)
				if !ok {
					return fmt.Errorf("list item is not unstructured")
				}
				return classify(snap, []*unstructured.Unstructured{u})
			}); err != nil {
				return err
			}
			continue
		}
		switch {
		case isPolicy(d):
			snap.Policies = append(snap.Policies, d)
		case isReport(d):
			snap.Reports = append(snap.Reports, d)
		default:
			snap.Ignored++
		}
	}
	return nil
}

// Hash is the SHA-256 of a document's JSON form (keys sorted, managedFields left out), so a report can show which
// inputs it was made from.
func Hash(u *unstructured.Unstructured) (string, error) {
	// managedFields is bookkeeping that kubectl hides and the API returns, so it is left out:
	// the same object then has the same hash whichever way it was read.
	c := u.DeepCopy()
	unstructured.RemoveNestedField(c.Object, "metadata", "managedFields")
	b, err := json.Marshal(c.Object)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
