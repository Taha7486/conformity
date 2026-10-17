package source

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

// Cluster reads from the cluster a kubeconfig points at, with the dynamic client, so no
// Kyverno Go types are needed. It only lists; it never writes.
type Cluster struct {
	Kubeconfig string // empty: the default loading rules (KUBECONFIG, ~/.kube/config)
	Context    string // empty: the current context
	Pods       bool   // also list all pods (needed for image checks)
}

var clusterKinds = []schema.GroupVersionResource{
	{Group: "policies.kyverno.io", Version: "v1", Resource: "validatingpolicies"},
	{Group: "policies.kyverno.io", Version: "v1", Resource: "imagevalidatingpolicies"},
	{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "policyreports"},
	{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "clusterpolicyreports"},
}

func (c Cluster) Load(ctx context.Context) (*Snapshot, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = c.Kubeconfig
	cfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
		&clientcmd.ConfigOverrides{CurrentContext: c.Context})
	raw, err := cfg.RawConfig()
	if err != nil {
		return nil, err
	}
	name := raw.CurrentContext
	if c.Context != "" {
		name = c.Context
	}
	restCfg, err := cfg.ClientConfig()
	if err != nil {
		return nil, err
	}
	client, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{Origin: "cluster, kubeconfig context " + name}
	kinds := clusterKinds
	if c.Pods {
		kinds = append(append([]schema.GroupVersionResource{}, kinds...), schema.GroupVersionResource{Version: "v1", Resource: "pods"})
	}
	for _, gvr := range kinds {
		list, err := client.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", gvr.Resource, err)
		}
		docs := make([]*unstructured.Unstructured, 0, len(list.Items))
		for i := range list.Items {
			docs = append(docs, &list.Items[i])
		}
		if err := classify(snap, docs); err != nil {
			return nil, err
		}
	}
	return snap, nil
}
