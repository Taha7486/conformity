package source

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

type runtimeObject = runtime.Object

// Dir reads every .yaml, .yml and .json file below a directory, in name order. A file may
// hold several YAML documents or a List.
type Dir struct{ Path string }

func (d Dir) Load(ctx context.Context) (*Snapshot, error) {
	var files []string
	err := filepath.WalkDir(d.Path, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yaml", ".yml", ".json":
			if !e.IsDir() {
				files = append(files, p)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .yaml, .yml or .json files in %s", d.Path)
	}
	sort.Strings(files)
	snap := &Snapshot{Origin: "directory " + d.Path}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
		for {
			u := &unstructured.Unstructured{}
			if err := dec.Decode(&u.Object); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			if len(u.Object) == 0 {
				continue // empty document between separators
			}
			if u.GetKind() == "" {
				return nil, fmt.Errorf("%s: document without a kind", f)
			}
			if err := classify(snap, []*unstructured.Unstructured{u}); err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
		}
	}
	return snap, nil
}
