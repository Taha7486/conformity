// Package supply checks an image's signature and attestations by running cosign, and reads
// the certificate and Rekor entry out of the bundles attached to the image. The signature
// math stays in cosign; this package decides what cosign's answer means.
package supply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Result is the outcome of one cosign run.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner runs cosign with the given arguments. An error means cosign could not be run or
// timed out; a non-zero exit code is a normal Result.
type Runner interface {
	Run(ctx context.Context, args ...string) (Result, error)
}

// Exec runs the cosign binary at Path.
type Exec struct {
	Path    string
	Timeout time.Duration
}

func (e Exec) Run(ctx context.Context, args ...string) (Result, error) {
	if e.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, e.Path, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	// After the timeout kills cosign, do not wait for a child that still holds the pipes.
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	res := Result{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return res, fmt.Errorf("cosign timed out after %s", e.Timeout)
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
	default:
		return res, err
	}
	return res, nil
}

// Version returns cosign's GitVersion line, for the report.
func Version(ctx context.Context, r Runner) (string, error) {
	res, err := r.Run(ctx, "version")
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		if strings.HasPrefix(l, "GitVersion:") {
			return strings.TrimSpace(strings.TrimPrefix(l, "GitVersion:")), nil
		}
	}
	return "", fmt.Errorf("no GitVersion in cosign version output")
}
