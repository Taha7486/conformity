# conformity

Compliance evidence for a Kubernetes cluster that admits only signed images. It reads Kyverno
PolicyReports, re-verifies cosign signatures and attestations, takes the Rekor log entry from
the bundle attached to each image, and writes a control-by-control report as Markdown and JSON.

Part of the Forge project (hardened-image factory plus cryptographic admission). Runs on a
laptop against a kubeconfig or against saved files. It has no server and no UI on purpose.

## Status

| Part | State |
| --- | --- |
| Control catalog from the `forge.dev/controls` annotation of Kyverno policies | done |
| Control-by-control status from PolicyReports (JSON, plain text) | done, tested on kind only |
| Markdown report | not yet |
| Cosign attestation checks and the Rekor entry from the bundle | not yet |

## Use

```
go build -o conformity .

# from a cluster (current kubeconfig context)
./conformity report --out out/

# from saved files: Kyverno policies and PolicyReports as YAML or JSON
./conformity report --dir testdata/input/kind-snapshot --format json
```

`--now` stamps the report with a fixed time, so the same input gives the same bytes.

## How a control gets its status

A policy lists the controls it enforces in the annotation `forge.dev/controls`, for example
`CIS 5.2.3, 5.2.4; PSS baseline: Host Namespaces` or `FORGE SC-1: Image signed by the pinned
build workflow`. A line the parser does not understand stops the run; nothing is skipped silently.

For each control, all results of its policies are counted. `fail`, `warn` and `error` results make
the control FAIL (a check that warned or could not run is not a pass); otherwise `pass` results make
it PASS; only `skip` results give SKIPPED; no results at all give NO DATA. Findings list every
result that stopped a control from passing. Counts are results, not resources: a Deployment and
its Pod each have a report.

## Tests

`go test ./...`. The fixtures in `testdata/input` were captured on 2026-10-17 from a one-node kind
cluster (Kubernetes 1.35.8, Kyverno 1.19.1) with the 17 pod policies of the Forge GitOps repo and
pods created before the policies, so the background scan reports failures. `go test ./internal/report -update`
rewrites the golden file after an intended change.
