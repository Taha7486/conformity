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
| Image checks with cosign (signature, SBOM, vulnerability scan) and the certificate and Rekor entry from the bundle | done, tested against the public spike image only (no ECR yet) |
| Markdown report | not yet |

## Use

```
go build -o conformity .

# from a cluster (current kubeconfig context)
./conformity report --out out/

# from saved files: Kyverno policies and PolicyReports as YAML or JSON
./conformity report --dir testdata/input/kind-snapshot --format json --skip-images
```

`--now` stamps the report with a fixed time, so the same input gives the same bytes. `--skip-images` leaves cosign out (the report then rests on the PolicyReports alone and works offline). Other flags: `--cosign PATH`, `--cosign-timeout` (default 90s), `--retries` (default 1: a cosign call that ended in an error is repeated once after 3 seconds, a FAIL never is), `--max-scan-age` (default 720h, the window of the `ecr-vuln` policy).

## How a control gets its status

A policy lists the controls it enforces in the annotation `forge.dev/controls`, for example
`CIS 5.2.3, 5.2.4; PSS baseline: Host Namespaces` or `FORGE SC-1: Image signed by the pinned
build workflow`. A line the parser does not understand stops the run; nothing is skipped silently.

For each control, all results of its policies are counted. `fail`, `warn` and `error` results make
the control FAIL (a check that warned or could not run is not a pass); otherwise `pass` results make
it PASS; only `skip` results give SKIPPED; no results at all give NO DATA. Findings list every
result that stopped a control from passing. Counts are results, not resources: a Deployment and
its Pod each have a report.

## Image checks (the FORGE controls)

Kyverno says an image was admitted; `conformity` checks it again on its own. Policies that carry a
`FORGE SC-n` control are `ImageValidatingPolicy` objects. From each, conformity reads the image globs
(`matchImageReferences`) and the exact keyless signer identities (`attestors`); a regular expression,
a key or any other shape stops the run instead of being guessed. It then takes the images of the
Pods (cluster: all pods; directory: Pod documents), keeps those that match a glob, and for each runs
cosign:

| Control | Check | What counts as a pass |
| --- | --- | --- |
| `SC-1` | `cosign verify` | a valid keyless signature from the policy's identity, for the image digest |
| `SC-2` | `cosign verify-attestation --type https://cyclonedx.org/bom` | a verified CycloneDX SBOM attestation about the digest |
| `SC-3` | `cosign verify-attestation --type https://cosign.sigstore.dev/attestation/vuln/v1` | a verified scan attestation whose newest `scanFinishedOn` is within `--max-scan-age` |

The digest comes from the pod spec, else from the `imageID` the runtime reported; with neither, the
tag is verified and the report says the image is not pinned. A failure is **FAIL** only when cosign
says the evidence is missing or wrong (no matching attestation, no signature); anything else
(network, registry, TUF, timeout) is **ERROR**. Both keep the control from passing, but ERROR means
"could not look", not "bad image". Where Kyverno's PolicyReport and this check disagree about a pod,
the report lists a disagreement.

The certificate (signer, ten-minute validity) and the Rekor entry (log index, integration time, log
ID, inclusion proof) come from the bundles that `cosign download attestation` returns, tied to the
verified attestation by its DSSE signature (`binding: dsse-signature`). For the signature check
cosign prints no envelope, so bundles are chosen by type, subject digest and certificate identity
(`binding: certificate-identity`). conformity makes no call to Rekor and does not verify the proof
itself; it relies on cosign, and the tree size and root hash it shows come from the log's signed
checkpoint (`proofMatchesCheckpoint` says whether the proof's own fields agree).

### What cosign checks (tested 2026-10-17, cosign v3.1.3)

`CONFORMITY_LIVE=1 go test ./internal/supply -run Tampered -v` gives `cosign verify-blob-attestation
--bundle` a real bundle with one change at a time. The untouched bundle passes; cosign refuses a
changed Merkle root hash, a changed path hash, a changed checkpoint root, a changed signed entry
timestamp, a changed integration time or log index, a removed log entry, and a changed signed
payload. By hand, a checkpoint signature changed by one character, a proof tree size off by 64 or
more, and a removed signed entry timestamp were also refused. NOT refused: a proof `treeSize` off
by 1 to 8 (the Merkle path still computes the same root, and the field is not tied to the signed
checkpoint), which is why the report shows the checkpoint's values. With a bundle that has no signed
entry timestamp cosign refuses even an intact proof (it wants a timestamp from the log); how a
Rekor v2 bundle without one behaves is untested.

### What Kyverno's reports look like for an image policy (kind, Kyverno 1.19.1)

Kyverno writes ONE result per policy and pod (`rule` equals the policy name, `source:
KyvernoImageValidatingPolicy`), so conformity compares per policy: Kyverno passes only if all checks of
the policy pass. Pods whose images the policy does not match get a `pass` ("success"); conformity
leaves those out of the FORGE counts when it knows the pods (image checks on). The background scan
FAILS a pod whose spec has a tag but no digest ("image ... does not have a digest"): pods created
through the admission webhook get the digest written into the spec, pods created earlier do not.
conformity resolves the digest from the runtime's `imageID`, so it can disagree with Kyverno there,
and it reports the disagreement with Kyverno's message. When the report controllers stop, or a
policy changes after the reports were written, the same mechanism shows a stale "pass".
When Kyverno's `extractPayload` meets two verified scans of one image it returned the newer one,
which is the scan conformity judges.

## Tests

`go test ./...`. The fixtures in `testdata/input` were captured on 2026-10-17 from a one-node kind
cluster (Kubernetes 1.35.8, Kyverno 1.19.1) with the 17 pod policies of the Forge GitOps repo and
pods created before the policies, so the background scan reports failures. `go test ./internal/report -update`
rewrites the golden files after an intended change.

The cosign tests use real cosign v3.1.3 output in `testdata/cosign` (predicates trimmed, see the
README there) and a fake runner. `testdata/input/pods` holds real Pods from a kind cluster, with the
runtime's `imageID` values. With `CONFORMITY_LIVE=1 go test ./internal/supply -run Live -v` the real
cosign runs against the public spike image on GHCR (positive case, stale scan, a lookalike identity,
an image signed by someone else, an unsigned image, a missing tag, an unknown host).
