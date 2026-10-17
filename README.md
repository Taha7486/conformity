# conformity

Compliance evidence for a Kubernetes cluster that admits only signed images. It reads Kyverno
policies and PolicyReports, checks the signature, SBOM and vulnerability scan of the running images
again with cosign, and writes a control-by-control report as Markdown and JSON.

Part of the Forge project (hardened-image factory plus cryptographic admission). It runs on a laptop,
against a kubeconfig or against saved files, and writes files. It has no server and no UI on purpose.

Two committed examples, made from the fixtures in `testdata/input`:
[`examples/kind-snapshot`](examples/kind-snapshot/report.md) (17 CIS and Pod Security policies on a
kind cluster, PolicyReports only) and [`examples/kind-ivp`](examples/kind-ivp/report.md) (an image
policy, real cosign checks, a Rekor entry per attestation, and a real disagreement with Kyverno).

**Status:** tested on kind with Kyverno 1.19.1 and on the public spike image on GHCR. Not yet run
against EKS or ECR.

## Use

```
go build -o conformity .

./conformity report --out out/                    # live cluster, current kubeconfig context
./conformity report --dir testdata/input/kind-ivp # saved YAML or JSON instead of a cluster
./conformity report --skip-images --format md     # PolicyReports only, no cosign, no network
```

| Flag | Meaning |
| --- | --- |
| `--dir PATH` | read policies, PolicyReports and Pods from YAML or JSON files below PATH |
| `--kubeconfig FILE`, `--context NAME` | which cluster (default: `KUBECONFIG`, then `~/.kube/config`); it only lists, never writes |
| `--format text\|json\|md` | what goes to stdout (default `text`) |
| `--out DIR` | also write `report.md` and `report.json` into DIR |
| `--strict` | exit with code 3 when any control is FAIL (default: exit 0; errors exit 1) |
| `--now TIME` | RFC 3339 time to stamp the report with, so the same input gives the same bytes |
| `--skip-images` | do not run cosign; the report rests on the PolicyReports alone and works offline |
| `--cosign PATH`, `--cosign-timeout D` | cosign binary (default from `PATH`) and time limit per call (default 90s) |
| `--retries N` | repeat a cosign call that ended in an error (network, TUF) N times, 3 s apart (default 1); a FAIL is never repeated |
| `--max-scan-age D` | oldest vulnerability scan that counts as fresh (default 720h, the window of the `ecr-vuln` policy) |

## How a control gets its status

Policies list the controls they enforce in the annotation `forge.dev/controls`, for example
`CIS 5.2.3, 5.2.4; PSS baseline: Host Namespaces` or `FORGE SC-1: Image signed by the pinned build
workflow`. A segment the parser does not understand stops the run; nothing is skipped silently.

For each control, all results of its policies are counted. `fail`, `warn` and `error` results make
the control FAIL (a check that warned or could not run is not a pass); otherwise `pass` results make
it PASS; only `skip` results give SKIPPED; no result at all gives NO DATA. Findings list every result
that stopped a control from passing. Counts are results, not resources: a Deployment and its Pod each
have a report.

## Image checks (the FORGE controls)

Kyverno says an image was admitted; conformity checks it again on its own. Policies that carry a
`FORGE SC-n` control are `ImageValidatingPolicy` objects. From each, conformity reads the image globs
(`matchImageReferences`) and the exact keyless signer identities (`attestors`); a regular expression,
a key or any other shape stops the run instead of being guessed. It takes the images of the Pods
(cluster: all pods; directory: Pod documents), keeps those that match a glob, and for each runs cosign:

| Control | Check | What counts as a pass |
| --- | --- | --- |
| `SC-1` | `cosign verify` | a valid keyless signature from the policy's identity, for the image digest |
| `SC-2` | `cosign verify-attestation --type https://cyclonedx.org/bom` | a verified CycloneDX SBOM attestation about the digest |
| `SC-3` | `cosign verify-attestation --type https://cosign.sigstore.dev/attestation/vuln/v1` | a verified scan attestation whose newest `scanFinishedOn` is within `--max-scan-age` |

The digest comes from the pod spec, else from the `imageID` the runtime reported; with neither, the
tag is verified and the report says the image is not pinned. A failure is **FAIL** only when cosign
says the evidence is missing or wrong (no matching attestation, no signature); anything else
(network, registry, TUF, timeout) is **ERROR**. Both keep the control from passing, but ERROR means
"could not look", not "bad image". One image costs about 25 seconds (three verifications and a
download). Registry login is whatever the Docker config provides (for ECR:
`aws ecr get-login-password | docker login`; not tried yet).

The certificate (signer, ten-minute validity) and the Rekor entry (log index, integration time, log
ID, inclusion proof) come from the bundles that `cosign download attestation` returns, tied to the
verified attestation by its DSSE signature (`binding: dsse-signature`). For the signature check cosign
prints no envelope, so bundles are chosen by type, subject digest and certificate identity
(`binding: certificate-identity`). conformity makes no call to Rekor and does not verify the proof
itself; it relies on cosign, and the tree size and root hash it shows come from the log's signed
checkpoint (`proofMatchesCheckpoint` says whether the proof's own fields agree).

### What cosign checks (tested 2026-10-17, cosign v3.1.3)

`CONFORMITY_LIVE=1 go test ./internal/supply -run Tampered -v` gives `cosign verify-blob-attestation
--bundle` a real bundle with one change at a time. The untouched bundle passes; cosign refuses a
changed Merkle root hash, a changed path hash, a changed checkpoint root, a changed signed entry
timestamp, a changed integration time or log index, a removed log entry, and a changed signed
payload. By hand, a checkpoint signature changed by one character, a proof tree size off by 64 or
more, and a removed signed entry timestamp were also refused. NOT refused: a proof `treeSize` off by
1 to 8 (the Merkle path still computes the same root, and the field is not tied to the signed
checkpoint), which is why the report shows the checkpoint's values. With a bundle that has no signed
entry timestamp cosign refuses even an intact proof; how a Rekor v2 bundle without one behaves is
untested.

### What Kyverno's reports look like for an image policy (kind, Kyverno 1.19.1)

Kyverno writes ONE result per policy and pod (`rule` equals the policy name, `source:
KyvernoImageValidatingPolicy`), so conformity compares per policy: Kyverno passes only if all checks
of the policy pass. Pods whose images the policy does not match get a `pass` ("success"); conformity
leaves those out of the FORGE counts when it knows the pods (image checks on). The background scan
FAILS a pod whose spec has a tag but no digest ("image ... does not have a digest"): pods created
through the admission webhook get the digest written into the spec, pods created earlier do not.
conformity resolves the digest from the runtime's `imageID`, so it can disagree with Kyverno there,
and it lists the disagreement with Kyverno's message. When the report controllers stop, or a policy
changes after the reports were written, the same mechanism shows a stale "pass". When Kyverno's
`extractPayload` meets two verified scans of one image it returned the newer one, which is the scan
conformity judges.

## What the report does not say

The report lists its own limits under "Scope and limits". In short: only controls that a Forge policy
enforces appear (this is not a CIS audit); results exist only for resources that exist when it runs,
and a refused pod leaves none; ephemeral containers are not covered by the pod policies; a result is
as old as Kyverno's last background scan; excluded namespaces are not evaluated; Rekor evidence is
verified by cosign, not by conformity.

## Tests

`go test ./...` runs offline. Fixtures in `testdata/input` are real: PolicyReports and policies from
a kind cluster (Kubernetes 1.35.8, Kyverno 1.19.1; pods created before the policies so the scan
reports failures), Pods with the runtime's `imageID`, and an image policy with its reports. The cosign
tests use real cosign v3.1.3 output in `testdata/cosign` (predicates trimmed, see the README there)
and a fake runner. Golden files in `testdata/golden`; `go test ./internal/report -update` rewrites
them after an intended change.

`CONFORMITY_LIVE=1 go test ./internal/supply -run Live -v` runs the real cosign against the public
spike image on GHCR: the positive case, a stale scan, a lookalike identity, an image signed by someone
else, an unsigned image, a missing tag, an unknown host, and the tampered Rekor evidence.

To regenerate the examples (the second one calls cosign and needs the network):

```
./conformity report --dir testdata/input/kind-snapshot --skip-images --now 2026-10-17T15:00:00Z --out examples/kind-snapshot
./conformity report --dir testdata/input/kind-ivp --now 2026-10-17T15:50:00Z --out examples/kind-ivp
```

## Layout

`main.go` (flags), `internal/catalog` (annotation parser), `internal/source` (directory and cluster
input), `internal/images` (images of pods, globs), `internal/supply` (cosign runner, bundles, the three
checks), `internal/report` (evaluation, JSON, Markdown, text).
