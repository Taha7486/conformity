# Compliance report

- Generated: 2026-10-17T12:00:00Z
- Source: fixtures
- Tool: test, cosign v3.1.3
- Report format: schema 1 (`report.json` holds the same data and every finding)

## Summary

**Overall: PASS.** All 3 controls pass.

| PASS | FAIL | SKIPPED | NO DATA | Controls |
|---|---|---|---|---|
| 3 | 0 | 0 | 0 | 3 |

How to read a status: a control is **FAIL** if any result of its policies is fail, warn or error (a check that warned or could not run is not a pass), or if an image check on it failed or could not be done; **PASS** if it has at least one passing result and none of those; **SKIPPED** if every result was skipped; **NO DATA** if there is no result at all (no resource in scope, or no report yet).

## Controls: Forge supply-chain controls

| Control | Status | Kyverno results (pass / not pass) | Image checks (pass / not pass) | Policies |
|---|---|---|---|---|
| SC-1 Image signed by the spike workflow | **PASS** | 0 / 0 | 1 / 0 | spike-ivp |
| SC-2 Signed SBOM attestation present | **PASS** | 0 / 0 | 1 / 0 | spike-ivp |
| SC-3 Signed, fresh vulnerability scan attestation | **PASS** | 0 / 0 | 1 / 0 | spike-ivp |

## Image evidence

10 images in use; 1 fall under an image policy and were checked again with cosign (vulnerability scans must be at most 720h0m0s old). cosign verified signatures, attestations and the Rekor log entries; conformity read the certificate and log entry out of the bundles attached to each image.

### `ghcr.io/taha7486/forge-spike-r1@sha256:f5eb8b57a454ab073acb0cea7d6bedfb27d37f48a327ecd65fdb7d9ea5c7c7d5`

Used by: demo/golden-pinned, demo/golden-tag. The digest is known (pod spec or runtime).

- **FORGE SC-1** (signature): **PASS**
  - `https://sigstore.dev/cosign/sign/v1`, signer `https://github.com/Taha7486/forge-spike-r1/.github/workflows/r1-sign-golden.yml@refs/heads/main`, Rekor log index 3048288286 logged 2026-10-02T05:04:10Z
  - `https://sigstore.dev/cosign/sign/v1`, signer `https://github.com/Taha7486/forge-spike-r1/.github/workflows/r1-sign-golden.yml@refs/heads/main`, Rekor log index 3049190029 logged 2026-10-02T06:06:39Z
- **FORGE SC-2** (sbom): **PASS**
  - `https://cyclonedx.org/bom`, signer `https://github.com/Taha7486/forge-spike-r1/.github/workflows/r1-sign-golden.yml@refs/heads/main`, Rekor log index 3048288702 logged 2026-10-02T05:04:14Z
- **FORGE SC-3** (vuln): **PASS**
  - `https://cosign.sigstore.dev/attestation/vuln/v1`, scan finished 2026-10-02T06:06:38Z, signer `https://github.com/Taha7486/forge-spike-r1/.github/workflows/r1-sign-golden.yml@refs/heads/main`, Rekor log index 3049191141 logged 2026-10-02T06:06:44Z
  - `https://cosign.sigstore.dev/attestation/vuln/v1`, scan finished 2026-10-02T05:04:09Z, signer `https://github.com/Taha7486/forge-spike-r1/.github/workflows/r1-sign-golden.yml@refs/heads/main`, Rekor log index 3048289202 logged 2026-10-02T05:04:17Z
  - newest verified scan is 365h53m0s old (limit 720h0m0s)

## Scope and limits

- 0 PolicyReports, 0 results, 0 resources
- Only controls that a Forge policy enforces appear here. This is not a full CIS Kubernetes Benchmark audit.
- Results exist only for resources that exist when the report is made. A pod that was refused at admission leaves no PolicyReport entry.
- Ephemeral containers (kubectl debug) are not covered by the pod policies.
- A result is as old as the last Kyverno background scan; see the oldest and newest result times.
- Namespaces listed as excluded by a policy are not evaluated by it.
- Rekor evidence (certificate, log entry, inclusion proof) is verified by cosign, not by conformity; tree size and root hash shown come from the log's signed checkpoint.

### Policies

| Policy | Kind | Ready | Actions | Controls |
|---|---|---|---|---|
| spike-ivp | ImageValidatingPolicy | no | Deny | FORGE SC-1; FORGE SC-2; FORGE SC-3 |

### Inputs

3 documents were read. SHA-256 over the sorted list (kind, namespace/name, SHA-256 of each document with managedFields left out): `0d6494f817679adff8eeeeb1fb1330884877cabbec52da2005df69db64690d09`. The list is in `report.json`.
