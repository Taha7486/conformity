# cosign fixtures

Captured on 2026-10-17 with cosign v3.1.3 against the public spike image
`ghcr.io/taha7486/forge-spike-r1@sha256:f5eb8b57a454ab073acb0cea7d6bedfb27d37f48a327ecd65fdb7d9ea5c7c7d5`
(signed and attested by `https://github.com/Taha7486/forge-spike-r1/.github/workflows/r1-sign-golden.yml@refs/heads/main`).

- `golden/bundles.jsonl`: `cosign download attestation` (5 bundles: 2 sign/v1, 2 vulnerability scans, 1 SBOM).
- `golden/verify-attestation-*.jsonl`, `golden/verify.json`: stdout of `cosign verify-attestation --type ...` and `cosign verify`.
- `golden/stderr-*.txt`: stderr of failed runs (wrong identity, other signer, wrong type, missing tag, unknown host, image without attestations or signatures).

TRIMMED: the SBOM and vulnerability predicates were cut down to `bomFormat`/`specVersion` and
`metadata.scanFinishedOn`, in the bundles and in the verify output alike (same bytes, so a verified
envelope still matches its bundle by signature). The certificates and Rekor entries are untouched.
As a result the DSSE signatures no longer verify: these files test how conformity reads cosign's
answers, not cryptography. The live tests (see the main README) run the real cosign.
