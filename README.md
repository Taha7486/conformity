# conformity

Compliance evidence for a Kubernetes cluster that admits only signed images. It reads Kyverno
PolicyReports, re-verifies cosign signatures and attestations, takes the Rekor log entry from
the bundle attached to each image, and writes a control-by-control report as Markdown and JSON.

Part of the Forge project (hardened-image factory plus cryptographic admission). Runs on a
laptop against a kubeconfig or against saved files. It has no server and no UI on purpose.

Status: skeleton only. Nothing is implemented yet.
