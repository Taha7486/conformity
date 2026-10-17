# Compliance report

- Generated: 2026-10-17T15:00:00Z
- Source: directory testdata/input/kind-snapshot
- Tool: conformity 0.1.0-dev
- Report format: schema 1 (`report.json` holds the same data and every finding)

## Summary

**Overall: FAIL.** 17 of 29 controls fail.

| PASS | FAIL | SKIPPED | NO DATA | Controls |
|---|---|---|---|---|
| 12 | 17 | 0 | 0 | 29 |

How to read a status: a control is **FAIL** if any result of its policies is fail, warn or error (a check that warned or could not run is not a pass), or if an image check on it failed or could not be done; **PASS** if it has at least one passing result and none of those; **SKIPPED** if every result was skipped; **NO DATA** if there is no result at all (no resource in scope, or no report yet).

## Controls: CIS Kubernetes Benchmark (numbering of v1.9)

| Control | Status | Kyverno results (pass / not pass) | Image checks (pass / not pass) | Policies |
|---|---|---|---|---|
| 5.1.6 | **FAIL** | 9 / 3 | - | forge-cis-sa-token |
| 5.2.2 | **FAIL** | 9 / 3 | - | forge-pss-privileged |
| 5.2.3 | **FAIL** | 11 / 1 | - | forge-pss-host-namespaces |
| 5.2.4 | **FAIL** | 11 / 1 | - | forge-pss-host-namespaces |
| 5.2.5 | **FAIL** | 11 / 1 | - | forge-pss-host-namespaces |
| 5.2.6 | **FAIL** | 7 / 5 | - | forge-pss-privilege-escalation |
| 5.2.7 | **FAIL** | 21 / 3 | - | forge-pss-run-as-non-root, forge-pss-run-as-user |
| 5.2.8 | **FAIL** | 10 / 2 | - | forge-pss-capabilities |
| 5.2.9 | **FAIL** | 10 / 2 | - | forge-pss-capabilities |
| 5.2.10 | **FAIL** | 10 / 2 | - | forge-pss-capabilities |
| 5.2.12 | **PASS** | 12 / 0 | - | forge-pss-host-path |
| 5.2.13 | **PASS** | 12 / 0 | - | forge-pss-host-ports |
| 5.4.1 | **PASS** | 12 / 0 | - | forge-cis-secrets-as-files |
| 5.7.2 | **FAIL** | 9 / 3 | - | forge-pss-seccomp |
| 5.7.4 | **PASS** | 12 / 0 | - | forge-cis-default-namespace |

## Controls: Pod Security Standards

| Control | Status | Kyverno results (pass / not pass) | Image checks (pass / not pass) | Policies |
|---|---|---|---|---|
| baseline: /proc Mount Type | **PASS** | 12 / 0 | - | forge-pss-proc-mount |
| baseline: AppArmor | **PASS** | 12 / 0 | - | forge-pss-apparmor |
| baseline: Host Namespaces | **FAIL** | 11 / 1 | - | forge-pss-host-namespaces |
| baseline: Host Ports | **PASS** | 12 / 0 | - | forge-pss-host-ports |
| baseline: HostPath Volumes | **PASS** | 12 / 0 | - | forge-pss-host-path |
| baseline: Privileged Containers | **FAIL** | 9 / 3 | - | forge-pss-privileged |
| baseline: SELinux | **PASS** | 12 / 0 | - | forge-pss-selinux |
| baseline: Sysctls | **PASS** | 12 / 0 | - | forge-pss-sysctls |
| restricted: Capabilities | **FAIL** | 10 / 2 | - | forge-pss-capabilities |
| restricted: Privilege Escalation | **FAIL** | 7 / 5 | - | forge-pss-privilege-escalation |
| restricted: Running as Non-root | **FAIL** | 9 / 3 | - | forge-pss-run-as-non-root |
| restricted: Running as Non-root user | **PASS** | 12 / 0 | - | forge-pss-run-as-user |
| restricted: Seccomp | **FAIL** | 9 / 3 | - | forge-pss-seccomp |
| restricted: Volume Types | **PASS** | 12 / 0 | - | forge-pss-volume-types |

## Findings

Every result that kept a control from passing. A Deployment and its Pod each have a report, and a policy that enforces several controls counts under each of them, so one cause can appear more than once.

### CIS 5.1.6

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-cis-sa-token | Deployment local-path-storage/local-path-provisioner | fail | set automountServiceAccountToken: false (CIS 5.1.6) |
| forge-cis-sa-token | Pod local-path-storage/local-path-provisioner-67b778fdf6-b7k79 | fail | set automountServiceAccountToken: false (CIS 5.1.6) |
| forge-cis-sa-token | Pod pt/fail-satoken | fail | set automountServiceAccountToken: false (CIS 5.1.6) |

### CIS 5.2.2

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-privileged | Deployment pt/fail-deployment | fail | privileged containers are not allowed (CIS 5.2.2, PSS baseline): app |
| forge-pss-privileged | Pod pt/fail-container | fail | privileged containers are not allowed (CIS 5.2.2, PSS baseline): app |
| forge-pss-privileged | Pod pt/fail-deployment-776df798fb-jm5k7 | fail | privileged containers are not allowed (CIS 5.2.2, PSS baseline): app |

### CIS 5.2.3

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-host-namespaces | Pod pt/fail-host-network | fail | sharing host namespaces is not allowed (CIS 5.2.3 to 5.2.5, PSS baseline): hostNetwork |

### CIS 5.2.4

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-host-namespaces | Pod pt/fail-host-network | fail | sharing host namespaces is not allowed (CIS 5.2.3 to 5.2.5, PSS baseline): hostNetwork |

### CIS 5.2.5

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-host-namespaces | Pod pt/fail-host-network | fail | sharing host namespaces is not allowed (CIS 5.2.3 to 5.2.5, PSS baseline): hostNetwork |

### CIS 5.2.6

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-privilege-escalation | Deployment local-path-storage/local-path-provisioner | fail | allowPrivilegeEscalation must be false (CIS 5.2.6, PSS restricted) for: local-path-provisioner |
| forge-pss-privilege-escalation | Deployment pt/fail-deployment | fail | allowPrivilegeEscalation must be false (CIS 5.2.6, PSS restricted) for: app |
| forge-pss-privilege-escalation | Pod local-path-storage/local-path-provisioner-67b778fdf6-b7k79 | fail | allowPrivilegeEscalation must be false (CIS 5.2.6, PSS restricted) for: local-path-provisioner |
| forge-pss-privilege-escalation | Pod pt/fail-container | fail | allowPrivilegeEscalation must be false (CIS 5.2.6, PSS restricted) for: app |
| forge-pss-privilege-escalation | Pod pt/fail-deployment-776df798fb-jm5k7 | fail | allowPrivilegeEscalation must be false (CIS 5.2.6, PSS restricted) for: app |

### CIS 5.2.7

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-run-as-non-root | Deployment local-path-storage/local-path-provisioner | fail | runAsNonRoot must be true (CIS 5.2.7, PSS restricted) for: local-path-provisioner |
| forge-pss-run-as-non-root | Pod local-path-storage/local-path-provisioner-67b778fdf6-b7k79 | fail | runAsNonRoot must be true (CIS 5.2.7, PSS restricted) for: local-path-provisioner |
| forge-pss-run-as-non-root | Pod pt/fail-unset | fail | runAsNonRoot must be true (CIS 5.2.7, PSS restricted) for: app |

### CIS 5.2.8

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-capabilities | Deployment local-path-storage/local-path-provisioner | fail | capabilities must drop ALL (CIS 5.2.10, PSS restricted) for: local-path-provisioner |
| forge-pss-capabilities | Pod local-path-storage/local-path-provisioner-67b778fdf6-b7k79 | fail | capabilities must drop ALL (CIS 5.2.10, PSS restricted) for: local-path-provisioner |

### CIS 5.2.9

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-capabilities | Deployment local-path-storage/local-path-provisioner | fail | capabilities must drop ALL (CIS 5.2.10, PSS restricted) for: local-path-provisioner |
| forge-pss-capabilities | Pod local-path-storage/local-path-provisioner-67b778fdf6-b7k79 | fail | capabilities must drop ALL (CIS 5.2.10, PSS restricted) for: local-path-provisioner |

### CIS 5.2.10

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-capabilities | Deployment local-path-storage/local-path-provisioner | fail | capabilities must drop ALL (CIS 5.2.10, PSS restricted) for: local-path-provisioner |
| forge-pss-capabilities | Pod local-path-storage/local-path-provisioner-67b778fdf6-b7k79 | fail | capabilities must drop ALL (CIS 5.2.10, PSS restricted) for: local-path-provisioner |

### CIS 5.7.2

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-seccomp | Deployment local-path-storage/local-path-provisioner | fail | a seccomp profile (RuntimeDefault or Localhost) is required (CIS 5.7.2, PSS restricted) for: local-path-provisioner |
| forge-pss-seccomp | Pod local-path-storage/local-path-provisioner-67b778fdf6-b7k79 | fail | a seccomp profile (RuntimeDefault or Localhost) is required (CIS 5.7.2, PSS restricted) for: local-path-provisioner |
| forge-pss-seccomp | Pod pt/fail-seccomp | fail | a seccomp profile (RuntimeDefault or Localhost) is required (CIS 5.7.2, PSS restricted) for: app |

### PSS baseline: Host Namespaces

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-host-namespaces | Pod pt/fail-host-network | fail | sharing host namespaces is not allowed (CIS 5.2.3 to 5.2.5, PSS baseline): hostNetwork |

### PSS baseline: Privileged Containers

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-privileged | Deployment pt/fail-deployment | fail | privileged containers are not allowed (CIS 5.2.2, PSS baseline): app |
| forge-pss-privileged | Pod pt/fail-container | fail | privileged containers are not allowed (CIS 5.2.2, PSS baseline): app |
| forge-pss-privileged | Pod pt/fail-deployment-776df798fb-jm5k7 | fail | privileged containers are not allowed (CIS 5.2.2, PSS baseline): app |

### PSS restricted: Capabilities

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-capabilities | Deployment local-path-storage/local-path-provisioner | fail | capabilities must drop ALL (CIS 5.2.10, PSS restricted) for: local-path-provisioner |
| forge-pss-capabilities | Pod local-path-storage/local-path-provisioner-67b778fdf6-b7k79 | fail | capabilities must drop ALL (CIS 5.2.10, PSS restricted) for: local-path-provisioner |

### PSS restricted: Privilege Escalation

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-privilege-escalation | Deployment local-path-storage/local-path-provisioner | fail | allowPrivilegeEscalation must be false (CIS 5.2.6, PSS restricted) for: local-path-provisioner |
| forge-pss-privilege-escalation | Deployment pt/fail-deployment | fail | allowPrivilegeEscalation must be false (CIS 5.2.6, PSS restricted) for: app |
| forge-pss-privilege-escalation | Pod local-path-storage/local-path-provisioner-67b778fdf6-b7k79 | fail | allowPrivilegeEscalation must be false (CIS 5.2.6, PSS restricted) for: local-path-provisioner |
| forge-pss-privilege-escalation | Pod pt/fail-container | fail | allowPrivilegeEscalation must be false (CIS 5.2.6, PSS restricted) for: app |
| forge-pss-privilege-escalation | Pod pt/fail-deployment-776df798fb-jm5k7 | fail | allowPrivilegeEscalation must be false (CIS 5.2.6, PSS restricted) for: app |

### PSS restricted: Running as Non-root

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-run-as-non-root | Deployment local-path-storage/local-path-provisioner | fail | runAsNonRoot must be true (CIS 5.2.7, PSS restricted) for: local-path-provisioner |
| forge-pss-run-as-non-root | Pod local-path-storage/local-path-provisioner-67b778fdf6-b7k79 | fail | runAsNonRoot must be true (CIS 5.2.7, PSS restricted) for: local-path-provisioner |
| forge-pss-run-as-non-root | Pod pt/fail-unset | fail | runAsNonRoot must be true (CIS 5.2.7, PSS restricted) for: app |

### PSS restricted: Seccomp

| Policy | Resource | Result | Message |
|---|---|---|---|
| forge-pss-seccomp | Deployment local-path-storage/local-path-provisioner | fail | a seccomp profile (RuntimeDefault or Localhost) is required (CIS 5.7.2, PSS restricted) for: local-path-provisioner |
| forge-pss-seccomp | Pod local-path-storage/local-path-provisioner-67b778fdf6-b7k79 | fail | a seccomp profile (RuntimeDefault or Localhost) is required (CIS 5.7.2, PSS restricted) for: local-path-provisioner |
| forge-pss-seccomp | Pod pt/fail-seccomp | fail | a seccomp profile (RuntimeDefault or Localhost) is required (CIS 5.7.2, PSS restricted) for: app |

## Scope and limits

- 12 PolicyReports, 204 results, 12 resources; results written between 2026-10-17T14:47:17Z and 2026-10-17T14:47:25Z (newest is 13m0s older than this report)
- Only controls that a Forge policy enforces appear here. This is not a full CIS Kubernetes Benchmark audit.
- Results exist only for resources that exist when the report is made. A pod that was refused at admission leaves no PolicyReport entry.
- Ephemeral containers (kubectl debug) are not covered by the pod policies.
- A result is as old as the last Kyverno background scan; see the oldest and newest result times.
- Namespaces listed as excluded by a policy are not evaluated by it.
- Rekor evidence (certificate, log entry, inclusion proof) is verified by cosign, not by conformity; tree size and root hash shown come from the log's signed checkpoint.

### Policies

| Policy | Kind | Ready | Actions | Controls |
|---|---|---|---|---|
| forge-cis-default-namespace | ValidatingPolicy | yes | Deny, Audit | CIS 5.7.4 |
| forge-cis-sa-token | ValidatingPolicy | yes | Deny, Audit | CIS 5.1.6 |
| forge-cis-secrets-as-files | ValidatingPolicy | yes | Deny, Audit | CIS 5.4.1 |
| forge-pss-apparmor | ValidatingPolicy | yes | Deny, Audit | PSS baseline: AppArmor |
| forge-pss-capabilities | ValidatingPolicy | yes | Deny, Audit | CIS 5.2.8; CIS 5.2.9; CIS 5.2.10; PSS restricted: Capabilities |
| forge-pss-host-namespaces | ValidatingPolicy | yes | Deny, Audit | CIS 5.2.3; CIS 5.2.4; CIS 5.2.5; PSS baseline: Host Namespaces |
| forge-pss-host-path | ValidatingPolicy | yes | Deny, Audit | CIS 5.2.12; PSS baseline: HostPath Volumes |
| forge-pss-host-ports | ValidatingPolicy | yes | Deny, Audit | CIS 5.2.13; PSS baseline: Host Ports |
| forge-pss-privilege-escalation | ValidatingPolicy | yes | Deny, Audit | CIS 5.2.6; PSS restricted: Privilege Escalation |
| forge-pss-privileged | ValidatingPolicy | yes | Deny, Audit | CIS 5.2.2; PSS baseline: Privileged Containers |
| forge-pss-proc-mount | ValidatingPolicy | yes | Deny, Audit | PSS baseline: /proc Mount Type |
| forge-pss-run-as-non-root | ValidatingPolicy | yes | Deny, Audit | CIS 5.2.7; PSS restricted: Running as Non-root |
| forge-pss-run-as-user | ValidatingPolicy | yes | Deny, Audit | CIS 5.2.7; PSS restricted: Running as Non-root user |
| forge-pss-seccomp | ValidatingPolicy | yes | Deny, Audit | CIS 5.7.2; PSS restricted: Seccomp |
| forge-pss-selinux | ValidatingPolicy | yes | Deny, Audit | PSS baseline: SELinux |
| forge-pss-sysctls | ValidatingPolicy | yes | Deny, Audit | PSS baseline: Sysctls |
| forge-pss-volume-types | ValidatingPolicy | yes | Deny, Audit | PSS restricted: Volume Types |

Namespaces a policy leaves out:

- argocd, kube-node-lease, kube-public, kube-system, kyverno, monitoring, policy-reporter: 17 policies (forge-cis-default-namespace, forge-cis-sa-token, forge-cis-secrets-as-files, forge-pss-apparmor, forge-pss-capabilities, forge-pss-host-namespaces, forge-pss-host-path, forge-pss-host-ports, forge-pss-privilege-escalation, forge-pss-privileged, forge-pss-proc-mount, forge-pss-run-as-non-root, forge-pss-run-as-user, forge-pss-seccomp, forge-pss-selinux, forge-pss-sysctls, forge-pss-volume-types)

### Inputs

29 documents were read. SHA-256 over the sorted list (kind, namespace/name, SHA-256 of each document with managedFields left out): `61340b519a57f1386f0a434114226765d1ae36cf6c5f63556d638fada004af0c`. The list is in `report.json`.
