# "day 0" controls catalog — AWS + community → Kiro mechanisms

This catalog lists **what** to enforce (security controls from official and community sources)
and **how** Kiro enforces each one (this project's mechanism). It is the bridge between security
theory and the artifacts in `.kiro/`.

Mechanism legend: **PERM** = `permissions.yaml` · **GUARD** = `kiro-secops guard` binary ·
**HOOK** = `.kiro/hooks` · **STEER** = `.kiro/steering` · **AGENT** = `kiro-secops-reviewer` ·
**SKILL** = `kiro-secops-review` · **SCAN** = `kiro-secops scan` · **PIPE** = pre-commit/CI ·
**RELEASE** = release pipeline (goreleaser).

**Status** legend:

| Status | Meaning |
|---|---|
| **ENFORCED** | Deterministic block/decision enforced by the solution (permissions/guard/CI/release). |
| **ADVISORY** | Guides or warns, but does **not** block (steering, skills, prompts, `scan --advisory`, pre-commit bypassable with `--no-verify`). |
| **EXTERNAL-AWS** | Must be applied **in the AWS account** — the CLI documents it, does not configure it. |
| **NOT-IMPLEMENTED** | Planned/roadmap; not yet delivered by the solution. |

---

## Part 0 — Traceable controls matrix

Each row: **control → status → mechanism → evidence (file) → automated test**.
"Evidence" points to the source file in the repository; "Test" points to the test that covers the
behavior (when applicable).

### Local enforcement (personal baseline in `~/.kiro`)

| Control | Status | Mechanism | Evidence (file) | Test |
|---|---|---|---|---|
| Agent does not read secrets (`.env`, keys, `credentials`) | ENFORCED | PERM `fs_read: deny` | `internal/assets/payload/global/settings/permissions.yaml` | — (evaluated by Kiro) |
| Agent does not write/remove secrets | ENFORCED | PERM `fs_write: deny` + GUARD `denyWriteRE` | `permissions.yaml`; `internal/app/guard.go` | `guard_test.go::TestGuardEval` |
| Destructive/exfiltration commands blocked (`rm -rf /`, `curl\|sh`, reverse shell, `mkfs`, `dd`) | ENFORCED | PERM `shell: deny` + GUARD `blockRE` | `permissions.yaml`; `internal/app/guard.go` | `guard_test.go::TestGuardEval` |
| High impact asks for confirmation (`sudo`, `terraform apply/destroy`, `kubectl delete`, `git push --force`) | ENFORCED | PERM `effect: ask` | `permissions.yaml` (+ `profiles/strict.yaml`) | — (evaluated by Kiro) |
| Guard fails closed (invalid JSON/unknown schema/large payload → blocks) | ENFORCED | GUARD | `internal/app/guard.go::cmdGuard` | `guard_test.go`, `cmd_test.go::TestCmdGuard` |
| Hook calls the binary by a validated **absolute path** (no PATH hijack) | ENFORCED | HOOK + `hooks.go` | `internal/app/hooks.go`; payload `kiro/hooks/kiro-secops.json` | `initcmd_test.go::TestInitScaffold`, `hooks_test.go` |
| `.kiroignore` hides `.env`/keys from the context | ENFORCED | PERM/ignore | `internal/assets/payload/global/settings/kiroignore` | `merge_test.go::TestMergeKiroignore*` |
| Selectable, versioned policy profile (`baseline`/`strict`; strict ⊇ baseline) | ENFORCED | PERM + `--profile` | `install.go`; `payload/global/settings/profiles/strict.yaml` | `install_test.go::TestInstallProfileStrict`, `payload_consistency_test.go::TestStrictProfileIsSupersetOfBaseline` |
| Org-distributable Administration profile (deny/ask only; ⊇ baseline restrictions) | ENFORCED (template invariant; deployment is org-side, see [`ENTERPRISE.md`](ENTERPRISE.md)) | PERM (Administration scope) | `payload/global/settings/profiles/admin.yaml` | `payload_consistency_test.go::TestAdminProfile*` |
| Canonical secret set consistent across ALL layers (permissions, strict, agent, kiroignore, guard, guard-write.sh) | ENFORCED | PERM + GUARD + ignore (anti-drift test) | `internal/app/payload_consistency_test.go` | `payload_consistency_test.go::TestProfilesCoverCanonicalSecrets` et al. |
| Transactional installation with ownership + rollback + exact restore | ENFORCED | `manifest.go`/`safefs.go` | `internal/app/manifest.go`, `internal/app/safefs.go` | `manifest_test.go`, `kirohome_test.go` |
| Verifiable installation integrity (hash vs manifest) | ENFORCED | `verify --strict` | `internal/app/verify.go` | `cmd_test.go::TestCmdVerifyStrictAfterInstall` |
| Workspace hook health — detects the post-clone silent fail-open (hook pinned to a foreign path exits 127 and never blocks) | ENFORCED | `verify --project` | `internal/app/verify.go`, `internal/app/hooks.go` | `verify_workspace_test.go::TestVerifyProjectDetectsForeignBinaryPath` |
| Secure coding (OWASP Top 10) as policy | ADVISORY | STEER | `payload/global/steering/security-policies.md` | — |
| On-demand AppSec review (OWASP→CWE, ASVS L1) | ADVISORY | AGENT + SKILL | `payload/global/agents/…`; `payload/global/skills/kiro-secops-review/` | — |
| Review gate at the end of the turn | ADVISORY | HOOK `Stop` (agent) | `payload/workspace/kiro/hooks/kiro-secops.json` | `initcmd_test.go` |
| Scan at the end of the task | ADVISORY | HOOK `PostTaskExec` → `scan --advisory` | `payload/workspace/kiro/hooks/kiro-secops.json`; `scan.go` | `cmd_test.go::TestCmdScan*` |
| Injection of Security Requirements / Threat Model into the SDD | ADVISORY | HOOK `PostFileCreate` (agent) | `payload/workspace/kiro/hooks/kiro-secops.json` | `initcmd_test.go` |
| Secret scan **on save** (on every saved file) | NOT-IMPLEMENTED | bash reference `gitleaks-scan.sh` (not deployed) | `payload/workspace/scripts/gitleaks-scan.sh` | — |

### Pipeline enforcement (per project that adopts the scaffold)

| Control | Status | Mechanism | Evidence (file) | Test |
|---|---|---|---|---|
| SAST/SCA/IaC/secret as a **blocking** gate on the PR | ENFORCED (CI) | PIPE | `payload/workspace/github/workflows/security-scan.yml` | `actionlint` in CI |
| `kiro-secops scan` blocks findings (gate) | ENFORCED | SCAN (exit 1; `--advisory` only reports) | `internal/app/scan.go` | `cmd_test.go::TestCmdScan` |
| Structured scan report (JSON + SARIF for code scanning) | ENFORCED | SCAN `--format json\|sarif` | `internal/app/scanreport.go` | `cmd_test.go::TestScanReport{JSON,SARIF}` |
| Local shift-left (secrets/SAST/IaC/SCA) | ADVISORY | PIPE (pre-commit; bypassable with `--no-verify`) | `payload/workspace/pre-commit-config.yaml` | — |
| SBOM per release (SPDX/CycloneDX) | ENFORCED (release) | RELEASE (syft/trivy) | `.goreleaser.yaml` | `goreleaser check` in CI |
| Keyless signing of checksums (cosign/OIDC) | ENFORCED (release) | RELEASE | `.goreleaser.yaml` | — |
| SLSA provenance of artifacts (template for fork) | ENFORCED (release, in the fork) | RELEASE `attest-build-provenance` | `examples/release/release.yml` (template) | — |
| Actions pinned by commit SHA + Dependabot | ENFORCED | PIPE | `.github/workflows/*.yml`; `.github/dependabot.yml` | `actionlint` |
| Reachable vulnerabilities (stdlib/deps) | ENFORCED (CI) | PIPE (govulncheck) | `.github/workflows/ci.yml` (`vuln` job) | `vuln` job |

### AWS account controls (outside the CLI)

| Control | Status | Where to apply | Source |
|---|---|---|---|
| Security Hub (FSBP + CIS) | EXTERNAL-AWS | Account/Organization | [standards](https://docs.aws.amazon.com/securityhub/latest/userguide/standards-reference.html) |
| GuardDuty org-wide | EXTERNAL-AWS | Organization | [findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-summary.html) |
| CloudTrail multi-Region + log file validation | EXTERNAL-AWS | Organization | [best practices](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html) |
| SCPs denying the disabling of CloudTrail/GuardDuty/Config | EXTERNAL-AWS | Organization | [SCP examples](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html) |
| Amazon Inspector Code Security (SAST/SCA/IaC) | EXTERNAL-AWS | Account | [code security](https://docs.aws.amazon.com/inspector/latest/user/code-security-assessments.html) |
| ECR enhanced scanning (detection; blocking requires a policy in the pipeline) | EXTERNAL-AWS | Account/registry | [enhanced scanning](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-enhanced.html) |
| Secrets Manager (KMS + rotation) / SSM SecureString | EXTERNAL-AWS | Account | [best practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html) |
| Macie (sensitive data) | EXTERNAL-AWS | Account | [what is Macie](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html) |

> **Fleet distribution:** MDM with *drift correction* — the guide (Administration scope,
> governance console, identity, scheduled `verify --strict`) is in
> [`ENTERPRISE.md`](ENTERPRISE.md). The MDM tooling itself is external, like EXTERNAL-AWS.

---

## Part A — AWS baseline (official sources)

### A1. Well-Architected — Security Pillar
Seven design principles: (1) strong identity foundation / least privilege; (2) traceability
(monitor/alert/audit); (3) security at all layers (defense-in-depth);
(4) **automate best practices as versioned code**; (5) protect data in transit and at
rest; (6) keep people away from data; (7) prepare for events.

Source: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/security.html ·
design principles: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/design-principles.html

### A2. Foundational Security Best Practices (FSBP) standard
AWS + industry compilation of controls that continuously evaluate accounts and resources for
deviations from best practices, grouped by security function (Identify / Protect / Detect /
Respond / Recover). Runs as a **detective** standard in Security Hub CSPM.

kiro-secops mirrors the most critical FSBP controls **preventively** (shift-left) in the
`infrastructure-security.md` steering and the IaC scanners (checkov / trivy config) — e.g.
block public access, encryption at rest by default, no `0.0.0.0/0` on admin ports, IMDSv2,
CloudTrail multi-Region with log file validation.

Source: https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html ·
control categories: https://docs.aws.amazon.com/securityhub/latest/userguide/control-categories.html

### A3. CI/CD pipeline security
Never put secrets in plain text (they show up in logs) — use **Secrets Manager**/**SSM**;
artifacts with SSE-KMS; builds in a private VPC; webhooks with filters.

- **Security Hub `CodeBuild.1`** — source URL (Bitbucket) without credentials (Critical).
- **Security Hub `CodeBuild.2`** — env vars without `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (Critical).
- **`CodeBuild.3`** — CodeBuild S3 logs encrypted.
- **`CodeBuild.4`** — logging (S3 or CloudWatch) enabled.
- **`CodeBuild.7`** — report group export encrypted.
- *(`CodeBuild.5`, privileged mode, was **retired** by Security Hub in Apr/2024; the AWS Config
  rule `codebuild-project-environment-privileged-check` remains useful.)*

Sources: https://docs.aws.amazon.com/codepipeline/latest/userguide/security-best-practices.html ·
CodeBuild controls: https://docs.aws.amazon.com/securityhub/latest/userguide/codebuild-controls.html ·
webhooks: https://docs.aws.amazon.com/codebuild/latest/userguide/webhooks.html ·
VPC: https://docs.aws.amazon.com/codebuild/latest/userguide/vpc-support.html

### A4. Policy as Code
**cfn-guard** (preventive shift-left + server-side CloudFormation Hooks), **AWS Config custom
rules** (proactive/detective), **conformance packs**, **SCPs** (org guardrails),
**IAM least-privilege** + Access Analyzer.

Sources: https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html ·
https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

### A5. Scanning
**Amazon Inspector Code Security** (SAST/SCA/IaC), **Inspector SBOM Generator/Scan API** (CI/CD),
**ECR enhanced scanning** (detection via Inspector), **Macie** (sensitive data), **Amazon Q
Developer** code reviews.

| Control | Status | Kiro mechanism |
|---|---|---|
| SAST/SCA/IaC mandatory | ENFORCED (CI) / ENFORCED (`scan`) | PIPE (semgrep/trivy/checkov) + `kiro-secops scan` (blocking) |
| Scan report for code scanning | ENFORCED | `kiro-secops scan --format sarif --output scan.sarif` |
| SBOM per build | ENFORCED (release) | RELEASE (syft) + PIPE (trivy SPDX) |
| Block Critical/High image | ENFORCED (CI) | PIPE (`trivy image --exit-code 1`) |

> The `payload/workspace/scripts/security-scan.sh` script is a **bash reference**; the real,
> cross-platform scan is done by the binary (`scan`, incl. `PostTaskExec` hook).

Sources: https://docs.aws.amazon.com/inspector/latest/user/code-security-assessments.html ·
https://docs.aws.amazon.com/inspector/latest/user/scanning-cicd.html ·
https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-enhanced.html

### A6. Secrets
**Secrets Manager** (KMS + automatic rotation), **SSM Parameter Store** SecureString. Prohibit
hardcoded secrets.

| Control | Status | Kiro mechanism |
|---|---|---|
| Prohibit reading/writing of secrets by the agent | ENFORCED | PERM (`fs_read`/`fs_write: deny`) + GUARD + `.kiroignore` |
| Detect hardcoded secret | ENFORCED (`scan`/CI) | `kiro-secops scan` + PIPE (gitleaks) |

Source: https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html

### A7. Governance / Detection
**Security Hub** as the aggregation/scoring plane for the enabled standards (FSBP is detailed in
A2; CIS optional), **GuardDuty** org-wide, **CloudTrail** multi-Region with **log file
validation**. SCPs denying the disabling of these services. All **EXTERNAL-AWS** (see Part 0 and D).

Anchor the org-wide layout on the **AWS Security Reference Architecture (SRA)** — delegated
administrator, dedicated Log Archive and Security Tooling accounts, and the prescriptive
checklist for where each security service should be deployed.

Source: https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/checklist.html

---

## Part B — Community baseline (frameworks + tools)

### B1. Secure SDLC frameworks
- **OWASP ASVS** — verifiable requirements V1–V14; use **L1 as the Definition of Done**. https://owasp.org/www-project-application-security-verification-standard/
- **OWASP Top 10 (2025)** — triage taxonomy; SAST ruleset. https://owasp.org/Top10/2025/
- **OWASP API Security Top 10 (2023)** — taxonomy for endpoints/APIs. https://owasp.org/API-Security/editions/2023/en/0x00-header/
- **OWASP SAMM** — program maturity. https://owaspsamm.org/model/
- **NIST SSDF SP 800-218** — PO/PS/PW/RV. https://csrc.nist.gov/pubs/sp/800/218/final
- **SLSA v1.0** — build provenance/signing (supply chain). https://slsa.dev/spec/v1.0/levels
- **CIS Benchmarks** — hardening. https://www.cisecurity.org/cis-benchmarks

### B2. Shift-left categories (where each scanner fits)

| Category | Where in the pipeline | OSS tool |
|---|---|---|
| SAST | pre-commit → PR/CI | Semgrep |
| Secret scanning | pre-commit (critical) → CI → server-side | Gitleaks, TruffleHog |
| SCA | PR/CI → continuous | Trivy, OWASP Dependency-Check, Grype |
| IaC scanning | pre-commit → PR/CI | Checkov, Trivy config |
| Container scanning | CI post-build → admission | Trivy, Grype |
| DAST | staging/QA | OWASP ZAP, Nuclei |
| SBOM | build → release | Syft, Trivy |

> **tfsec has been consolidated into Trivy** — for new projects use `trivy config`.

### B3. Reference commands (used by the hooks/pipeline)
```bash
# SAST
semgrep scan --config p/owasp-top-ten --config p/secrets --error
# Secrets
gitleaks detect --source . -v
# SCA/IaC/secret/misconfig in a single scan
trivy fs --scanners vuln,secret,misconfig .
# Container (fails on High/Critical)
trivy image --severity HIGH,CRITICAL --exit-code 1 myimage:latest
# IaC
checkov -d .
# SBOM
trivy image --format spdx-json --output sbom.json myimage:latest
# Unified gate with SARIF report (kiro-secops)
kiro-secops scan --format sarif --output scan.sarif .
```
Sources: https://semgrep.dev/docs/ · https://trivy.dev/ · https://github.com/gitleaks/gitleaks ·
https://www.checkov.io/ · https://owasp.org/www-project-dependency-check/

### B4. Threat modeling (STRIDE)
Analyze the design via DFDs and trust boundaries. Each letter is the inverse of a property:
Spoofing↔authentication, Tampering↔integrity, Repudiation↔non-repudiation, Information
Disclosure↔confidentiality, Denial of Service↔availability, Elevation of
Privilege↔authorization. As-code: OWASP Threat Dragon, pytm, Threagile.
→ **STRIDE** template (reference from the `kiro-secops-review` skill), used in the `design.md` of the specs.
Sources: https://owasp.org/www-project-threat-dragon/ · https://github.com/izar/pytm

---

## Part C — Minimum "day 0" set (consolidated checklist)

- [ ] `permissions.yaml` with `deny` for reading/writing secrets and destructive commands (**PERM**)
- [ ] `.kiroignore` hiding `.env`/keys/credentials (**PERM**)
- [ ] Guard `PreToolUse` hooks (shell + write) calling the binary by absolute path (**GUARD/HOOK**)
- [ ] Review gate on `Stop` + advisory scan on `PostTaskExec` (**HOOK/SCAN**)
- [ ] Steering `always` with a secure coding policy (**STEER**)
- [ ] `kiro-secops-reviewer` agent (**AGENT**) + `kiro-secops-review` skill (**SKILL**)
- [ ] SDD hooks injecting Security Requirements / Threat Model (**HOOK**)
- [ ] pre-commit with gitleaks + semgrep + checkov + trivy (**PIPE**)
- [ ] CI with a blocking gate (secrets/SAST/SCA/IaC) + SBOM + SARIF report (**PIPE/SCAN**)
- [ ] Release with checksums + cosign + SBOM + SLSA provenance (**RELEASE**)
- [ ] ASVS L1 as the Definition of Done; threat model for changes to trust boundaries

---

## Part D — AWS application by context

The AWS controls above are **EXTERNAL-AWS**: the CLI documents them, but the account is what
applies them. Below, the same baseline separated by **where** it runs. Make it clear in reviews
which context is in play — the mechanisms differ.

### D1. GitHub Actions-based CI (what the solution delivers)
This is the context the scaffold covers directly.

- Blocking gate `security-scan.yml` (gitleaks/semgrep/trivy/checkov) — **ENFORCED (CI)**.
- `kiro-secops scan --format sarif --output scan.sarif` + `github/codeql-action/upload-sarif`
  for code scanning alerts.
- minimal `permissions:` in the workflow, Actions by **SHA**, OIDC instead of a static key,
  no `pull_request_target` with untrusted checkout.

Sources: Actions hardening https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions ·
artifact attestations https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds

### D2. AWS CodeBuild / CodePipeline-based CI (apply in the account)
Mirror the same scanners in a `buildspec.yml`, but the platform controls are **EXTERNAL-AWS**:

- **Secrets:** never in a plain-text env var (`CodeBuild.1`/`CodeBuild.2`); use Secrets
  Manager/SSM referenced in the buildspec.
- **Encryption:** encrypted S3 logs and report groups (`CodeBuild.3`/`CodeBuild.7`); pipeline
  artifacts with SSE-KMS.
- **Logging:** S3 or CloudWatch enabled (`CodeBuild.4`).
- **Network:** builds in private subnets (NAT/endpoints), no ingress; inline/S3 buildspec and
  webhook filters (`ACTOR_ACCOUNT_ID`, `FILE_PATH`) for public repositories.
- **IAM:** build service role with the minimum necessary (separate test from deploy).

Sources: https://docs.aws.amazon.com/codepipeline/latest/userguide/security-best-practices.html ·
https://docs.aws.amazon.com/codebuild/latest/userguide/security.html

### D3. Account-level / organization controls (apply via IaC/Org)
They are independent of any specific pipeline — they are the account "floor":

- **Detection:** Security Hub (FSBP+CIS), GuardDuty org-wide, CloudTrail multi-Region + log file
  validation, AWS Config + conformance packs.
- **Guardrails:** SCPs denying the disabling of CloudTrail/GuardDuty/Config; IAM least-privilege +
  Access Analyzer.
- **Data:** Secrets Manager (rotation + KMS), Macie, default encryption for S3/EBS/RDS.
- **Platform scanning:** Amazon Inspector (EC2/ECR/Lambda) and ECR enhanced scanning with a
  Critical/High blocking policy at deploy (EventBridge/admission).

> These items are **not** configured by `kiro-secops`. Treat them as account prerequisites and
> apply them via IaC (CloudFormation/Terraform) reviewed by the baseline itself (SAST/IaC scan).

*Compliance note: content from sources was paraphrased/summarized; CLI/config examples are
functional and written for this project.*
