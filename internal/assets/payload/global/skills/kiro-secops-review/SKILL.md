---
name: kiro-secops-review
description: Code security review (kiro-secops) — OWASP vulnerabilities, CWEs, secrets, and dependencies in Python, TypeScript/Node, and Shell. Use when reviewing PRs/diffs, touching authentication/authorization/cryptography/IAM/IaC, adding endpoints, or before a release.
license: MIT-0
---

# kiro-secops Review

Reusable, **standalone** security review workflow, portable across projects.
Apply it to a diff, PR, or set of files. Aligned with **OWASP Top 10 2025 + ASVS L1/L2**,
classifying findings by **CWE**, and with the **AWS Well-Architected Security Pillar**.

## When to run (triggers)
New endpoint/route; change in authN/authZ/session; new input handling; database query/model;
file uploads; payment/PII code; dependencies added/updated; before deploy.

## Step 1 — Scope
`git diff` / `git status`; identify the affected *trust boundaries*. Prioritize auth, crypto,
external input, IAM/IaC, and dependencies.

## Step 2 — Checklist (OWASP Top 10 2025 + ASVS L1/L2)
1. Deny-by-default access control; IDOR (A01, CWE-284/639); SSRF (CWE-918); path traversal (CWE-22)
2. Security misconfiguration (A02): security headers / CSP (CWE-693), no debug / verbose errors in
   prod (CWE-209/489), CORS (CWE-942), XXE (CWE-611), default creds. **IaC/Terraform:** no public
   buckets, open SGs (0.0.0.0/0), unencrypted storage, IAM `*:*` (`trivy config` / `checkov`)
3. Supply chain (A03): dependencies without critical CVE, pinned lockfile (CWE-1104)
4. Strong cryptography + crypto PRNG + key management; no cleartext transmission (A04, CWE-327/338/319)
5. Injection: SQL/NoSQL/command/XSS/SSTI (A05, CWE-89/943/78/79/1336)
6. Insecure design (A06): rate limiting / anti-automation (CWE-307/799), business-logic abuse cases
   — see `references/threat-model-template.md`
7. Authentication (A07): JWT signature verification, no `alg:none` (CWE-347); session management
   (CWE-384); brute-force / lockout (CWE-307)
8. Software / data integrity (A08): safe deserialization (CWE-502); verified/pinned deps & CI
9. Hardcoded secrets (A04/A02, CWE-798) — incl. `NEXT_PUBLIC_*` / `VITE_*` exposed to the client
10. Logging & alerting (A09): no PII/secrets in logs (CWE-532) + sufficient logging / alerting of
    security events (CWE-778)
11. Mishandling of exceptional conditions (A10): robust error handling — no fail-open / unhandled
    exceptions (CWE-703/755)

Details per language: `references/owasp-python.md`, `owasp-node.md`, `owasp-shell.md` (+ go/java/rust).
**ASVS L1** checklist (Definition of Done): `references/owasp-asvs-l1.md`. **STRIDE** threat model template for `design.md`: `references/threat-model-template.md`.

## Step 3 — Secrets
```bash
gitleaks detect --no-git --redact --source .
git log -p | grep -Ei "api[_-]?key|password|secret|token" || true   # history
```

## Step 4 — SAST + security lint (per language)
```bash
# Cross-language
semgrep scan --config p/owasp-top-ten --config p/secrets --error
# Python
bandit -r . -ll ;  ruff check --select S .
# TypeScript/Node  (eslint-plugin-security + typescript-eslint)
npx eslint . ;  njsscan -w .
# Shell
shellcheck --severity=warning $(git ls-files '*.sh')
# IaC
trivy config . ;  checkov -d .
```

## Step 5 — SCA per ecosystem
| Language | Command |
|---|---|
| Node/TS | `npm audit --audit-level=high` (or `pnpm audit` / `yarn npm audit`); `retire` |
| Python | `pip-audit` (or `safety check`) |
| Go | `govulncheck ./...` |
| Rust | `cargo audit` |
| Java | `mvn org.owasp:dependency-check-maven:check` / `gradle dependencyCheckAnalyze` |
| Cross-lang | `trivy fs --scanners vuln .` |

## Step 6 — Report (structured)
Use the per-finding schema:
```
[SEVERITY] <scanner/rule>  file:line
  CWE: CWE-89   OWASP: A05:2025
  Evidence: <snippet and why it is vulnerable>
  Fix:      <secure code>
  Source:   <URL / rule id>
```
Rules: **deduplicate** repeated findings; sort by severity; at the end **total by severity**
and give the **release verdict** — *do not deploy while there are Critical/High*.
Prefer to **export SARIF** and attach it to the repository's code scanning (traceability — AWS WA
*maintain traceability*):
```bash
bandit -f sarif -o bandit.sarif -r .
semgrep scan --sarif -o semgrep.sarif
njsscan --sarif -o njsscan.sarif .
trivy fs --format sarif -o trivy.sarif .
```
