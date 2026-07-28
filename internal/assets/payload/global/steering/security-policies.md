---
inclusion: always
---

# Security Policy (mandatory across the entire project)

These rules apply to ALL code generation, review, and execution in this repository.
They guide behavior; deterministic enforcement comes from `permissions.yaml` and the
hooks in `.kiro/hooks/`. Treat this file as code — changes require review.

## Secure coding (OWASP Top 10 2025)
- **A01 Broken Access Control:** authorization verified on the server for every route; deny by
  default; validate object ownership (no IDOR). SSRF is consolidated here — outbound requests
  only to allowlisted destinations.
- **A02 Security Misconfiguration:** minimal surface; no insecure defaults; security headers in web
  apps (CSP, HSTS, X-Content-Type-Options). IaC hardened — no public storage, no open security
  groups (0.0.0.0/0), no over-permissive IAM.
- **A03 Software Supply Chain Failures:** dependencies pinned (lockfile), from trusted sources,
  without known critical CVEs (run SCA); beware of install-time scripts (`postinstall`).
- **A04 Cryptographic Failures:** strong, current algorithms; TLS for all communication; sensitive
  data encrypted at rest. MD5/SHA1/DES/ECB prohibited for security purposes.
- **A05 Injection:** every query MUST be parameterized — never concatenate input into SQL/NoSQL/
  OS commands. Output encoding according to context (anti-XSS).
- **A07 Authentication Failures:** verify JWT signatures (reject `alg:none`); robust session
  management (rotation, secure/HttpOnly cookies); brute-force / lockout protection; MFA where applicable.
- **A08 Software & Data Integrity Failures:** no deserialization of untrusted data; verify the
  integrity of artifacts/updates (signatures, checksums); protect the CI/CD pipeline.
- **A09 Logging & Alerting Failures:** log security events (authN/authZ, failures) without PII or
  secrets; ensure the events are actually monitored and alerted on.
- **A10 Mishandling of Exceptional Conditions:** robust error handling; no fail-open paths; never
  leak stack traces or internal details in responses.

## Secrets
- **Prohibited** to hardcode credentials, API keys, tokens, or passwords — in any file
  (including code, tests, steering, specs, and docs).
- Secrets come from a secret manager (AWS Secrets Manager / SSM Parameter Store SecureString)
  or environment variables injected at runtime.
- Never log secrets, tokens, or PII.

## Validation and error handling
- Validate/sanitize all external input (params, body, headers, env) via allowlist.
- Errors do not leak stack traces, secrets, or internal details to the client.
- Log security events (auth, access denied, sensitive actions) without PII/secrets.

## Mandatory review (human gate)
Changes to the following topics require human review before merge:
- Authentication, authorization, session
- Cryptography and key/secret management
- IAM, access policies, and cloud configuration
- Adding/updating dependencies
- Infrastructure as code (Terraform, CloudFormation, Kubernetes, Dockerfile)

## When to run a security review
Trigger the `kiro-secops-review` skill (or the `kiro-secops-reviewer` agent) whenever you:
- Add/change an API endpoint or route
- Touch authentication/authorization/session
- Introduce new user input handling
- Create/change a query or database model
- Add file upload/handling
- Touch payment/financial/PII code
- Add/update dependencies
- Before any deploy/release

## SCA per ecosystem (vulnerable dependencies)
Run the stack's dependency scanner and fail on high/critical CVE:
- Node/TS: `npm audit --audit-level=high` (or `pnpm audit` / `yarn audit`)
- Python: `pip-audit` (or `safety check`)
- Go: `govulncheck ./...`
- Rust: `cargo audit`
- Java: `mvn org.owasp:dependency-check-maven:check` / `gradle dependencyCheckAnalyze`
- Cross-lang: `trivy fs --scanners vuln .`

## Security Definition of Done
Every feature must satisfy the **OWASP ASVS L1** checklist — trigger the `kiro-secops-review` skill (reference `references/owasp-asvs-l1.md`) as the *Definition of Done*.

## When working on specs (SDD)
- `requirements.md` MUST contain a `## Security Requirements` section in EARS notation
  (`WHEN … THE SYSTEM SHALL …`), including abuse/misuse cases.
- `design.md` MUST contain `## Security Considerations / Threat Model` (STRIDE, trust
  boundaries, authN/Z, secrets, crypto, supply chain). Use the STRIDE template from the `kiro-secops-review` skill (`references/threat-model-template.md`).
- `tasks.md` MUST contain explicit threat modeling, SAST, SCA, DAST, and security review tasks.
