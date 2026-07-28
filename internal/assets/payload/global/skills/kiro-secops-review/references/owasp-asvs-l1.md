# OWASP ASVS L1 — Definition of Done checklist (security)

Practical checklist based on the **OWASP Application Security Verification Standard (ASVS) L1**
(opportunistic, mostly automatable to verify). Use it as a security *Definition of
Done* for features. Delivered as a reference for the `kiro-secops-review` skill and
cited by the `security-policies.md` steering.

Source: https://owasp.org/www-project-application-security-verification-standard/

> Every item must be **testable**. Mark `[x]` when there is evidence (test, scan, or review).

## V1 — Architecture & design
- [ ] A threat model exists for components that cross *trust boundaries*
- [ ] Security handled at every layer (defense-in-depth)

## V2 — Authentication
- [ ] No hardcoded credentials/secrets
- [ ] Passwords with strong hashing (bcrypt/argon2/scrypt); never cleartext
- [ ] Brute-force protection (rate limiting / lockout)
- [ ] Password reset flows do not reveal account existence

## V3 — Session
- [ ] Session tokens/cookies with `HttpOnly`, `Secure`, `SameSite`
- [ ] Session invalidated on logout and expires on inactivity

## V4 — Access control
- [ ] Deny by default; authorization verified on the server for every route
- [ ] No IDOR: object access validates ownership/permission
- [ ] Privilege separation (least privilege)

## V5 — Validation, sanitization & encoding
- [ ] All external input validated by allowlist
- [ ] Parameterized queries (no concatenation → SQL/NoSQL injection)
- [ ] Output encoding per context (HTML/JS/URL) → anti-XSS
- [ ] OS commands not assembled with untrusted input

## V6 — Cryptography
- [ ] Strong, current algorithms (no MD5/SHA1/DES/ECB)
- [ ] Keys/secrets in a vault (Secrets Manager/SSM), not in the code
- [ ] Cryptographic randomness for sensitive tokens/IDs

## V7 — Error handling & logging
- [ ] Errors do not leak stack traces, secrets, or internal details
- [ ] Security events logged (auth, access denied, sensitive actions)
- [ ] Logs do not contain PII/secrets

## V8 — Data protection
- [ ] Sensitive data classified; collection minimized
- [ ] Encryption at rest for sensitive data
- [ ] Cache/headers do not expose sensitive data

## V9 — Communication
- [ ] TLS on all communications (internal and external)
- [ ] Valid certificates; no downgrade to HTTP

## V10 — Malicious code / integrity
- [ ] Dependencies from trusted sources and pinned (lockfile)
- [ ] No dependencies with known critical CVEs (SCA)

## V11 — Business logic
- [ ] Sensitive flows validate sequence/limits (anti-abuse)
- [ ] Abuse/misuse cases considered

## V12 — Files & resources
- [ ] Upload validates type/size; no path traversal
- [ ] No SSRF: outbound requests to controlled/allowlisted URLs

## V13 — API
- [ ] AuthN/AuthZ on all endpoints; no "forgotten" endpoints
- [ ] Rate limiting; schema validation (JSON/params)

## V14 — Configuration
- [ ] No secrets in versioned environment variables/logs
- [ ] Security headers (CSP, HSTS, X-Content-Type-Options) when web
- [ ] Dependencies and base images up to date; minimal surface
