# Threat Model Template (STRIDE)

Copy this section into the `## Security Considerations / Threat Model` of each spec's `design.md`
(`.kiro/specs/<feature>/design.md`). The `inject-threat-model` hook
(`.kiro/hooks/security-spec-gates.json`) requests the creation of this section automatically; use
this template as a base.

Sources: STRIDE (Microsoft SDL); OWASP Threat Dragon (https://owasp.org/www-project-threat-dragon/).

---

## 1. Scope and assets
- **Feature/service:** <name>
- **Protected assets:** <data/credentials/critical functions>
- **Data classification:** <public / internal / confidential / PII / regulated>

## 2. Trust boundaries and data flow
Describe the trust boundaries (e.g., internet → API gateway → service → database) and the data
flow. A diagram (DFD) is recommended.

```
[Client] --HTTPS--> [API Gateway] --(authz)--> [Service] --(TLS)--> [Database]
                                          |
                                          +--> [Secrets Manager]
```

## 3. STRIDE analysis (per component / flow)

| Threat | Guiding question | Applies? | Mitigation | Requirement/Test |
|---|---|:--:|---|---|
| **S**poofing | Can someone impersonate another identity? | | Strong AuthN, MFA, mTLS | |
| **T**ampering | Can data/code be altered? | | Integrity, signing, validation | |
| **R**epudiation | Can an action be denied? | | Immutable logging/audit | |
| **I**nfo Disclosure | Can data leak? | | Crypto, least privilege, masking | |
| **D**enial of Service | Can it be made unavailable? | | Rate limiting, quotas, timeouts | |
| **E**levation of Privilege | Can privileges be gained? | | Deny-by-default authz, sandbox | |

## 4. Security controls adopted
- **Authentication/Authorization:** <description>
- **Input validation/encoding:** <description>
- **Secrets & keys:** <vault used, rotation>
- **Cryptography (in transit/at rest):** <algorithms>
- **Logging/audit/monitoring:** <what is logged, where>
- **Dependencies / supply chain:** <SCA, lockfile, SBOM, signing>

## 5. Residual risks and decisions
- <accepted risk + justification + owner + reassessment date>

## 6. Traceability
- Map each mitigation to an EARS requirement in `requirements.md` and to a test in `tasks.md`.
