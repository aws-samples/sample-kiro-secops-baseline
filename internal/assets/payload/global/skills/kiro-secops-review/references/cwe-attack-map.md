# Reference — CWE → MITRE ATT&CK mapping (curated)

Optional enrichment for findings. Maps code weaknesses (CWE) to the adversary
tactic/technique they could enable **if exploited**. This is *potential impact
context for threat modeling and detection*, NOT a claim that the technique was
observed.

- **ATT&CK baseline:** v18 (October 2025) — Enterprise matrix.
- **Review cadence:** MITRE ships ~2 releases/year (April & October).
  Re-check this table each April and October and bump the baseline above.
- **Scope:** high-level, long-stable techniques only. Deep sub-techniques and
  Groups/Software/Campaigns churn between releases and are intentionally excluded.
- **Usage rule for the agent:** cite an ATT&CK ID **only** if the finding's CWE
  appears in the table below. Otherwise output `ATT&CK: n/a`. Never invent IDs.
- **Correlation path:** the principled chain is CWE → CAPEC → ATT&CK; entries
  below already resolve that chain to the technique level.

## Mapping table

| CWE | Weakness | OWASP 2025 | ATT&CK tactic | Technique |
| --- | --- | --- | --- | --- |
| CWE-798 / CWE-522 | Hardcoded / unsecured credentials | A04 / A02 | TA0006 Credential Access | T1552.001 Unsecured Credentials: Credentials In Files |
| CWE-78 | OS command injection | A05 | TA0002 Execution | T1059 Command and Scripting Interpreter |
| CWE-94 / CWE-1336 | Code injection / SSTI | A05 | TA0002 Execution | T1059 Command and Scripting Interpreter |
| CWE-502 | Insecure deserialization | A08 | TA0002 Execution | T1059 Command and Scripting Interpreter |
| CWE-89 | SQL injection | A05 | TA0001 Initial Access | T1190 Exploit Public-Facing Application |
| CWE-943 | NoSQL injection | A05 | TA0001 Initial Access | T1190 Exploit Public-Facing Application |
| CWE-918 | SSRF | A01 | TA0007 Discovery | T1046 Network Service Discovery |
| CWE-22 | Path traversal | A01 | TA0009 Collection | T1005 Data from Local System |
| CWE-284 / CWE-639 | Broken access control / IDOR | A01 | TA0001 Initial Access | T1190 Exploit Public-Facing Application |
| CWE-347 | Improper signature verification (JWT `alg:none`) | A07 | TA0006 Credential Access | T1550.001 Use Alternate Authentication Material: Application Access Token |
| CWE-1104 | Use of unmaintained / vulnerable dependency | A03 | TA0001 Initial Access | T1195.001 Supply Chain Compromise: Software Dependencies and Development Tools |
| CWE-79 | Cross-site scripting (XSS) | A05 | TA0001 Initial Access | T1189 Drive-by Compromise |
| CWE-327 / CWE-338 | Weak crypto / non-crypto PRNG | A04 | TA0006 Credential Access | T1110 Brute Force |
| CWE-532 | Sensitive data (PII/secrets) in logs | A09 | TA0006 Credential Access | T1552 Unsecured Credentials |

> If a finding does not match any row above, report `ATT&CK: n/a` rather than
> guessing. Add new rows only after verifying the ID against the pinned baseline.
