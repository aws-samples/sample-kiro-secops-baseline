---
inclusion: fileMatch
fileMatchPattern:
  - "**/api/**/*.ts"
  - "**/api/**/*.js"
  - "**/routes/**/*.ts"
  - "**/routes/**/*.js"
  - "**/controllers/**/*.py"
  - "**/controllers/**/*.java"
  - "**/handlers/**/*.go"
---

# Security rules for endpoints/API

Applied automatically when editing routes, controllers, and handlers.
Taxonomy: **OWASP API Security Top 10 2023**
(https://owasp.org/API-Security/editions/2023/en/0x00-header/).

## Authentication and authorization
- AuthN before authZ; **deny by default** on every route (API2 Broken Authentication).
- Verify resource permission/ownership on every request — object-level authorization,
  avoid IDOR (API1 Broken Object Level Authorization).
- Administrative and function-level endpoints require an explicit role check
  (API5 Broken Function Level Authorization).

## Data exposure and mass assignment
- Bind only the properties the client is allowed to set — no blanket mass assignment
  (`Object.assign(entity, body)`, `Model(**body)`); use an explicit allowlist / DTO
  (API3 Broken Object Property Level Authorization).
- Return only the fields required by the consumer; never rely on the client to filter
  sensitive properties — object property-level authorization (API3).

## Input and output
- Validate the schema of every request (body, query, params, headers) via allowlist
  (supports API3; defensive baseline for API8).
- Always parameterized queries; never interpolate input into SQL/commands (injection is
  not a standalone API 2023 category — see web Top 10 2025 **A05 Injection**).
- Output encoding according to context; set `Content-Type` correctly (anti-XSS — web **A05**).

## Resilience and abuse
- Rate limiting / throttling on public and authentication endpoints; payload size
  limits; timeouts and pagination caps (API4 Unrestricted Resource Consumption).
- Protect sensitive business flows (checkout, signup, purchase, referral) against
  automated abuse — proof-of-work, CAPTCHA, or device/flow controls where warranted
  (API6 Unrestricted Access to Sensitive Business Flows).
- No SSRF: outbound URLs on an allowlist; block private/link-local ranges
  (API7 Server Side Request Forgery).

## Consuming third-party APIs
- Never blindly trust data from upstream/third-party APIs — validate and sanitize it
  as untrusted input, same rules as client input (API10 Unsafe Consumption of APIs).
- Enforce TLS, timeouts, and redirect limits on outbound integrations (API10).

## Errors and logs
- Generic error responses to the client (no stack trace/secret) — API8 Security
  Misconfiguration (and web Top 10 2025 **A10 Mishandling of Exceptional Conditions**).
- Log denied access attempts and auth failures (no PII/secrets), and ensure they are
  monitored/alerted on (no dedicated API 2023 category — web Top 10 2025 **A09 Logging & Alerting**).

## Configuration and inventory
- Security headers (web): `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
  `Content-Security-Policy`, appropriate `Cache-Control` for sensitive responses; disable
  verbose errors and unused methods (API8 Security Misconfiguration).
- Maintain an inventory of API versions/hosts; retire deprecated, debug, and non-prod
  endpoints; keep the spec (OpenAPI) current (API9 Improper Inventory Management).

## OWASP API Security Top 10 2023 — checklist
1. API1 Broken Object Level Authorization — ownership check per object
2. API2 Broken Authentication — strong authN, deny by default
3. API3 Broken Object Property Level Authorization — no mass assignment / over-exposure
4. API4 Unrestricted Resource Consumption — rate limits, size/timeout/pagination caps
5. API5 Broken Function Level Authorization — explicit role checks on privileged routes
6. API6 Unrestricted Access to Sensitive Business Flows — anti-automation on key flows
7. API7 Server Side Request Forgery — outbound allowlist, block private ranges
8. API8 Security Misconfiguration — headers, no verbose errors, minimal surface
9. API9 Improper Inventory Management — version/endpoint inventory, retire stale APIs
10. API10 Unsafe Consumption of APIs — treat upstream responses as untrusted; TLS/timeouts
