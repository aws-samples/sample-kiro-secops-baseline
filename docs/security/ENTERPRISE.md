# Enterprise adoption — from personal baseline to fleet policy

Audience: platform/security teams rolling the kiro-secops baseline out to an **organization**.

What `install`/`init` deploy is a **personal floor**: it protects the machine of the developer
who ran it — and that developer can edit or remove it, because `~/.kiro` belongs to the user.
This guide maps each baseline control to the **organizational** mechanism that makes it
non-removable and centrally governed, using only officially documented Kiro capabilities.

> The lever that makes fleet policy possible is permission resolution by restrictiveness:
> **`deny > ask > allow`, across all scopes**. A rule placed in the *Administration* scope can
> never be relaxed by a user or workspace `allow`.

Contents:

1. [The four organizational levers](#1-the-four-organizational-levers)
2. [Control-by-control mapping](#2-control-by-control-mapping)
3. [The Administration profile (`profiles/admin.yaml`)](#3-the-administration-profile)
4. [Rollout order (day 0 for an organization)](#4-rollout-order)
5. [Drift correction](#5-drift-correction)
6. [Known limits](#6-known-limits)
7. [Sources](#7-sources)

---

## 1. The four organizational levers

| Lever | What it governs | Where it is managed |
|---|---|---|
| **Administration permission scope** | `deny`/`ask` rules the developer cannot override or remove (only these two effects are accepted) | Enterprise plans; enterprise tooling/MDM |
| **Kiro console governance** (Shared settings) | Model allow-list + org default model; MCP disabled or restricted to an **MCP registry** allow-list; org-wide **web tools** on/off (`web_search`/`web_fetch`); API keys (disabled by default); prompt logging and usage reporting | Kiro console (admin) |
| **Identity & data** | Sign-in via IAM Identity Center / Okta / Microsoft Entra ID; per-user/group subscriptions; session duration (incl. the extended-session option for Kiro in IAM Identity Center); enterprise telemetry/content-collection **auto opt-out**; data residency per profile Region; customer-managed KMS keys | Kiro console + IAM Identity Center |
| **MDM distribution** | IDE update policy (`UpdateUrl`/`UpdateMode`: pinning, phased rollout, disabling) via macOS managed preferences (`dev.kiro.desktop`), Windows registry (`HKLM\SOFTWARE\Policies\Kiro`), Linux (`/etc/kiro/policy.json`); pushing team steering to `~/.kiro/steering`; distributing the `kiro-secops` binary + baseline; scheduled drift checks | Your MDM / Group Policy |

The first two levers are enforcement the developer cannot undo; the last two are distribution
and identity. The personal baseline (`kiro-secops install`) remains useful **on top** of them —
it adds the guard hook, the reviewer agent, and developer ergonomics (scoped `allow` rules).

## 2. Control-by-control mapping

Each row: what the baseline enforces today per developer → the mechanism that enforces it
fleet-wide.

| Baseline control | Personal mechanism (this sample) | Fleet mechanism |
|---|---|---|
| Agent never reads/writes secrets (canonical set) | `permissions.yaml` deny (`install`) | **Administration scope** — deploy [`profiles/admin.yaml`](../../internal/assets/payload/global/settings/profiles/admin.yaml) |
| Destructive/exfiltration shell blocked | `permissions.yaml` deny + guard hook | **Administration scope** (deny); guard hooks stay per-repo (`init`) |
| Agent cannot rewrite its own guardrails | `permissions.yaml` deny (+ Kiro's built-in scope) | **Administration scope** (deny) |
| High-impact commands/writes ask for confirmation | `permissions.yaml` ask | **Administration scope** (ask) |
| No silent web exfiltration | `web_fetch: ask` (baseline) / `deny` (strict) | Console: **disable web tools org-wide** (stronger — the tools disappear for users) |
| MCP under control | `mcp: ask` | Console: **MCP registry** allow-list, or disable MCP entirely |
| Only approved models | reviewer agent pins `model:` | Console: **model allow-list + org default**. Keep the pin in [`kiro-secops-reviewer.md`](../../internal/assets/payload/global/agents/kiro-secops-reviewer.md) inside the allow-list, or drop the pin to use the org default |
| Security steering on every machine | `install` → `~/.kiro/steering` | **MDM** pushes steering to the fleet's `~/.kiro/steering` |
| Guard + review gates per repository | `init` (committed) | Committed workspace layer; each dev runs `install` + `init` after cloning; `verify --project .` detects broken hooks |
| Baseline integrity on each machine | `verify --strict` (manual) | **MDM-scheduled** `verify --strict`; on exit `1`, MDM re-runs `install` (drift correction) |
| Who can use Kiro, and for how long | — | **IAM Identity Center / Okta / Entra ID** subscriptions; session-duration policy in IAM Identity Center |
| Telemetry / content collection | individual opt-out | **Enterprise plans: automatic opt-out**; usage reporting is admin-controlled |
| Data residency / encryption keys | — | Console: profile **Region** (+ customer-managed **KMS** keys) |
| Deterministic CI gate | `scan` blocking + `security-scan.yml` | Same, org-wide via repo templates/required workflows |

## 3. The Administration profile

[`internal/assets/payload/global/settings/profiles/admin.yaml`](../../internal/assets/payload/global/settings/profiles/admin.yaml)
is the distributable subset of the baseline for the Administration scope:

- **Only `deny` and `ask`.** The Administration scope accepts no `allow`, so the baseline's
  allow rules (scanner/git shell allow-list, broad `fs_read`, `web_search`) are intentionally
  absent. Developer ergonomics stay in the **personal** baseline; anything unmatched falls to
  the default (`ask`).
- **Test-enforced invariants** (this repo's CI):
  `TestAdminProfileOnlyDenyAsk` — the file can never carry an `allow`;
  `TestAdminProfileCoversBaselineRestrictions` — every baseline `deny`/`ask` is present with at
  least the same restrictiveness. The org floor can never silently drift below the personal one.
- **Hardening further:** for the strict posture org-wide, add the deltas from
  [`profiles/strict.yaml`](../../internal/assets/payload/global/settings/profiles/strict.yaml)
  (publishing denied, `web_fetch` denied, no broad package managers) — the superset invariant
  still holds, since strict ⊇ baseline.
- **Org-specific rules** (internal registries, proprietary paths) can be appended; keep them in
  your fork so the tests keep guarding the floor.

**Deployment.** The Administration scope is documented (enterprise plans) as MDM/enterprise-
managed, but the public docs do not specify the file's deployment path — coordinate the rollout
with your Kiro enterprise onboarding/support. Pragmatic interim: distribute the same rules into
each user's `~/.kiro/settings/permissions.yaml` via MDM and rely on drift correction (section 5).
That interim is weaker — the file is user-editable between corrections — which is exactly why
the detector exists.

## 4. Rollout order

Day 0 for an organization (compare with the per-developer order in
[`SECURITY-BASELINE.md`](SECURITY-BASELINE.md#10-deployment-order)):

1. **Console:** connect IAM Identity Center / Okta / Entra ID and subscribe users/groups; set
   the model allow-list + org default; enable the MCP registry (or disable MCP); decide the
   org-wide web-tools switch; keep API keys disabled unless a pipeline needs them; set profile
   Region (+ KMS) and logging/reporting.
2. **Administration scope:** deploy the `admin.yaml` rules (section 3).
3. **MDM:** distribute the `kiro-secops` binary and run `install` per user (never as root);
   push team steering to `~/.kiro/steering`; set the IDE update policy; schedule the drift
   check (section 5).
4. **Per repository:** `kiro-secops init` → commit the workspace layer; make the CI gate
   blocking (`kiro-secops scan` / `security-scan.yml`); teammates run `install` + `init` after
   cloning (`verify --project .` confirms).
5. **Personal baseline** (`install --profile baseline|strict`) stays as reinforcement and
   developer ergonomics — it is no longer the only line of defense.

## 5. Drift correction

The detector ships in the binary; the corrector is your MDM.

```bash
kiro-secops verify --strict              # global layer: guard self-test + manifest (hash + presence)
kiro-secops verify --strict --project .  # + workspace: hooks must resolve on THIS machine
```

- Exit `1` means divergence: MDM re-runs `kiro-secops install` (global) and the developer
  re-runs `kiro-secops init` (workspace).
- Schedule `verify --strict` on workstations via your MDM's script scheduler (or launchd /
  Task Scheduler / systemd user timers) and alert on non-zero exits.
- **Do not run `verify --project` in CI**: committed hooks pin per-machine absolute paths by
  design, so a CI runner would always report them as broken. The deterministic CI gate is
  `kiro-secops scan` (plus the pipeline scanners); hook health is a **workstation** check.

## 6. Known limits

- The Administration scope's file deployment path is not publicly documented (the scope itself
  is documented on the IDE permissions page; CLI docs describe user/workspace scopes). Validate
  behavior in your environment and engage your enterprise onboarding.
- `~/.kiro` remains user-writable: MDM drift correction is a **compensating** control, not
  tamper-proofing. The tamper-resistant home for deny/ask is the Administration scope.
- Workspace hooks are opt-in per repository (`init` + commit). A repo without the workspace
  layer still has the global floor, but no guard hook or review gates.
- The guard denylist is not a sandbox (see
  [`ARCHITECTURE.md`](../dev/ARCHITECTURE.md#known-limitations)). For high-assurance
  environments, add OS-level isolation (dedicated dev accounts/containers), in line with the
  official guidance on clean environments and workspace isolation.

## 7. Sources

Official documentation (content paraphrased/summarized for compliance):

- Permissions and scopes (incl. Administration): <https://kiro.dev/docs/chat/permissions/> ·
  <https://kiro.dev/docs/cli/v3/permissions/>
- Enterprise governance and settings: <https://kiro.dev/docs/enterprise/governance> ·
  <https://kiro.dev/docs/enterprise/settings> · <https://kiro.dev/docs/enterprise/subscribe>
- Managed updates via MDM/policy: <https://kiro.dev/docs/enterprise/managed-updates>
- Privacy, security, and data protection: <https://kiro.dev/docs/privacy-and-security> ·
  <https://kiro.dev/docs/privacy-and-security/data-protection>
- MCP registry and MCP security: <https://kiro.dev/docs/cli/mcp/registry> ·
  <https://kiro.dev/docs/cli/mcp/security>
- CLI security considerations: <https://kiro.dev/docs/cli/chat/security>
- Steering distribution to fleets: <https://kiro.dev/docs/steering>
- Extended sessions for Kiro in IAM Identity Center:
  <https://docs.aws.amazon.com/singlesignon/latest/userguide/90-day-extended-session-duration.html>
