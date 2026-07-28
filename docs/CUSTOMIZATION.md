# Customization guide — where to change what

After reconciliation, **`internal/assets/payload/` is the single source** of the content (hooks, prompts, agent,
skill, steering, permissions, configs). The guard's **validation logic** lives in the Go code
(`internal/app/guard.go`). Since `internal/assets/payload/` is **embedded** in the binary via `//go:embed`, any change
to it requires a **rebuild** to be distributed (in development, `go run ./cmd/kiro-secops install|init` already uses
the current payload).

## Quick map

| I want to change… | File(s) | Rebuild? | How it reaches the user |
|---|---|:--:|---|
| **Hooks** (which ones, triggers, matchers) | `internal/assets/payload/workspace/kiro/hooks/kiro-secops.json` | Yes | `kiro-secops init` → project's `.kiro/hooks/` |
| **Prompts** for review (Stop) and SDD | `internal/assets/payload/workspace/kiro/hooks/kiro-secops.json` → `action.prompt` | Yes | same |
| **Guard logic** (what it blocks / denies writes to) | `internal/app/guard.go` → `blockRE` / `denyWriteRE` | Yes | binary; the hooks call `kiro-secops guard` via its absolute path |
| **Validation scripts (bash, reference)** | `internal/assets/payload/workspace/scripts/*.sh` | — | reference/fallback — **not** used by the hooks (the official guard is the binary) |
| **Agent persona/instructions** | `internal/assets/payload/global/agents/kiro-secops-reviewer.md` (body) | Yes | `kiro-secops install` → `~/.kiro/agents/` |
| **Agent tools/permissions** | `internal/assets/payload/global/agents/kiro-secops-reviewer.md` (frontmatter) | Yes | same |
| **Review skill** (checklist, commands, report) | `internal/assets/payload/global/skills/kiro-secops-review/SKILL.md` + `references/owasp-*.md` | Yes | install → `~/.kiro/skills/` |
| **Steering** (policies/guidance) | `internal/assets/payload/global/steering/*.md` | Yes | install → `~/.kiro/steering/` |
| **Permissions** (enforcement) | `internal/assets/payload/global/settings/permissions.yaml` (+ `profiles/strict.yaml`) | Yes | install (structural merge of managed items) |
| **Global .kiroignore** | `internal/assets/payload/global/settings/kiroignore` | Yes | install (managed block `# >>> … >>>`) |
| **Scanner/CI configs** | `internal/assets/payload/workspace/{pre-commit-config.yaml,gitleaks.toml,trivy.yaml,checkov.yaml,github/workflows/security-scan.yml}` | Yes | `init` copies to the project |
| **`kiro-secops scan` scanners** | `internal/app/scan.go` (`cmdScan`/`detectLangs`) | Yes | binary |

---

## 1. Hooks and prompts (workspace)

Single source: **`internal/assets/payload/workspace/kiro/hooks/kiro-secops.json`**. Structure:

```json
{ "version": "v1",
  "hooks": [
    { "name": "kiro-secops-guard-shell", "trigger": "PreToolUse", "matcher": "execute_bash|shell",
      "action": { "type": "command", "command": "kiro-secops guard" }, "timeout": 10, "enabled": true },
    { "name": "kiro-secops-review-gate", "trigger": "Stop",
      "action": { "type": "agent", "prompt": "…review text…" }, "enabled": true }
  ] }
```

- **Change a prompt** (review on `Stop`, or the SDD ones on `PostFileCreate`): edit the
  `action.prompt` field of the corresponding hook.
- **Add/remove a hook**: edit the `hooks` list. Triggers: `PreToolUse`, `PostToolUse`,
  `SessionStart`, `Stop`, `PreTaskExec`, `PostTaskExec`, `PostFileCreate`, `PostFileSave`,
  `PostFileDelete`. Actions: `command` (receives JSON on stdin) or `agent` (injects `prompt`).
- **Important:** the guard hooks only **call** `kiro-secops guard`. The *logic* (which
  commands to block) lives in `internal/app/guard.go`, not in the JSON (see §2).
- Apply: `make build` (re-embed) → distribute the binary → `kiro-secops init` in the projects.

## 2. Guard logic (command/write validation)

File: **`internal/app/guard.go`**. Two regex lists (RE2, `(?i)` prefix):

- `blockRE` — commands that **block** (exit 2).
- `denyWriteRE` — file paths whose **write is blocked** (secrets).

The guard is **binary** (block/allow) and **fail-closed**: invalid JSON, a payload over the limit, or
an unknown `tool_input` schema also **block** (exit 2). Confirmation (`ask`) is **not**
done by the hook — high-impact actions that should ask for confirmation live in `permissions.yaml`
with `effect: ask` (see section 5).

To add a pattern: include the regex in the right list **and** add a case in
`internal/app/guard_test.go` (`TestGuardEval`). Keep the reference `internal/assets/payload/global/skills/kiro-secops-review/references/owasp-shell.md`
in sync. Rebuild the binary.

> The `internal/assets/payload/workspace/scripts/*.sh` are a **bash reference implementation**
> of the same concept. They are **not** deployed by `init`: in production, the guard (PreToolUse) and the
> advisory scan (PostTaskExec) are run by the `kiro-secops` **binary**, which is
> cross-platform. Use the scripts as a fallback/documentation.

## 3. Review agent

File: **`internal/assets/payload/global/agents/kiro-secops-reviewer.md`**.
- **Frontmatter**: `tools`, `permissions` (deny/ask/allow), `model`, `resources`.
- **Body**: persona, what to look for (OWASP→CWE), report format, and AWS
  Well-Architected alignment. Edit here to change the agent's behavior/text.

## 4. Review skill

`internal/assets/payload/global/skills/kiro-secops-review/SKILL.md` (workflow, checklist, SCA commands, report
format) + `references/owasp-{node,python,go,java,rust,shell}.md` (BAD/GOOD patterns per
language). For a new language, create `references/owasp-<lang>.md` and reference it in `SKILL.md`.

## 5. Steering and permissions

- **Steering**: `internal/assets/payload/global/steering/*.md` (`security-policies.md` is `inclusion: always`).
- **Permissions**: `internal/assets/payload/global/settings/permissions.yaml` (and `profiles/strict.yaml`).
  During installation, a **structural merge** is performed (`yaml.v3` parser): the rules are added as **marked
  items** in the `rules` sequence (comment `kiro-secops-managed profile=… schema=…`),
  preserving the user's rules. Reinstalling replaces only the managed items; switching
  profiles (`--profile`) swaps the marker without duplicating. The `# >>> … >>>` text block is used only
  in **kiroignore**, not in permissions.

## 6. Flow after any change to the payload

```bash
make build            # re-embed the payload into the binary
./kiro-secops install    # reinstalls global config (transactional + manifest)
./kiro-secops init       # re-applies the scaffold in the projects
# in development, without build: go run ./cmd/kiro-secops install   /   go run ./cmd/kiro-secops init --project <dir>
```
