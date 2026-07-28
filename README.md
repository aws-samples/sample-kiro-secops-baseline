# Kiro SecOps Baseline

A DevSecOps security baseline for [Kiro](https://kiro.dev), packaged as a single, dependency-light
Go CLI (`kiro-secops`) that deploys security guardrails to a developer's machine and scaffolds
security automation into a project.

This sample demonstrates how to package and distribute a complete information-security and
DevSecOps baseline for Kiro. It showcases a **declarative-first** approach to guardrails for
AI-assisted development: hard, cross-platform blocking rules in a `permissions.yaml`, softer
guidance through steering and skills, a security-review agent, and event hooks such as a
fail-closed guard and PR/pipeline review gates. The baseline ships **inert** inside the binary,
organized into a **global** layer (deployed to `~/.kiro/`, following the user across every
workspace) and a per-project **workspace** layer (scaffolded into a project's `.kiro/` and
committed with the code).

## Table of Contents

- [Overview](#overview)
- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Getting started](#getting-started)
- [Usage](#usage)
- [Repository structure](#repository-structure)
- [Documentation](#documentation)
- [Cost](#cost)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Overview

`kiro-secops` installs a security baseline in two independent, composable layers:

- **Global layer** (`internal/assets/payload/global/` → `~/.kiro/`): permissions, steering, skills,
  and a security-review agent. It follows the user across all of their workspaces.
- **Workspace layer** (`internal/assets/payload/workspace/` → a project's `.kiro/`): event hooks
  (review on `Stop`, advisory scan on `PostTaskExec`, SDD gates), reference scripts, and scanner/CI
  configs (pre-commit, gitleaks, trivy, checkov, GitHub Actions). It is committed with the project.

The binary is compiled with `make build` (or `go build ./cmd/kiro-secops`) and **embeds** the
entire `internal/assets/payload/` via `//go:embed`.

## How it works

The baseline separates **guidance** from **enforcement**:

| Layer | Where (target) | Nature | Blocks? |
|---|---|---|:--:|
| [**Permissions**](https://kiro.dev/docs/cli/v3/permissions/) | `~/.kiro/settings/permissions.yaml` | Hard enforcement (global, agent-agnostic) | **Yes** |
| [**Steering**](https://kiro.dev/docs/cli/steering/) | `~/.kiro/steering/*.md` | Guidance (soft) | No |
| [**Skills**](https://kiro.dev/docs/cli/skills/) | `~/.kiro/skills/*/SKILL.md` | On-demand guidance | No |
| [**Agents**](https://kiro.dev/docs/cli/custom-agents/) | `~/.kiro/agents/*.md` | Tool scoping | Partial |
| [**Hooks**](https://kiro.dev/docs/cli/hooks/) | `.kiro/hooks/*.json` (workspace) | Event-driven automation | Yes |

The design is **declarative-first**: hard blocking goes into `permissions.yaml` (global, no runtime,
cross-platform); steering and skills provide soft guidance; event hooks (review/SDD) remain an
opt-in per-workspace scaffold.

**Enforcement scope:** the global `permissions.yaml` is the user's **personal floor** — it lives in
`~/.kiro`, which they can edit. For **fleet** policy (not removable by the developer), replicate the
rules in the *Administration* (enterprise) scope and/or distribute them via **MDM** with drift
correction. A ready-made deny/ask template for that scope ships in the payload
([`profiles/admin.yaml`](internal/assets/payload/global/settings/profiles/admin.yaml)); the rollout
guide is [`docs/security/ENTERPRISE.md`](docs/security/ENTERPRISE.md).

See [`docs/dev/ARCHITECTURE.md`](docs/dev/ARCHITECTURE.md) for the full design.

## Prerequisites

- **Go ≥ 1.25** to build the binary (the only build dependency; the binary needs nothing at runtime).
- **Optional — scanners** used by `kiro-secops scan` (semgrep, trivy, gitleaks, bandit, etc.):
  install them per environment as described in [`docs/TOOLS.md`](docs/TOOLS.md). `scan` degrades
  safely and skips whatever is not on the `PATH`.
- **Optional — AI review** (headless Kiro CLI): requires a paid Kiro plan and consumes credits (see
  [Cost](#cost)).

## Getting started

This sample does not publish releases. Clone the repository and build the binary locally:

```bash
git clone https://github.com/aws-samples/sample-kiro-secops-baseline
cd sample-kiro-secops-baseline
make build            # compiles ./kiro-secops for the current OS (from ./cmd/kiro-secops)
make dist             # cross-compiles darwin/linux/windows (amd64/arm64) → dist/
make checksums        # generates dist/SHA256SUMS
make vet              # go vet + gofmt check
make test             # go test ./...
```

To build the binaries in CI on every push/PR (artifact with the 5 targets + `SHA256SUMS`), enable
the template in [`examples/build/`](examples/build/). To produce a signed, downloadable release
from your own fork, enable the template in [`examples/release/`](examples/release/). The per-OS
download-and-verify guide is in [`docs/INSTALLER.md`](docs/INSTALLER.md#get-the-binary).

## Usage

`kiro-secops` exposes the subcommands below (the two main ones are independent and composable):

| Command | Target | When | Effect |
|---|---|---|---|
| `kiro-secops install` | `~/.kiro/` (honors `KIRO_HOME`) | once per machine/user | global floor: permissions, steering, skills, agent |
| `kiro-secops init [--project <dir>]` | project `.kiro/` | per project | workspace layer: hooks, SDD gates, CI (commit it) |
| `kiro-secops scan [dir]` | project dir | on demand / CI | runs scanners; findings block by default |
| `kiro-secops verify [--strict] [--project <dir>]` | installed baseline | on demand | guard self-test + integrity check (global manifest; with `--project`, also workspace hooks/manifest) |
| `kiro-secops guard` | stdin (hook) | per tool call | evaluates a tool call against the deny-list (fail-closed) |
| `kiro-secops uninstall [--project <dir>]` | global or project | on demand | restores the previous state from the manifest |

```bash
./kiro-secops install                 # global config → ~/.kiro (honors KIRO_HOME)
cd my-project && kiro-secops init      # workspace scaffold → .kiro/ (commit it for the team)
kiro-secops scan .                     # runs scanners; findings block (use --advisory to not fail)
kiro-secops verify --strict            # guard self-test + install integrity (via the manifest)
kiro-secops verify --project .         # + workspace check: hooks must resolve on THIS machine
kiro-secops uninstall                  # restores the previous global state
```

> **Team workflow:** the hooks that `init` writes pin the **absolute path** of the binary on the
> machine that ran it. After cloning, each teammate runs `kiro-secops install` + `kiro-secops init`
> (and `kiro-secops verify --project .` to confirm) — otherwise the committed hooks fail silently
> and the guard layer stays off for them.

> `~/.kiro/settings/` can only be written by an external process (you / the installer) — the Kiro
> agent itself is prevented from changing that folder, which is why installation is done by the
> binary. `install`/`init` are **transactional**: they write an ownership manifest (hashing each
> artifact) and roll back on failure; `uninstall` restores exactly the previous state.

For a detailed, per-command guide — how to run each command, its options and exit codes, plus **troubleshooting** — see [`docs/USAGE.md`](docs/USAGE.md).

Using the baseline in CI/CD (headless Kiro CLI + scanners) is covered in
[`docs/PIPELINES.md`](docs/PIPELINES.md), with a forkable example in
[`examples/kiro-headless-ci/`](examples/kiro-headless-ci/).

## Repository structure

```
.
├── cmd/kiro-secops/main.go          # entry point (thin) → app.Run
├── internal/
│   ├── app/                         # CLI logic (package app): guard, install, init, merge, scan, verify
│   └── assets/                      # //go:embed of the payload
│       └── payload/                 # INERT baseline — what the installer deploys
│           ├── global/              #   → ~/.kiro (steering, skills, agents, settings)
│           └── workspace/           #   → project .kiro/ (hooks + scanner/CI configs)
├── docs/                            # user guides + dev/ + security/
├── examples/
│   ├── build/                       # build workflow template (inactive) — enable it in your fork
│   ├── kiro-headless-ci/            # forkable: headless Kiro CI in Docker (review/pipeline + DAST)
│   └── release/                     # release pipeline template (inactive) — enable it in your fork
├── vendor/                          # vendored dependencies (hermetic build)
├── Makefile  .goreleaser.yaml       # build/cross-compile · release
└── .github/workflows/               # ci.yml (quality gate)
```

## Documentation

**Usage**
- [`docs/USAGE.md`](docs/USAGE.md) — how to run each command (options, exit codes) and troubleshooting per command.
- [`docs/INSTALLER.md`](docs/INSTALLER.md) — the `kiro-secops` binary: commands, flags, guard, merge, and distribution.
- [`docs/CUSTOMIZATION.md`](docs/CUSTOMIZATION.md) — where to change hooks, guard, prompts, agent, steering, and permissions.
- [`docs/PIPELINES.md`](docs/PIPELINES.md) — using the security skills/agent in CI/CD (headless Kiro CLI) and pipeline reviews.
- [`docs/TOOLS.md`](docs/TOOLS.md) — external scanners: per-environment installation with pinned versions.

**Security**
- [`docs/security/SECURITY-BASELINE.md`](docs/security/SECURITY-BASELINE.md) — master guide to Kiro's security mechanisms.
- [`docs/security/ENTERPRISE.md`](docs/security/ENTERPRISE.md) — fleet-wide adoption: Administration scope, governance console, identity, MDM, drift correction.
- [`docs/security/controls-catalog.md`](docs/security/controls-catalog.md) — AWS + community controls mapped to a Kiro mechanism.

**Development**
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute.
- [`docs/dev/ARCHITECTURE.md`](docs/dev/ARCHITECTURE.md) — solution architecture (layers, payload, code map, flows).
- [`docs/dev/DEVELOPMENT.md`](docs/dev/DEVELOPMENT.md) — build, cross-compile, test, and how to extend.

## Cost

This repository is sample code. The `kiro-secops` binary and the baseline have no license cost, but:

- The **AI review** (headless Kiro CLI — see [`examples/kiro-headless-ci/`](examples/kiro-headless-ci/))
  requires a **paid Kiro plan** and consumes credits per run.
- Running images/scanners in **CI** consumes runner minutes.
- **OWASP ZAP** and the scanners are open source (no license cost).

Estimate the cost before enabling the AI layer on every PR (e.g., run it only on labeled PRs or when
the diff touches sensitive areas).

## Security

To report a security vulnerability, **do not open a public GitHub issue** — follow the process in
[CONTRIBUTING](CONTRIBUTING.md). The security mechanisms and baseline are described in
[`docs/security/SECURITY-BASELINE.md`](docs/security/SECURITY-BASELINE.md). When exposing any network
endpoint or CI integration, review authentication and access controls before use.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.

Third-party components keep their own licenses: `gopkg.in/yaml.v3` (MIT, vendored under `vendor/`),
**OWASP ZAP** (Apache-2.0), and **Kiro CLI** (Amazon terms) — the latter two used only by the
example images.
