# Development guide

How to build, test, and extend the `kiro-secops` solution.

## Requirements

- **Go ≥ 1.25** (the binary uses only the stdlib + one pinned dependency: `gopkg.in/yaml.v3`).
- `make` (optional, but recommended). Scan tools (semgrep, trivy, etc.) are optional and
  only needed to run `kiro-secops scan` locally.

## Build and cross-compile

```bash
make build        # ./kiro-secops for the current OS (builds ./cmd/kiro-secops)
make dist         # cross-compile: darwin amd64/arm64, linux amd64/arm64, windows amd64 -> dist/
make checksums    # dist/SHA256SUMS (basis for signing/SLSA)
make vet          # go vet + gofmt check
make test         # go test ./...
make clean        # removes binary and dist/
```

Without `make`:
```bash
go build -trimpath -ldflags '-s -w -X kiro-secops/internal/app.version=1.1.0' -o kiro-secops ./cmd/kiro-secops
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o kiro-secops.exe ./cmd/kiro-secops
```

The binary **embeds** `internal/assets/payload/` via `//go:embed all:payload` (in
`internal/assets/assets.go`). Any change in `internal/assets/payload/` is incorporated into the
next build — there is no copy step.

## Tests

```bash
go test ./...                 # runs everything
go test ./... -v -count=1     # verbose, no cache
go test ./... -cover          # coverage (~78%)
go test ./internal/app -run TestGuardEval -v # a specific test
```

What the suite covers (all in `internal/app/`):

| Test file | Covers |
|---|---|
| `guard_test.go` | `guardEval` (block/allow + secret writes, fail-closed) and `extractPayload` |
| `merge_test.go` | **structural** merge of `permissions.yaml` (idempotent, preserves user rules, rejects invalid YAML) and `kiroignore` |
| `manifest_test.go` | transaction (commit/rollback), exact restoration, tampering detection, and manifest validation |
| `kirohome_test.go` | `kiroHome` (abs/relative/default), `firstString`, `safeRoot` (atomic, anti-symlink parent/final) |
| `hooks_test.go` | guard binary resolution/validation and absolute path materialization |
| `fsutil_test.go` | `extractTree`, `walkEmbedFiles`, `copyEmbedFile` (against the real embed, within the transaction) |
| `install_test.go` | `install`/reinstall/`uninstall` + preexisting file restoration + `--dry-run` |
| `initcmd_test.go` | `init` (materialized hooks + configs); `uninstall --project` (restores); `--dry-run` |
| `cmd_test.go` | CLI dispatch, `scan` (blocking/advisory), `verify`/`verify --strict`, guard via stdin |

Notes:
- Tests use `t.TempDir()` and `t.Setenv("KIRO_HOME", ...)` — they **do not touch** the real `~/.kiro`.
- `TestInstall*` do `t.Skip` if running as **root** (the `install` refuses root).

## How to extend

> Complete map of **"where to change what"** (hooks, prompts, agent, steering, permissions):
> **[CUSTOMIZATION.md](../CUSTOMIZATION.md)**.

**Change workspace hooks/prompts** → `internal/assets/payload/workspace/kiro/hooks/kiro-secops.json`
(the `init` copies this file and **materializes** the binary's absolute path in the command actions,
via `internal/app/hooks.go`).

**Add a dangerous pattern to the guard** → edit `blockRE`/`denyWriteRE` in
`internal/app/guard.go` (RE2 regex, `(?i)` prefix for case-insensitive) and **add a case** in
`internal/app/guard_test.go`. Confirmation (`ask`) does not belong in the guard — go to `permissions.yaml`.
Keep the reference in sync:
`internal/assets/payload/global/skills/kiro-secops-review/references/owasp-shell.md`.

**Add/change a baseline artifact** → edit the files in `internal/assets/payload/global/`
(global deploy) or `internal/assets/payload/workspace/` (project scaffold). They are incorporated into the
next build.

**Add a language to the skill** → create
`internal/assets/payload/global/skills/kiro-secops-review/references/owasp-<lang>.md` and reference it in
`SKILL.md`. Update `detectLangs`/scanners in `internal/app/scan.go` if applicable.

**New subcommand** → add the `case` in `run()` (`internal/app/cli.go`) and implement `cmdXxx`.

## Style and conventions

- **gofmt** mandatory (`make vet` fails if there is an unformatted file).
- **Minimal dependencies**: only the stdlib + `gopkg.in/yaml.v3` (pinned). Do not add new
  third-party dependencies without an explicit, documented decision — the minimal
  supply chain surface is a requirement of the tool.
- Prefer the **`safeRoot`** primitives (`internal/app/safefs.go`) and the **transaction** in
  `manifest.go` for any write to `~/.kiro`/project (confinement, atomicity, rollback).
- Structured file generation (JSON) via `encoding/json`, never via string interpolation.

## CI

- `.github/workflows/ci.yml` — **quality gate**: `test` (tests with `-race` + coverage +
  guard self-test, Ubuntu), `test-cross-os` (**macOS/Windows** matrix, `go test` without `-race`),
  `go-analysis` (`gofmt` + `go vet` + **golangci-lint**, config in `.golangci.yml`), `vuln`
  (**govulncheck** pinned), and `yaml` (**yamllint** + **actionlint** + `goreleaser check`).
  Actions pinned by commit **SHA** (updates via Dependabot).
- `examples/build/build.yml` — **template** (inactive) for build + cross-compile (`make dist`) +
  `make checksums`, publishing the binaries as an artifact (enable it in your fork).
- `examples/release/release.yml` — **template** (inactive) for the signed release; this sample does not
  publish releases (enable it in your fork — see below).

## Release

This sample **does not publish releases**. The pipeline is an **inert template** in
[`examples/release/`](../../examples/release/) — GitHub only runs workflows in
`.github/workflows/`. To generate the installable **in your fork**, copy the template to
`.github/workflows/release.yml` and push a `vX.Y.Z` tag (guide in
[`examples/release/README.md`](../../examples/release/README.md)):

```bash
git tag v1.1.0 && git push origin v1.1.0
```

The workflow builds the 5 targets, generates `checksums.txt` + **SBOMs** (syft), **signs** the checksums
with **cosign** (keyless/OIDC), creates the **GitHub Release**, and emits **SLSA provenance**
(`actions/attest-build-provenance`).

> **SLSA provenance** is **mandatory when supported** (**public** or **organization**
> repository): the step fails the release if the attestation cannot be emitted. In a
> **private user** repository — where the attestation API does not exist — the step is
> **skipped** (via `if: github.event.repository.visibility != 'private'`), so as not to fail the
> release due to a platform limitation; make the repo public to obtain verifiable
> provenance. The **cosign** signing of the checksums works in any case.

Local test (from a git repo; does not publish):
```bash
make release-check      # validates the .goreleaser.yaml (requires an 'origin' remote)
make release-snapshot   # full build in dist/ (use `--skip=sign,sbom` if cosign/syft are missing)
```

## Roadmap

- [x] **GoReleaser** packaging + **checksums** + **cosign signing** (keyless) + **SBOM** + **SLSA provenance**
- [x] Distribution via **GitHub Releases** (workflow on `v*` tag)
- [ ] **MDM** (push the binary to the fleet + *drift correction*)
