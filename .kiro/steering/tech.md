# Tech Stack

## Language and Runtime

- **Go ≥ 1.25** — single-binary CLI, cross-platform (darwin/linux/windows, amd64/arm64).
- **CGO_ENABLED=0** for static Linux binaries.
- Minimal dependency surface: **stdlib only + `gopkg.in/yaml.v3`** (pinned, vendored). Do NOT add new third-party dependencies without an explicit ADR.

## Build System

- **GNU Make** (primary build driver).
- **GoReleaser** for release builds (`.goreleaser.yaml`).
- Payload embedding via `//go:embed all:payload` in `internal/assets/assets.go`.

## Common Commands

```bash
make build            # Compile ./kiro-secops for the current OS
make dist             # Cross-compile all 5 targets → dist/
make checksums        # Generate dist/SHA256SUMS
make vet              # go vet + gofmt check (must pass before commit)
make fmt              # Auto-format code with gofmt
make test             # go test ./...
make clean            # Remove binary and dist/
make release-check    # Validate .goreleaser.yaml
make release-snapshot # Local release build (no publish)
make install-local    # Build + run install on this machine
```

## Linting and Static Analysis

- **gofmt** — mandatory (CI fails on unformatted files).
- **go vet** — standard static checks.
- **golangci-lint** — standard linter set (config: `.golangci.yml`). Misspell disabled (codebase uses Portuguese).
- **govulncheck** — vulnerability scanning (pinned version in CI).
- **yamllint** + **actionlint** — YAML/GitHub Actions linting.

## Testing

- `go test ./...` — all tests live in `internal/app/*_test.go`.
- Tests use `t.TempDir()` and `t.Setenv("KIRO_HOME", ...)` — never touch real `~/.kiro`.
- CI runs tests with `-race` on Ubuntu; cross-OS matrix (macOS/Windows) without `-race`.
- Coverage target: ~78%.

## CI/CD

- `.github/workflows/ci.yml` — quality gate (test, cross-OS, go-analysis, govulncheck, yaml lint).
- `examples/build/build.yml` — inert build workflow template (cross-compile + checksums; enable in your fork).
- `examples/release/release.yml` — inert release template (cosign signing, SBOM, SLSA provenance).
- GitHub Actions pinned by commit SHA; Dependabot enabled for updates.

## Conventions

- Commit messages follow Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`.
- Vendored dependencies: run `go mod tidy && go mod vendor` and commit `vendor/` when changing deps.
- Structured file generation via `encoding/json` / `yaml.v3` — never string interpolation.
- All filesystem writes must use `safeRoot` primitives (confinement, atomic write, anti-symlink) and the manifest transaction system.
