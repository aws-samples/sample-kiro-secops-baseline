# Project Structure

```
.
├── cmd/kiro-secops/main.go          # Entry point (thin): os.Exit(app.Run(os.Args[1:]))
├── internal/
│   ├── app/                         # All CLI logic (package "app")
│   │   ├── cli.go                   # Subcommand dispatch, flags, Run(), opts, version
│   │   ├── guard.go                 # Guard evaluation (block/allow, fail-closed, regex deny-lists)
│   │   ├── install.go               # install / uninstall commands
│   │   ├── initcmd.go              # init command (workspace scaffold)
│   │   ├── merge.go                 # Structural YAML merge (permissions.yaml) + kiroignore merge
│   │   ├── manifest.go             # Ownership manifest (SHA-256), transactional write/commit/rollback
│   │   ├── safefs.go               # safeRoot: confinement, anti-symlink, atomic writes
│   │   ├── hooks.go                # Guard binary resolution + absolute path materialization in hooks
│   │   ├── fsutil.go               # extractTree, copyEmbedFile, walkEmbedFiles from embed FS
│   │   ├── scan.go                 # Scanner orchestration (language detection, timeout, block/advisory)
│   │   ├── kirohome.go            # KIRO_HOME resolution, mustNotRoot
│   │   ├── assets.go              # Bridge: payloadFS = assets.FS
│   │   └── *_test.go              # Tests for each module (guard, merge, manifest, install, init, etc.)
│   └── assets/
│       ├── assets.go               # //go:embed all:payload → assets.FS
│       └── payload/                # INERT baseline content embedded into the binary
│           ├── global/             # Deployed to ~/.kiro/ (steering, skills, agents, settings)
│           └── workspace/          # Deployed to <project>/.kiro/ (hooks, scanner configs, CI)
├── docs/
│   ├── INSTALADOR.md               # Installer user guide
│   ├── PERSONALIZACAO.md           # Customization guide (hooks, guard, prompts, steering)
│   ├── PIPELINES.md                # CI/CD integration guide
│   ├── FERRAMENTAS.md              # External tools/scanners installation
│   ├── security/                   # Security baseline docs, controls catalog
│   └── dev/                        # Internal: architecture, dev guide, ADRs
├── examples/
│   ├── build/                      # Inert build workflow template (cross-compile + checksums)
│   ├── kiro-headless-ci/           # Forkable: Docker images for headless Kiro CI (PR review + DAST)
│   └── release/                    # Inert release workflow template
├── vendor/                          # Vendored dependencies (committed, hermetic builds)
├── Makefile                         # Build targets
├── go.mod / go.sum                  # Go module (kiro-secops)
├── .goreleaser.yaml                 # Release configuration
├── .golangci.yml                    # Linter config
├── .github/workflows/              # CI (ci.yml)
└── .yamllint.yml                    # YAML lint config
```

## Key Patterns

- **Entry point is thin**: `cmd/kiro-secops/main.go` only calls `app.Run()`. All logic lives in `internal/app/`.
- **Single package**: all CLI logic is in package `app` (`internal/app/`). No sub-packages.
- **Payload is embedded**: files under `internal/assets/payload/` are compiled into the binary. Editing them takes effect on next `make build`.
- **Tests are co-located**: each source file `foo.go` has a corresponding `foo_test.go` in the same package.
- **Docs split by audience**: `docs/` for users, `docs/dev/` for contributors, `docs/security/` for security reference.
- **Examples are forkable**: `examples/` contains standalone, self-contained examples users can copy.
