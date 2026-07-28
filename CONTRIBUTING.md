# Contributing to kiro-secops

Thank you for contributing! Community contributions are welcome — from bug reports and
improvement suggestions to documentation fixes and new features. Please read this guide before
opening an issue or a pull request.

## Repository structure

- `cmd/kiro-secops/` — entry point (thin main).
- `internal/app/` — CLI logic (guard, install, init, merge, scan, verify, PATH hint).
- `internal/assets/` — payload embedded via `//go:embed` (`internal/assets/payload/`).
- `examples/` — forkable examples (e.g., headless CI in Docker).
- `docs/` — **user** documentation; `docs/dev/` — **internal** documentation (architecture, dev guide).
- `vendor/` — **vendored** dependencies (hermetic/reproducible build).

## Development

Requires **Go ≥ 1.25** (minimal surface: stdlib + one pinned dependency, `gopkg.in/yaml.v3`).

```bash
make build   # builds ./kiro-secops from ./cmd/kiro-secops
make vet     # go vet + gofmt check
make test    # go test ./...
make dist    # cross-compiles the 5 targets
```

Details: [`docs/dev/DEVELOPMENT.md`](docs/dev/DEVELOPMENT.md).
Architecture: [`docs/dev/ARCHITECTURE.md`](docs/dev/ARCHITECTURE.md).

## Code rules

- **gofmt** mandatory; `go vet` clean; tests passing.
- **Minimal dependencies** (stdlib + `gopkg.in/yaml.v3`): do not add new third-party
  dependencies without a justifying, documented decision. When touching dependencies, run `go mod tidy && go mod vendor`
  and **commit the updated `vendor/`**.
- When changing the payload (`internal/assets/payload/`), run `make build` (re-embed) and test `install`/`init`.
- Security: no hardcoded secrets; follow [`docs/security/SECURITY-BASELINE.md`](docs/security/SECURITY-BASELINE.md).

## Reporting bugs and suggestions

Use **GitHub Issues** to report bugs or suggest improvements. Before opening, **search the
existing issues** (open and closed) to avoid duplicates. When opening, include:

- reproducible step-by-step and the expected vs. observed behavior;
- `kiro-secops` version, OS/architecture, and Go version;
- relevant logs/outputs (**no secrets**).

## Contributing via Pull Request

1. Create a branch from `main`.
2. Small, descriptive commits (conventional: `feat:`, `fix:`, `docs:`, `refactor:`).
3. Run `make vet && make test` (and, if touching the example images, `docker build --check`) before opening the PR.
4. Describe the **what** and the **why**; reference the related issue.
5. Do not mix unrelated changes in the same PR.

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
See the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
opensource-codeofconduct@amazon.com with any questions.

## Security issue notifications

If you discover a potential **security** issue, please do **NOT** open a public issue.
Notify AWS/Amazon Security via the
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/).

## Licensing

This project is licensed under **MIT-0** (see [`LICENSE`](LICENSE)). By contributing, you agree
that your contribution will be licensed under the same terms.
