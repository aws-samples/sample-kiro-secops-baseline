# Build the binaries in your fork (build template)

This sample **does not produce CI artifacts** — the sample repository runs only the quality gate
(`.github/workflows/ci.yml`). Here is the **build pipeline as a template**: you enable it **in your
fork** to compile and cross-compile the `kiro-secops` installer (5 targets: darwin/linux amd64+arm64,
windows amd64) and publish the binaries plus `SHA256SUMS` as a workflow **artifact** on every
push/PR.

> Why doesn't it come active? GitHub Actions only runs workflows in `.github/workflows/`. Since this
> file lives in `examples/build/`, it is **inert** in the sample. Nothing here runs until you copy it.

## Activation (in your fork)

1. **Copy** the workflow into the active directory:
   ```bash
   mkdir -p .github/workflows
   cp examples/build/build.yml .github/workflows/build.yml
   git add .github/workflows/build.yml && git commit -m "ci: enable build in fork"
   ```
2. **Enable GitHub Actions** in the fork (*Actions* tab → *I understand my workflows, go ahead
   and enable them*). In forks, workflows come disabled by default.
3. **Push** (or open a PR). The workflow triggers on `push` to `main`/`master` and on
   `pull_request`, and runs:
   - `go build ./...` — host build (sanity);
   - `make dist` — cross-compiles the 5 targets into `dist/`;
   - `make checksums` — generates `dist/SHA256SUMS`.
4. **Download the binaries**: open the run in *Actions* → section **Artifacts** → artifact
   `kiro-secops-binaries` (a `.zip` with the 5 binaries + `SHA256SUMS`).

## Verification (whoever consumes the artifact)

```bash
unzip kiro-secops-binaries.zip -d kiro-secops-binaries
cd kiro-secops-binaries
shasum -a 256 -c SHA256SUMS
```

## Local alternative (no CI)

The same outputs can be produced locally — the workflow is a thin wrapper over the Makefile:

```bash
make dist        # cross-compiles the 5 targets → dist/
make checksums   # generates dist/SHA256SUMS
```

Requirements: Go ≥ 1.25 (see [`docs/dev/DEVELOPMENT.md`](../../docs/dev/DEVELOPMENT.md)).

## Notes

- **Artifacts vs. releases**: this template produces **unsigned CI artifacts** (retention follows
  your repository's artifact settings). For versioned, **signed** releases — cosign (keyless/OIDC),
  SBOM, and SLSA provenance — enable the separate template in
  [`../release/`](../release/README.md).
- Actions are **pinned by commit SHA** (supply chain, A08). With the file inside
  `.github/workflows/`, Dependabot keeps the pins updated in your fork.
- The workflow needs only `permissions: contents: read` — no secrets and no extra permissions.
