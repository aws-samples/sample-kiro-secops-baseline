# Generate the installer in your fork (release template)

This sample **does not publish releases** — the sample repository neither generates nor signs binaries.
Here is the **release pipeline as a template**: you enable it **in your fork** to produce the
`kiro-secops` installer (5 targets), with **checksums**, **SBOM**, **cosign signing
(keyless/OIDC)** and **SLSA provenance** — all under the **identity of your own repository**.

> Why doesn't it come active? GitHub Actions only runs workflows in `.github/workflows/`. Since this
> file lives in `examples/release/`, it is **inert** in the sample. Nothing here runs until you copy it.

## Activation (in your fork)

1. **Copy** the workflow into the active directory:
   ```bash
   mkdir -p .github/workflows
   cp examples/release/release.yml .github/workflows/release.yml
   git add .github/workflows/release.yml && git commit -m "ci: enable release in fork"
   ```
2. **Enable GitHub Actions** in the fork (*Actions* tab → *I understand my workflows, go ahead
   and enable them*). In forks, workflows come disabled by default.
3. Confirm that the workflow has the necessary **permissions** (already declared in the file):
   - `contents: write` — create the GitHub Release;
   - `id-token: write` — keyless cosign signing (OIDC);
   - `attestations: write` — SLSA provenance.
   If your organization restricts token permissions, adjust it in
   *Settings → Actions → General → Workflow permissions*.
4. **Publish a tag** — it is the release trigger:
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```
5. Follow the run in *Actions*. At the end, the **Release** appears in *Releases* with the `.tar.gz`/
   `.zip`, `checksums.txt`, `checksums.txt.sigstore.json`, SBOMs and the SLSA provenance.

## Verification (whoever consumes YOUR release)

The signature is issued under the identity of **your** repository. Replace `SEU-ORG` with the owner of your
fork when verifying:

```bash
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/SEU-ORG/sample-kiro-secops-baseline' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
shasum -a 256 -c checksums.txt --ignore-missing
```

## Notes

- **SLSA provenance** requires a **public or organization** repository. In a **private user**
  repository the step is skipped automatically (the attestation API does not exist there);
  make the repo public for verifiable provenance.
- The build/packaging configuration lives in [`../../.goreleaser.yaml`](../../.goreleaser.yaml)
  (it stays at the root; validated by `goreleaser check` in CI and usable via `make release-snapshot`,
  which **generates locally in `dist/` without publishing**).
- No hardcoded identity: cosign/SLSA use the **runner's OIDC**, so the release comes out under your
  fork's name without editing the workflow.
- Prefer **not** to publish signed binaries on behalf of third parties; enable this only in the repository
  that you control.
