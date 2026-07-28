# External tools — where to get them and how to install (by environment)

This guide covers the **external tools layer** that `kiro-secops` orchestrates but does **not
distribute**: the scanners called by `kiro-secops scan`, by `pre-commit`, and by the CI workflows.

> **Important:** `kiro-secops` (the binary) **does not depend** on any of these tools to
> compile, install (`install`), or operate the guard. `kiro-secops scan` **degrades safely**:
> if a tool is not on the `PATH`, it **skips** that step (`[skipped] <tool> (missing)`).
> Install only the ones that make sense for your project's languages.

- Binary guide: [INSTALLER.md](INSTALLER.md) · Customization: [CUSTOMIZATION.md](CUSTOMIZATION.md) · CI: [PIPELINES.md](PIPELINES.md)

---

## Inventory and pinned versions

Versions **validated in July 2026**. The ones marked *(mirrors pre-commit)* are pinned in
[`internal/assets/payload/workspace/pre-commit-config.yaml`](../internal/assets/payload/workspace/pre-commit-config.yaml) — keep
the two places in sync (see [§ Synchronization](#version-synchronization)).

| Tool | Pinned version | Role | Called by | Official source |
|---|---|---|---|---|
| **semgrep** | `1.166.0` *(mirrors pre-commit)* | Universal SAST | `scan`, pre-commit, CI | [semgrep/semgrep](https://github.com/semgrep/semgrep) |
| **gitleaks** | `8.21.2` *(mirrors pre-commit)* † | Secrets | `scan`, pre-commit | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| **checkov** | `3.2.0` *(mirrors pre-commit)* | IaC (TF/CFN/K8s/Docker) | pre-commit | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) |
| **detect-secrets** | `1.5.0` *(mirrors pre-commit)* | Secrets (baseline) | pre-commit (optional) | [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) |
| **trivy** | `0.71.0` ⚠️ | SCA + secret + IaC misconfig | `scan`, CI | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) |
| **bandit** | `1.9.4` | Python SAST | `scan` (py) | [PyCQA/bandit](https://github.com/PyCQA/bandit) |
| **pip-audit** | `2.9.0` | Python SCA | `scan` (py) | [pypa/pip-audit](https://github.com/pypa/pip-audit) |
| **ruff** | `0.15.20` | Python lint (`S` rules) | reference script | [astral-sh/ruff](https://github.com/astral-sh/ruff) |
| **njsscan** | `0.4.4` | Node SAST | `scan` (node) | [ajinabraham/njsscan](https://github.com/ajinabraham/njsscan) |
| **shellcheck** | `0.11.0` | Shell lint | `scan` (sh) | [koalaman/shellcheck](https://github.com/koalaman/shellcheck) |
| **pre-commit** | `4.5.1` | Shift-left orchestrator | workspace | [pre-commit.com](https://pre-commit.com) |
| **eslint** | `9.39.5` ‡ | JS/TS lint/security | reference script | [eslint.org](https://eslint.org) |
| **Node.js** | `24 LTS` (≥ `24.17.0`) | Runtime for `npm audit`/eslint | `scan` (node) | [nodejs.org](https://nodejs.org) |

† **gitleaks:** the latest stable in Jul 2026 is `8.30.1`, but we pin `8.21.2` to keep
**parity with the `pre-commit` hook**. To update, change it in **both** places (see §
Synchronization).
‡ **eslint:** the current major is `10.x` (e.g., `10.7.0`); we pin the `9.x` line (maintenance) for
**maximum compatibility** with security plugins. Adjust to fit your project.

> The "current stable" versions were checked against the official release pages in Jul 2026;
> check each tool's official source for newer patches before pinning in production.

---

## ⚠️ Supply chain note (read before installing)

Security tooling is also a **supply chain surface**. In **March 2026**, **Trivy**
suffered a compromise ([CVE-2026-33634](https://cyber.gc.ca/en/alerts-advisories/aqua-security-security-advisory-av26-283)):
releases, Docker images, and **`aquasecurity/trivy-action` tags** were replaced with malicious
versions. Versions **`v0.69.4`–`v0.69.6`** contained malware (the last safe version before was
`v0.69.3`; the current clean one is **`v0.71.0`**). Content [rewritten for licensing compliance].

Practical rules adopted in this guide:

1. **Pin versions** (pin) — never `latest` in CI/production.
2. **Verify integrity** — check the releases' `checksums`/signature before use.
3. **In GitHub Actions, pin by _commit SHA_**, not by tag (tags are mutable and were the vector of the
   incident). E.g.: `uses: aquasecurity/trivy-action@<full-sha>`.
4. **Docker: pin by _digest_** (`image@sha256:...`) when possible, not just by tag.
5. **NEVER** use `trivy` `v0.69.4`, `v0.69.5`, or `v0.69.6`.

---

## Prerequisites by ecosystem

The 13 tools fall into **3 groups**, which reduces installation to a few commands:

- **Python group** (via `pipx`, recommended): `semgrep`, `bandit`, `pip-audit`, `ruff`,
  `njsscan`, `checkov`, `pre-commit`, `detect-secrets`. Requires **Python ≥ 3.10**.
- **Standalone binary group**: `trivy`, `gitleaks`, `shellcheck`.
- **Node.js group**: `npm audit` (ships with Node) and `eslint`. Requires **Node.js 24 LTS**.

> **`pipx`** installs each Python CLI in an isolated environment (avoids dependency conflicts).
> Modern alternative: **`uv tool install <pkg>==<version>`** (Astral `uv`), if you already use `uv`.

---

## macOS

```bash
# 1) package managers/base
brew install pipx node                 # pipx (Python CLIs) + Node.js LTS
pipx ensurepath

# 2) standalone binaries (Homebrew follows the formula's "latest")
brew install trivy gitleaks shellcheck

# 3) Python CLIs with EXACT PIN
pipx install "semgrep==1.166.0"
pipx install "bandit==1.9.4"
pipx install "pip-audit==2.9.0"
pipx install "ruff==0.15.20"
pipx install "njsscan==0.4.4"
pipx install "checkov==3.2.0"
pipx install "pre-commit==4.5.1"
pipx install "detect-secrets==1.5.0"
```

> `brew` installs the **current** formula version (not pinned). To **pin** a binary (e.g.,
> `trivy 0.71.0`), prefer downloading the release and verifying the checksum (see [Linux](#linux), which applies
> the same on macOS by swapping `linux` for `darwin`).

---

## Linux

```bash
# 1) pipx + Node.js LTS (adjust to your package manager: apt/dnf)
python3 -m pip install --user pipx && python3 -m pipx ensurepath
#   Node.js 24 LTS: distro package (apt/dnf) or nodesource; if using nvm, download the
#   install.sh and verify it before running (avoid 'curl | bash').

# 2) Python CLIs with EXACT PIN
pipx install "semgrep==1.166.0" "bandit==1.9.4" "pip-audit==2.9.0" "ruff==0.15.20" \
             "njsscan==0.4.4" "checkov==3.2.0" "pre-commit==4.5.1" "detect-secrets==1.5.0"

# 3) trivy — pinned release + checksum verification (no curl|sh)
VER=0.71.0
BASE="https://github.com/aquasecurity/trivy/releases/download/v${VER}"
curl -sSfL -O "${BASE}/trivy_${VER}_Linux-64bit.tar.gz"
curl -sSfL -O "${BASE}/trivy_${VER}_checksums.txt"
sha256sum -c "trivy_${VER}_checksums.txt" --ignore-missing   # verifies only the downloaded .tar.gz
tar -xzf "trivy_${VER}_Linux-64bit.tar.gz" trivy && sudo install trivy /usr/local/bin/ && rm trivy*
trivy --version    # confirm: 0.71.0

# 4) gitleaks — download the pinned release and verify the checksum
VER=8.21.2
curl -sSfL -o gitleaks.tar.gz \
  "https://github.com/gitleaks/gitleaks/releases/download/v${VER}/gitleaks_${VER}_linux_x64.tar.gz"
# check against the release's checksums.txt BEFORE extracting:
#   curl -sSfL -o gitleaks.checksums "https://github.com/gitleaks/gitleaks/releases/download/v${VER}/gitleaks_${VER}_checksums.txt"
#   sha256sum -c gitleaks.checksums --ignore-missing
tar -xzf gitleaks.tar.gz gitleaks && sudo install gitleaks /usr/local/bin/ && rm gitleaks*

# 5) shellcheck — pinned release
VER=0.11.0
curl -sSfL "https://github.com/koalaman/shellcheck/releases/download/v${VER}/shellcheck-v${VER}.linux.x86_64.tar.xz" \
  | tar -xJf - && sudo install "shellcheck-v${VER}/shellcheck" /usr/local/bin/ && rm -rf "shellcheck-v${VER}"
```

> On distros with `apt`, `shellcheck` also comes via `apt-get install shellcheck` (distro
> version, not pinned). For strict reproducibility, prefer the release binary above.

---

## Windows

**Pure Python** tools and **binaries** work natively. **`semgrep` and `njsscan` do
not have reliable native support on Windows** — use **Docker** (below) or **WSL2**.

```powershell
# 1) binaries via winget (or scoop)
winget install AquaSecurity.Trivy
winget install Gitleaks.Gitleaks
winget install koalaman.shellcheck
winget install OpenJS.NodeJS.LTS
#   scoop alternative:  scoop install trivy gitleaks shellcheck nodejs-lts

# 2) pipx
py -m pip install --user pipx ; py -m pipx ensurepath

# 3) Python CLIs that run on Windows (EXACT PIN)
pipx install "bandit==1.9.4"
pipx install "pip-audit==2.9.0"
pipx install "ruff==0.15.20"
pipx install "checkov==3.2.0"
pipx install "pre-commit==4.5.1"
pipx install "detect-secrets==1.5.0"

# 4) semgrep and njsscan -> via Docker (section below) or WSL2 (where the Linux commands apply)
```

> The `winget`/`scoop` IDs may vary across versions. Confirm with `winget search trivy`
> (same for gitleaks/shellcheck) if any fails to resolve. `trivy` also supports pinning a version:
> `winget install AquaSecurity.Trivy --version 0.71.0`.

---

## Docker (universal fallback — and recommended on Windows for semgrep/njsscan)

Installs nothing on the host; ideal for Windows, ephemeral CI, and reproducibility. **Pin the tag**
(ideally the `@sha256:` digest) and mount the project at `/src`.

> **Registry (ECR/BuilderHub):** the images below are third-party in public registries
> (Docker Hub/GHCR). Where an **ECR Public** equivalent exists, it is already used (`python`, `trivy`); the
> others (`semgrep`, `gitleaks`, `shellcheck`, `checkov`) do **not** have an image on ECR Public — in
> environments that require ECR, use the **binaries/pipx** from the sections above or **mirror** those
> images to your ECR.

```bash
# Universal SAST — Semgrep
docker run --rm -v "${PWD}:/src" semgrep/semgrep:1.166.0 \
  semgrep scan --quiet --config p/ci --error /src

# Node SAST — njsscan (no stable official image: use the Python image)
docker run --rm -v "${PWD}:/src" -w /src public.ecr.aws/docker/library/python:3.12-slim \
  sh -c "pip install --quiet njsscan==0.4.4 && njsscan -w ."

# SCA + secret + IaC — Trivy  (PIN + prefer digest; see supply chain note)
docker run --rm -v "${PWD}:/src" public.ecr.aws/aquasecurity/trivy:0.71.0 \
  fs --quiet --scanners vuln,secret,misconfig --severity HIGH,CRITICAL /src

# Secrets — gitleaks
docker run --rm -v "${PWD}:/src" ghcr.io/gitleaks/gitleaks:v8.21.2 \
  detect --no-git --redact --source /src

# Shell — ShellCheck
docker run --rm -v "${PWD}:/mnt" koalaman/shellcheck:v0.11.0 script.sh

# IaC — Checkov
docker run --rm -v "${PWD}:/src" bridgecrew/checkov:3.2.0 -d /src --quiet --compact

# Python tools with no official image (bandit, pip-audit, ruff, detect-secrets):
docker run --rm -v "${PWD}:/src" -w /src public.ecr.aws/docker/library/python:3.12-slim \
  sh -c "pip install --quiet bandit==1.9.4 && bandit -r . -ll -q"
```

---

## CI (GitHub Actions)

Install by ecosystem (exact pin) and **pin the actions by commit SHA**. This complements the
`internal/assets/payload/workspace/github/workflows/security-scan.yml` (applied to projects by `kiro-secops init`).

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>            # pin by SHA
      - uses: actions/setup-python@<sha>
        with: { python-version: "3.12" }
      - name: Python scanners (exact pin)
        run: |
          pip install "semgrep==1.166.0" "bandit==1.9.4" "pip-audit==2.9.0" \
                      "checkov==3.2.0" "njsscan==0.4.4"
          semgrep scan --config p/ci --error .
      # Trivy: prefer the pinned binary over using the action by tag (vector of the 2026 incident).
      - name: Trivy (pinned binary + checksum)
        run: |
          VER=0.71.0
          BASE="https://github.com/aquasecurity/trivy/releases/download/v${VER}"
          curl -sSfL -O "${BASE}/trivy_${VER}_Linux-64bit.tar.gz"
          curl -sSfL -O "${BASE}/trivy_${VER}_checksums.txt"
          sha256sum -c "trivy_${VER}_checksums.txt" --ignore-missing
          tar -xzf "trivy_${VER}_Linux-64bit.tar.gz" trivy && sudo install trivy /usr/local/bin/
          trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --exit-code 1 .
      - name: gitleaks
        run: |
          VER=8.21.2
          curl -sSfL -o gl.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${VER}/gitleaks_${VER}_linux_x64.tar.gz"
          tar -xzf gl.tar.gz gitleaks && ./gitleaks detect --no-git --redact --source .
```

> If you prefer to use `aquasecurity/trivy-action`/`gitleaks/gitleaks-action`, **pin by commit SHA**
> (not by `@v0.x`/`@v2`) and reassess after the 2026 incident.

---

## Version synchronization

Four tools run **both as a CLI (this guide) and as a `pre-commit` hook**. To
avoid divergence (the hook finding X and the local CLI finding Y), keep the pins **identical** in both
places:

| Tool | Here (`TOOLS.md`) | `.pre-commit-config.yaml` (`rev:`) |
|---|---|---|
| semgrep | `1.166.0` | `v1.166.0` |
| gitleaks | `8.21.2` | `v8.21.2` |
| checkov | `3.2.0` | `3.2.0` |
| detect-secrets | `1.5.0` | `v1.5.0` (optional/commented) |

When updating, run `pre-commit autoupdate` (review the diff), reflect the same version here, and run
`kiro-secops scan .` to confirm the CLI agrees with the hook.

---

## Verification

```bash
# local scanners (kiro-secops skips whatever is missing)
kiro-secops scan .

# pre-commit hooks (mirror the CI gates)
pre-commit install
pre-commit run --all-files
```

If `kiro-secops scan` prints `[skipped] X (missing)`, the tool `X` is not on the `PATH` — go back
to your environment's section and install it (or use the Docker fallback).
