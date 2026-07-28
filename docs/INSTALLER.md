# `kiro-secops` installer guide

`kiro-secops` is a **single binary** (Go, minimal dependencies, cross-platform) that installs and operates
Kiro's DevSecOps baseline. It **embeds** the entire `internal/assets/payload/` via `//go:embed` — it needs no
runtime, network, or dependencies at the destination.

- **macOS, Linux, and Windows** (one binary per OS/arch).
- **No `sudo`** (installs to the user's `~/.kiro`).
- Respects the **`KIRO_HOME`** variable (overrides `~/.kiro`).

## Get the binary

> **This sample does not publish *releases*.** To use `kiro-secops`, choose an option:
> - **Build from source** (simplest): `make build` (or `go build ./cmd/kiro-secops`).
> - **Generate a signed release in your fork**: enable the template in
>   [`examples/release/`](../examples/release/) and publish a `vX.Y.Z` tag.
>
> The steps below show how to **consume a release that YOU published in your fork** — replace
> `SEU-ORG` with your repository's owner.

Each **Release** (in your fork) publishes one archive per OS/architecture, plus `checksums.txt`, the
`checksums.txt.sigstore.json` signature, and the SBOMs. Download it from your repository's **Releases**
page or via `gh` (GitHub CLI).

Choose the archive for your system (`<version>` = release version, e.g.: `1.1.0`):

| System | Architecture | Release archive |
|---|---|---|
| macOS (Apple Silicon, M1+) | arm64 | `kiro-secops_<version>_darwin_arm64.tar.gz` |
| macOS (Intel) | amd64 | `kiro-secops_<version>_darwin_amd64.tar.gz` |
| Linux | x86_64 | `kiro-secops_<version>_linux_amd64.tar.gz` |
| Linux | ARM64 | `kiro-secops_<version>_linux_arm64.tar.gz` |
| Windows | x86_64 | `kiro-secops_<version>_windows_amd64.zip` |

> Find your architecture with `uname -m` (macOS/Linux): `arm64`/`aarch64` → ARM64; `x86_64` → amd64.
> On Windows, `echo %PROCESSOR_ARCHITECTURE%` (`AMD64`).

---

### macOS — download, verify, and install

```bash
# 1) Set the version and detect the architecture
VER=1.1.0
ARCH=$([ "$(uname -m)" = "arm64" ] && echo arm64 || echo amd64)
BASE="https://github.com/SEU-ORG/sample-kiro-secops-baseline/releases/download/v${VER}"
ARQ="kiro-secops_${VER}_darwin_${ARCH}.tar.gz"

# 2) Download the archive + checksums + signature
curl -fsSLO "${BASE}/${ARQ}"
curl -fsSLO "${BASE}/checksums.txt"
curl -fsSLO "${BASE}/checksums.txt.sigstore.json"

# 3) Verify INTEGRITY (required)
shasum -a 256 -c checksums.txt --ignore-missing

# 4) Verify AUTHENTICITY with cosign (recommended; brew install cosign)
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/SEU-ORG/sample-kiro-secops-baseline' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 5) Extract and install into PATH (choose ONE option)
tar -xzf "${ARQ}" kiro-secops
xattr -d com.apple.quarantine ./kiro-secops 2>/dev/null || true   # clears Gatekeeper
#   a) without sudo (recommended): ~/.local/bin
mkdir -p ~/.local/bin && mv kiro-secops ~/.local/bin/
#   b) for all users: sudo mv kiro-secops /usr/local/bin/

# 6) Ensure the directory is on PATH and confirm
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.zshrc to persist
kiro-secops version
```

---

### Linux — download, verify, and install

```bash
# 1) Version + architecture
VER=1.1.0
case "$(uname -m)" in
  x86_64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)"; exit 1 ;;
esac
BASE="https://github.com/SEU-ORG/sample-kiro-secops-baseline/releases/download/v${VER}"
ARQ="kiro-secops_${VER}_linux_${ARCH}.tar.gz"

# 2) Download archive + checksums + signature
curl -fsSLO "${BASE}/${ARQ}"
curl -fsSLO "${BASE}/checksums.txt"
curl -fsSLO "${BASE}/checksums.txt.sigstore.json"

# 3) INTEGRITY (required)
sha256sum -c checksums.txt --ignore-missing

# 4) AUTHENTICITY with cosign (recommended)
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/SEU-ORG/sample-kiro-secops-baseline' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 5) Extract and install
tar -xzf "${ARQ}" kiro-secops
mkdir -p ~/.local/bin && mv kiro-secops ~/.local/bin/    # or: sudo mv kiro-secops /usr/local/bin/

# 6) PATH + confirmation
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.bashrc to persist
kiro-secops version
```

---

### Windows — download, verify, and install (PowerShell)

```powershell
# 1) Version and URL
$Ver  = "1.1.0"
$Base = "https://github.com/SEU-ORG/sample-kiro-secops-baseline/releases/download/v$Ver"
$Arq  = "kiro-secops_${Ver}_windows_amd64.zip"

# 2) Download the archive + checksums
Invoke-WebRequest "$Base/$Arq" -OutFile $Arq
Invoke-WebRequest "$Base/checksums.txt" -OutFile checksums.txt

# 3) Verify INTEGRITY (compare with the archive's line in checksums.txt)
(Get-FileHash $Arq -Algorithm SHA256).Hash.ToLower()
Select-String -Path checksums.txt -Pattern $Arq

# 4) (Optional) AUTHENTICITY with cosign (winget install sigstore.cosign)
#    cosign verify-blob --bundle checksums.txt.sigstore.json `
#      --certificate-identity-regexp '^https://github.com/SEU-ORG/sample-kiro-secops-baseline' `
#      --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt

# 5) Extract to a user folder
$Dest = "$env:LOCALAPPDATA\Programs\kiro-secops"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Expand-Archive -Path $Arq -DestinationPath $Dest -Force

# 6) Add to the user PATH (open a new terminal afterward)
[Environment]::SetEnvironmentVariable("Path",
  "$Dest;" + [Environment]::GetEnvironmentVariable("Path","User"), "User")

# 7) In a NEW terminal, confirm
kiro-secops version
```

> On Windows, the binary is named `kiro-secops.exe`; the `kiro-secops` command works on PATH.
> SmartScreen may warn because it's a binary without a Windows code signature — integrity
> comes from `checksums.txt` + cosign; allow it if verification passed.

---

### Verification — what each step guarantees

- **`checksums.txt` (SHA-256):** the downloaded archive was not corrupted/altered in transit.
- **`cosign verify-blob` (keyless/OIDC):** the checksums were signed **by this repository's release
  pipeline** (authenticity). Requires [cosign](https://docs.sigstore.dev/).
- **SLSA provenance (optional):** where/how the artifact was built.
  ```bash
  gh attestation verify kiro-secops_<version>_<os>_<arch>.tar.gz --repo SEU-ORG/sample-kiro-secops-baseline
  ```

---

### Option B — build from source (requires **Go ≥ 1.25**)

For those who prefer not to download binaries, or want their own builds:

```bash
git clone https://github.com/aws-samples/sample-kiro-secops-baseline && cd sample-kiro-secops-baseline
make build          # builds ./kiro-secops for your OS
# or cross-compile for all targets:
make dist           # dist/kiro-secops-{darwin,linux,windows}-{arch}[.exe]
```

Put the binary on **PATH**:

```bash
# macOS/Linux
mkdir -p ~/.local/bin && cp kiro-secops ~/.local/bin/   # ensure ~/.local/bin is on PATH
```

Build/cross-compile/signing details: see [DEVELOPMENT.md](dev/DEVELOPMENT.md).

## Complete flow (getting started)

```bash
# 1) build and make the binary available
make build && cp kiro-secops ~/.local/bin/

# 2) install the GLOBAL baseline (once per machine) and ensure PATH
kiro-secops install
export PATH="$HOME/.kiro/bin:$PATH"        # install also copies the binary to ~/.kiro/bin

# 3) in each project that wants the WORKSPACE layer (hooks + CI), and commit
cd my-project && kiro-secops init
git add .kiro .pre-commit-config.yaml .gitleaks.toml trivy.yaml .checkov.yaml .github

# 4) day to day
kiro-secops verify        # checks that the guard responds (self-test) and whether the installation exists
kiro-secops scan .        # runs the available scanners
```

> Restart the Kiro session after `install` to load steering/skills/agents/permissions.

---

## Command summary

| Command | What it does | Writes to |
|---|---|---|
| `kiro-secops install` | Installs the **global** config (transactional + manifest) | `~/.kiro/` (steering, skills, agents, settings, bin) |
| `kiro-secops init` | **Scaffolds** a project (transactional + manifest) | project `.kiro/` + scanner configs at the root |
| `kiro-secops guard` | Hook runtime (reads JSON from stdin) | — (decides allow/block; *fail-closed*) |
| `kiro-secops scan [--advisory] [--require-tools] [--timeout D] [--format text\|json\|sarif] [--output F] [DIR]` | Runs the available scanners | — (findings **block**; `--advisory` only reports) |
| `kiro-secops verify [--strict]` | Guard self-test (+ installation integrity with `--strict`) | — |
| `kiro-secops uninstall [--project DIR]` | **Restores** the previous state (via manifest) global or **workspace** | `~/.kiro/` or `.kiro/`+project configs |
| `kiro-secops version` | Shows the version | — |

Flags: `--dry-run` (install/init/uninstall — shows what it would do, without writing); `--force`
(install/init — replaces the managed artifact after a safe backup; uninstall — restores even if the
artifact was modified); `--project <dir>` (only `init`/`uninstall`); `--profile baseline|strict`
(only `install` — `permissions.yaml` profile); `--strict` (only `verify`);
`--advisory`/`--require-tools`/`--timeout`/`--format`/`--output` (only `scan`).

---

## `install` — global baseline (follows the person)

```bash
kiro-secops install            # -> ~/.kiro
KIRO_HOME=/opt/kiro kiro-secops install --dry-run
```

Deploys the contents of `internal/assets/payload/global/`:

- `~/.kiro/steering/*.md` — policies/guidance (security-policies, api-security, infrastructure-security)
- `~/.kiro/skills/kiro-secops-review/` — review skill + references per language
- `~/.kiro/agents/kiro-secops-reviewer.md` — read-only AppSec agent
- `~/.kiro/settings/permissions.yaml` — **enforcement** (structural merge by managed items; see below)
- `~/.kiro/settings/kiroignore` — global ignore (managed block)
- `~/.kiro/bin/kiro-secops` — a copy of the binary itself (so the hooks can find it)

**Profiles (`--profile`).** `--profile baseline` (default) installs the balanced baseline; `--profile
strict` installs a more locked-down baseline (no broad allow of package managers in the shell,
`web_fetch: deny` network, MCP/config writing set to `ask`). The active profile is recorded as a
comment in the managed items of `permissions.yaml` and is shown by `kiro-secops verify`. Reinstalling
with a different profile replaces the managed items (without duplicating), preserving your own rules.

Runs **once per machine/user**. When it finishes, the installer **detects your OS/shell** and prints
the exact instruction to put `~/.kiro/bin` on the `PATH` (or warns if it already is). Then restart the
Kiro session. It refuses to run as **root**.

---

## `init` — workspace layer (follows the project)

```bash
cd my-project && kiro-secops init
kiro-secops init --project /path/to/project --dry-run
```

Generates, in the project (to **commit** and share with the team):

- `.kiro/hooks/kiro-secops.json` — namespaced hooks (copied from `internal/assets/payload/workspace/kiro/hooks/`):
  - `PreToolUse` (shell and write) → call `kiro-secops guard` **by the binary's absolute path**
  - `Stop` → security review prompt
  - `PostTaskExec` → `kiro-secops scan --advisory` (non-blocking scan at the end of the task)
  - `PostFileCreate` on specs → injects *Security Requirements* / *Threat Model*
- `.pre-commit-config.yaml`, `.gitleaks.toml`, `trivy.yaml`, `.checkov.yaml`
- `.github/workflows/security-scan.yml`

`init` resolves and **validates** the guard binary (via `KIRO_HOME/bin`, `KIRO_SECOPS_BIN`, or `PATH`)
and writes the **absolute path** into the hooks — if the runtime is not found, `init` **fails** (nothing
is written). `init` is **independent** of `install`, is idempotent, and is **transactional** (writes an
ownership manifest and rolls back on failure).

---

## `guard` — hook runtime (cross-platform)

Reads the hook context (JSON) from **stdin** and decides, in a **binary and fail-closed** way:

- **exit 2** → **blocks** the tool (stderr returns to the model). E.g.: `rm -rf /`, `curl | sh`,
  `/dev/tcp` reverse shell, `mkfs`, `dd of=/dev/...`, `chmod -R 777`, writing to `.env`/keys.
- **exit 0** → **allows**.

Fields read from `tool_input`: `command`/`cmd` (shell) and `path`/`file_path`/`targetFile` (write),
with normalized separators (Windows). The guard is **fail-closed**: a payload over the limit, invalid
JSON, or an unknown `tool_input` schema result in a **block (exit 2)** — a protocol change does not
silently disable the control.

> **Confirmation (`ask`) is not done by the hook.** In the current Kiro CLI protocol, the stdout of a
> `PreToolUse` hook does not decide confirmation. Therefore, high-impact actions that should **ask for
> confirmation** (e.g.: `sudo`, `terraform apply/destroy`, `kubectl delete`, `git push --force`) live in
> `permissions.yaml` with `effect: ask`. The guard covers only the **hard block** (`deny`), which is
> deterministic.

> The guard's denylist **is not a sandbox** (it's bypassable via rewriting). It's one layer; strong,
> agent-agnostic enforcement lives in `permissions.yaml`.

---

## `scan`, `verify`, `uninstall`

```bash
kiro-secops scan .                   # semgrep/bandit/pip-audit/njsscan/npm audit/shellcheck/trivy/gitleaks — FINDINGS BLOCK
kiro-secops scan --advisory .        # same scan, but only reports (exit 0) — used by the PostTaskExec hook
kiro-secops verify --strict          # guard self-test + installation integrity against the manifest
kiro-secops uninstall                # GLOBAL: restores the previous state from the manifest
kiro-secops uninstall --project .    # WORKSPACE: restores the previous state from the manifest
```

`scan` detects the language by the presence of files and **degrades safely** (skips missing tools). By
default it is **blocking**: findings return **exit 1**, and an operational failure (e.g.: a scanner
stuck beyond `--timeout`) returns **exit 2**. Use `--advisory` to only report (exit 0),
`--require-tools` to fail when an applicable scanner is not installed, and `--timeout` to limit each
scanner.

`verify` runs the guard's deterministic self-test (block/allow). With **`--strict`**, it also validates
the global installation against the **manifest** (presence + hash of each artifact) and **fails (exit
1)** if anything is missing, modified, or if the manifest does not exist.

**`uninstall` has two scopes** (mirroring `install`/`init`) and is **based on the ownership manifest** —
it never removes by guessing names:

- **no flag** → **restores** the **global** layer of `~/.kiro` (respects `KIRO_HOME`) to the
  pre-installation state: removes what `install` created and **restores byte for byte** (with the
  original mode) any file that already existed before.
- **`--project <dir>`** → same for the **workspace** layer created by `init`.

In both cases, if a managed artifact has been **modified** after installation, `uninstall` refuses to
remove it without `--force` (protection against losing edits). Without a manifest, `uninstall` **fails**
instead of deleting blindly. It supports `--dry-run` — the removal must be **committed** in the
workspace case.

> **Installing the scanners** (semgrep, trivy, gitleaks, bandit, etc.), by environment
> (macOS/Linux/Windows/CI/Docker) and with **pinned versions**: see **[TOOLS.md](TOOLS.md)**.

---

## Idempotency, ownership, and restoration

- **Idempotent:** re-running does not duplicate or corrupt.
- **Transactional + manifest:** `install`/`init` write an **ownership manifest**
  (`.kiro-secops/manifest.json`) with the hash of each artifact and a **backup** of the original content
  (under `.kiro-secops/backups/`). On a mid-way failure, they **roll back**.
- **`permissions.yaml`:** **structural** merge (YAML parser, not text). The kiro-secops rules are
  inserted as marked items in the `rules` sequence; the user's rules are **preserved**. Re-running
  replaces only the managed items. Invalid/ambiguous input YAML is **rejected** (fail-closed) instead of
  corrupted.
- **`kiroignore`:** managed block (`# >>> … >>>`), idempotent and preserving negations (`!`).
- **Safe writing:** confined to the root via `os.Root` (refuses symlinks in any path component),
  **atomic** (temp + `fsync` + `rename`), and preserving the existing file's mode.
- **`uninstall`** uses the manifest to **restore exactly** the previous state (byte for byte and mode),
  instead of removing by name.

## Distribution (roadmap)

Releases (with `SHA256SUMS` + signature + SLSA provenance) and MDM (with *drift correction*)
for the fleet.
