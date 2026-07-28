# Example: security CI with Kiro CLI *headless* in Docker

A container image **ready to fork and edit** that runs the **Kiro CLI in headless mode**
(`--no-interactive`) for security in pipelines, reusing the **`kiro-secops-reviewer`** agent that
`kiro-secops install` deploys (the same product review logic — a single source of truth).

> **This is an EXAMPLE.** Copy the folder into your project, tune the prompts, pin the versions, and
> publish the image to your registry. Nothing here runs automatically in this repository.

One image (`Dockerfile.review`), one `entrypoint.sh` with three modes:

| Mode          | What it does                                                                     |
|---------------|----------------------------------------------------------------------------------|
| `review`      | Reviews the **PR diff** (`git diff BASE_REF...HEAD`)                              |
| `pipeline`    | Reviews **CI / IaC workflows** (GitHub Actions, GitLab, Terraform)               |
| `dast-triage` | **AI triage** of a **DAST** JSON report that YOU generated (ZAP, Nuclei, …)      |

> **DAST is "bring your own scanner" (BYO).** The image **does not bundle** OWASP ZAP or Nuclei — scanners
> depend on an external source/image and on the environment (running target, auth, mirror to ECR). You
> run the scanner in your CI, generate a JSON report, and the image performs the **AI triage** of it. See
> [Configure DAST](#configure-dast-in-your-cicd-byo-scanner).

## Philosophy (read first)

Mirrors the golden rule from [`docs/PIPELINES.md`](../../docs/PIPELINES.md): **the gate that blocks the
merge must be deterministic** (scanners / `kiro-secops scan`). AI review is **advisory** —
non-deterministic and consumes credits. That's why the example workflows run the AI part with
`continue-on-error` / `allow_failure`. The `entrypoint.sh` *knows how* to block (exits with `BLOCK_EXIT`
when the verdict is `BLOCK`), but you are the one who decides whether that fails the pipeline.

## Contents

```
examples/kiro-headless-ci/
├── Dockerfile.review        # lean image: kiro-cli + kiro-secops-reviewer agent (bases on ECR Public)
├── entrypoint.sh            # dispatcher: review | pipeline | dast-triage
├── prompts/                 # EDITABLE PROMPTS (the "brain" of each mode)
│   ├── pr-review.md
│   ├── pipeline-review.md
│   └── dast-triage.md
├── ci/
│   ├── github-actions.example.yml
│   └── gitlab-ci.example.yml
├── .env.example             # placeholders (NEVER commit real secrets)
└── README.md
```

## Prerequisites

- **Docker** (with BuildKit).
- **`KIRO_API_KEY`** (format `ksk_...`) — generate it at <https://app.kiro.dev>. Requires a Kiro
  **Pro/Pro+/Pro Max/Power** plan (if the account is managed by an admin, they must enable API keys).
- The **build context is the ROOT of the repo** (the image compiles the `kiro-secops` binary from source).

## Build

```bash
# from the repository root
docker build -f examples/kiro-headless-ci/Dockerfile.review -t kiro-secops-review:local .
```

## Local usage

```bash
export KIRO_API_KEY=ksk_...            # secret; never commit

# 1) PR diff review (mount the repo at /workspace)
docker run --rm \
  -e KIRO_API_KEY -e BASE_REF=origin/main -e KIRO_LOG_NO_COLOR=1 \
  -v "$PWD:/workspace" \
  kiro-secops-review:local review

# 2) Review of your own workflows / IaC
docker run --rm \
  -e KIRO_API_KEY -e KIRO_LOG_NO_COLOR=1 \
  -v "$PWD:/workspace" \
  kiro-secops-review:local pipeline

# 3) Triage of a DAST report you generated (see "Configure DAST")
docker run --rm -i \
  -e KIRO_API_KEY -e KIRO_LOG_NO_COLOR=1 \
  kiro-secops-review:local dast-triage < dast-report.json
```

The last output printed (last line) is the gate marker: `VERDICT: PASS` or
`VERDICT: BLOCK`. Exit code `0` = PASS; `BLOCK_EXIT` (default `1`) = BLOCK.

## Configure DAST in your CI/CD (BYO scanner)

DAST tests a **running** application and requires an external scanner. Since these scanners come from
third-party images/binaries (and environments have different registry policies — e.g., AWS
requires **ECR**), the scanner is **the one you choose and run**; this example's image only performs the
**AI triage** of the report. Flow:

1. Run the scanner against a **RUNNING** target that you are **authorized** to test → generate
   a **JSON** report.
2. Pass the report to the review image in `dast-triage` mode (via `DAST_REPORT=<file>` or
   through stdin).

### Choose the scanner — OWASP ZAP vs. Nuclei

| Criterion                   | OWASP ZAP                                   | Nuclei                                      |
|-----------------------------|---------------------------------------------|---------------------------------------------|
| Model                       | proxy + crawl + passive/active scan         | templates against targets you provide       |
| Discovers the surface       | **Yes** (spider/AJAX)                       | No (you provide the URLs)                    |
| Strong at                   | injection (SQLi/XSS), session/auth, deep DAST | known CVEs/exposures/misconfig, speed      |
| Weight / image              | heavy (JVM), large image                    | lightweight, **single binary**              |
| Distribution                | **image only** (Docker Hub/GHCR)            | signed **binary** + `checksums.txt`         |
| Registry (ECR/BuilderHub)   | **mirror the image to your ECR**            | binary — **no external image**              |
| Best when                   | you need deep DAST (crawl + active)         | fast gate in CI + clean ECR compliance      |

**Recommendation:** for **registry compliance** (ECR/BuilderHub) without exception, prefer **Nuclei**
(pinned binary + verified checksum, no external image). If you need ZAP's **depth** (crawl + active
scan), **mirror the ZAP image to your ECR** and use it — ZAP does **not** have an
image on ECR Public.

### Example A — Nuclei (binary, no external image)

```bash
# 1) scan (download the Nuclei binary pinning the version + verifying the checksum; AUTHORIZED target)
nuclei -target "$TARGET_URL" -severity medium,high,critical -json-export nuclei-report.json
# 2) AI triage (the image does not run the scanner)
docker run --rm -i -e KIRO_API_KEY -e KIRO_LOG_NO_COLOR=1 \
  kiro-secops-review:local dast-triage < nuclei-report.json
```

### Example B — OWASP ZAP (image mirrored to YOUR ECR)

```bash
# 1) scan with ZAP from YOUR mirrored image (ZAP does not exist on ECR Public)
docker run --rm -v "$PWD:/zap/wrk" <account>.dkr.ecr.<region>.amazonaws.com/zap-stable \
  zap-baseline.py -t "$TARGET_URL" -J zap-report.json
# 2) AI triage
docker run --rm -e KIRO_API_KEY -v "$PWD:/work" \
  -e DAST_REPORT=/work/zap-report.json \
  kiro-secops-review:local dast-triage
```

> **Authorized targets only.** ZAP baseline and Nuclei send active requests to the target. Run
> **only** against systems that you own or have explicit authorization to test.

## In CI/CD

See [`ci/github-actions.example.yml`](ci/github-actions.example.yml) and
[`ci/gitlab-ci.example.yml`](ci/gitlab-ci.example.yml). Both:

- run the image via **`docker run`** (respects the image's **non-root** user — avoids the
  *container job* problem that forces root);
- store `KIRO_API_KEY` as the provider's **secret**;
- treat the AI as **advisory** (the hard gate is the deterministic scanner); DAST (scanner + triage)
  is opt-in.

## How to customize (fork)

| I want to…                          | Where to change it |
|-------------------------------------|--------------------|
| Change what the AI looks for        | edit `prompts/*.md` (or mount one and point `PROMPT_FILE` to it) |
| Use another agent                   | `KIRO_AGENT=<name>` (default `kiro-secops-reviewer`) |
| Loosen/tighten the tool permissions | `KIRO_TRUST_TOOLS=fs_read` (default; least privilege) |
| Make the gate more/less strict      | `BLOCK_EXIT` (0 = never fails) + `continue-on-error`/`allow_failure` in CI |
| Pin the Kiro CLI version            | `--build-arg KIRO_CLI_SHA256=<sha>` (see "Supply chain" below) |
| Swap the base images' registry      | defaults on **ECR Public**; `--build-arg GO_IMAGE=...` / `UBUNTU_REF=...` (e.g., internal ECR `<account>.dkr.ecr.<region>.amazonaws.com/...`) |
| Pin the base images by digest       | `--build-arg GO_IMAGE=public.ecr.aws/docker/library/golang:1.25-bookworm@sha256:...` (same for `UBUNTU_REF`) |
| Choose/run the DAST scanner         | outside the image — see [Configure DAST](#configure-dast-in-your-cicd-byo-scanner) |

Variables recognized by `entrypoint.sh`: `KIRO_MODE`, `BASE_REF`, `PROMPT_FILE`, `KIRO_AGENT`,
`KIRO_TRUST_TOOLS`, `BLOCK_EXIT`, `PIPELINE_GLOBS`, `DAST_REPORT`, `KIRO_LOG_NO_COLOR`.

## Security notes

- **Secrets:** `KIRO_API_KEY` always as a CI secret (masked/protected). In fork PRs, secrets are
  normally **not** exposed — plan according to your policy. Never print the key.
- **DAST only on authorized targets:** the scanner (which **you** run) sends active requests. Run
  **only** against systems that you own or have explicit authorization to test.
- **Least privilege:** the agent is **read-only** (`fs_write: deny`, no network) and we use
  `--trust-tools=fs_read`. Avoid `--trust-all-tools`.
- **Non-root:** the image runs as a non-root user (the baseline installation refuses root).
- **Base images' registry:** the defaults come from **ECR Public** (`public.ecr.aws` — publicly
  accessible, recommended by AWS and without Docker Hub's rate limit). Environments that require an
  **internal** registry (e.g., AWS/BuilderHub guidelines, `non-ecr-docker-image` finding) must
  **mirror** the images to their own ECR and override `GO_IMAGE`/`UBUNTU_REF` via
  `--build-arg`. The DAST scanner is BYO: prefer **Nuclei** (binary, no image) or **mirror ZAP**
  to your ECR.
- **Supply chain (the honest part):** the Kiro CLI installer is downloaded from the official endpoint over
  **HTTPS/TLS 1.2** and installed via the `install.sh` **bundled in the zip** — we do **not** use
  `curl | sh` (which this project's own deny-list blocks). However, upstream only publishes
  `/latest/` and does **not publish a per-file checksum**; for reproducible builds, download the zip
  once, compute the `sha256` and pin it with `--build-arg KIRO_CLI_SHA256=<sha>`. Also pin the base
  images by **digest**.
- **Hermetic build & SBOM:** the `kiro-secops` binary is compiled from `vendor/` with
  `GOTOOLCHAIN=local` and `-mod=vendor` — without downloading modules or a toolchain during the build. For
  supply-chain attestations, generate an SBOM and provenance in the build:
  `docker buildx build --sbom=true --provenance=true ...`.
- **Runtime UID:** when mounting the repo, files may belong to another UID; the `entrypoint.sh` already
  runs `git config --global --add safe.directory` to avoid the *dubious ownership* error.

## License

Sample under **MIT-0** (see [`../../LICENSE`](../../LICENSE)). Third-party components: `gopkg.in/yaml.v3`
(MIT, in `vendor/`) and **Kiro CLI** (Amazon terms, installed at build time). If you use **OWASP ZAP**
or **Nuclei** for DAST, they keep their own licenses and are **referenced only in the
documentation** (not bundled in this image).
