#!/usr/bin/env bash
#
# entrypoint.sh — orchestrates the Kiro CLI in headless mode for security in CI.
#
# Modes (1st argument or the KIRO_MODE variable; default: review):
#   review       reviews the PR diff (context = git diff BASE_REF...HEAD)
#   pipeline     reviews CI / IaC workflows (context = pipeline files)
#   dast-triage  AI triage of a JSON DAST report that YOU generated (OWASP ZAP, Nuclei, ...).
#                Does NOT run a scanner — the image bundles no external scanner. Pass the report
#                via DAST_REPORT=<file> or through stdin. See "Configure DAST" in the README.
#
# Philosophy (see docs/PIPELINES.md): the AI review is ADVISORY and non-deterministic.
# This script KNOWS how to block (returns BLOCK_EXIT when the verdict is BLOCK), but the one that
# decides whether that stops the merge is the pipeline (e.g.: continue-on-error/allow_failure).
# The HARD gate must be the deterministic scanner (`kiro-secops scan`).
#
set -euo pipefail

# --------------------------------------------------------------------------- utilities
log() { printf '[kiro-secops-ci] %s\n' "$*" >&2; }
die() { printf '[kiro-secops-ci] ERROR: %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------- configuration
MODE="${1:-${KIRO_MODE:-review}}"
PROMPTS_DIR="${PROMPTS_DIR:-/opt/kiro-secops/prompts}"
AGENT="${KIRO_AGENT:-kiro-secops-reviewer}"
TRUST_TOOLS="${KIRO_TRUST_TOOLS:-fs_read}" # least privilege: read-only
BASE_REF="${BASE_REF:-origin/main}"
BLOCK_EXIT="${BLOCK_EXIT:-1}" # exit code when the verdict is BLOCK
VERDICT_RE='^VERDICT:[[:space:]]*BLOCK'
PROMPT_PATH="" # set by set_prompt()
DAST_REPORT="${DAST_REPORT:-}" # (dast-triage mode) path to the JSON report; empty = read from stdin

# Clean logs by default (the operator can override).
export KIRO_LOG_NO_COLOR="${KIRO_LOG_NO_COLOR:-1}"

# --------------------------------------------------------------------------- pre-checks
[ -n "${KIRO_API_KEY:-}" ] || die "KIRO_API_KEY not set. Export it (CI secret) — format ksk_..."

# Validate the credential without printing the secret.
if ! kiro-cli whoami >/dev/null 2>&1; then
  die "authentication failed (kiro-cli whoami). Check KIRO_API_KEY and the plan/permission."
fi

# set_prompt DEFAULT_FILENAME — resolves the prompt (honors override via PROMPT_FILE) into PROMPT_PATH.
# Runs in the current shell (no subshell) so that 'die' actually terminates the script.
set_prompt() {
  PROMPT_PATH="${PROMPT_FILE:-$PROMPTS_DIR/$1}"
  [ -r "$PROMPT_PATH" ] || die "prompt not found/readable: $PROMPT_PATH"
}

# run_kiro — runs Kiro headless. The context arrives via stdin (here-string/redirect at the
# caller, NEVER through a pipe: a pipe would create a subshell and 'exit' would not terminate the
# script). The prompt goes as a positional argument. It gates on the VERDICT.
run_kiro() {
  local out rc
  set +e
  out="$(kiro-cli chat \
    --no-interactive \
    --agent "$AGENT" \
    --trust-tools="$TRUST_TOOLS" \
    --wrap never \
    "$(cat "$PROMPT_PATH")")"
  rc=$?
  set -e
  printf '%s\n' "$out"
  [ "$rc" -eq 0 ] || die "kiro-cli returned rc=$rc (execution failure, not a verdict failure)."
  if grep -Eq "$VERDICT_RE" <<<"$out"; then
    log "verdict: BLOCK — Critical/High findings. Exiting with $BLOCK_EXIT."
    exit "$BLOCK_EXIT"
  fi
  log "verdict: PASS."
}

# --------------------------------------------------------------------------- modes
mode_review() {
  command -v git >/dev/null || die "git not found in the image."
  git config --global --add safe.directory "$(pwd)" 2>/dev/null || true

  local diff
  if git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
    diff="$(git diff "$BASE_REF"...HEAD)"
  else
    log "warning: base ref '$BASE_REF' not found; using 'git diff HEAD' (working tree)."
    diff="$(git diff HEAD || true)"
  fi
  [ -n "$diff" ] || log "empty diff — nothing to review."
  set_prompt pr-review.md
  run_kiro <<<"$diff"
}

mode_pipeline() {
  command -v git >/dev/null || die "git not found in the image."
  git config --global --add safe.directory "$(pwd)" 2>/dev/null || true

  # Default globs cover GitHub Actions, GitLab CI, Jenkins, and Terraform.
  # Override with PIPELINE_GLOBS="glob1 glob2 ...".
  local globs=(".github/workflows/*.yml" ".github/workflows/*.yaml" ".gitlab-ci.yml" "Jenkinsfile" "*.tf")
  if [ -n "${PIPELINE_GLOBS:-}" ]; then
    # shellcheck disable=SC2206  # intentional split on spaces
    globs=(${PIPELINE_GLOBS})
  fi

  local files=() f context=""
  mapfile -t files < <(git ls-files -- "${globs[@]}" 2>/dev/null || true)
  [ "${#files[@]}" -gt 0 ] || log "no pipeline/IaC files found (globs: ${globs[*]})."
  for f in "${files[@]}"; do
    context+="===== $f ====="$'\n'
    context+="$(cat "$f")"$'\n\n'
  done
  set_prompt pipeline-review.md
  run_kiro <<<"$context"
}

# dast-triage: does NOT run a scanner (the image bundles no ZAP/Nuclei — that is BYO and stays in
# the docs). It receives a JSON DAST report (generated in YOUR CI) via DAST_REPORT=<file> or stdin
# and performs AI triage with kiro-secops-reviewer (dedupe, priority, CWE/OWASP, fix).
mode_dast_triage() {
  set_prompt dast-triage.md
  if [ -n "$DAST_REPORT" ]; then
    [ -r "$DAST_REPORT" ] || die "DAST report not found/readable: $DAST_REPORT"
    log "triaging DAST report: $DAST_REPORT"
    run_kiro <"$DAST_REPORT"
  elif [ ! -t 0 ]; then
    log "triaging DAST report received via stdin"
    run_kiro
  else
    die "dast-triage mode: provide the report via DAST_REPORT=<file> or through stdin (e.g.: cat report.json | docker run -i ... dast-triage). Generate the report with your scanner (ZAP/Nuclei) — see README."
  fi
}

# --------------------------------------------------------------------------- dispatch
case "$MODE" in
review) log "mode: review (BASE_REF=$BASE_REF)" && mode_review ;;
pipeline) log "mode: pipeline" && mode_pipeline ;;
dast-triage | dast) log "mode: dast-triage" && mode_dast_triage ;;
*) die "invalid mode: '$MODE' (use: review | pipeline | dast-triage)" ;;
esac
