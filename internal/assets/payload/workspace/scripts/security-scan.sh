#!/usr/bin/env bash
# =============================================================================
# security-scan.sh — PostTaskExec hook (does NOT block)
# -----------------------------------------------------------------------------
# Runs per-language scanners when present; degrades safely (skips whatever is
# not installed/applicable). For a BLOCKING gate, replicate it in CI (exit!=0)
# or move it to a PreTaskExec hook with exit 2.
# =============================================================================
set -uo pipefail
status=0
has()  { command -v "$1" >/dev/null 2>&1; }
anyf() { find . -type f -name "$1" -not -path '*/.git/*' -not -path '*/node_modules/*' -print -quit 2>/dev/null | grep -q .; }

# --- Universal SAST ---
if has semgrep; then
  echo "security-scan: Semgrep (SAST)..."; semgrep scan --quiet --config p/ci --error . || status=1
else echo "security-scan: semgrep missing (https://semgrep.dev)" >&2; fi

# --- Python (bandit + ruff S + pip-audit) ---
if anyf '*.py'; then
  has bandit    && { echo "security-scan: Bandit..."; bandit -r . -ll -q || status=1; }
  has ruff      && { echo "security-scan: Ruff (S)..."; ruff check --select S . || status=1; }
  has pip-audit && { echo "security-scan: pip-audit..."; pip-audit || status=1; }
fi

# --- Node/TypeScript (eslint + njsscan + npm audit) ---
if [ -f package.json ]; then
  has npx     && { echo "security-scan: ESLint (security)..."; npx --no-install eslint . || status=1; }
  has njsscan && { echo "security-scan: njsscan..."; njsscan -w . || status=1; }
  has npm     && { echo "security-scan: npm audit..."; npm audit --audit-level=high || status=1; }
fi

# --- Shell (shellcheck) ---
if anyf '*.sh' && has shellcheck; then
  echo "security-scan: ShellCheck..."
  find . -type f -name '*.sh' -not -path '*/.git/*' -print0 | xargs -0 -r shellcheck --severity=warning || status=1
fi

# --- SCA / IaC / secrets (cross-language) ---
if has trivy; then
  echo "security-scan: Trivy (vuln/secret/misconfig HIGH,CRITICAL)..."
  trivy fs --quiet --scanners vuln,secret,misconfig --severity HIGH,CRITICAL . || status=1
else echo "security-scan: trivy missing (https://trivy.dev)" >&2; fi
has gitleaks && { echo "security-scan: gitleaks..."; gitleaks detect --no-git --redact --source . || status=1; }

[ "$status" -ne 0 ] && echo "security-scan: FINDINGS detected — review before finishing (non-blocking)." >&2
exit 0
