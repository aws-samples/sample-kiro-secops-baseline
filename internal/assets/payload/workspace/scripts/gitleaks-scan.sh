#!/usr/bin/env bash
# =============================================================================
# gitleaks-scan.sh — PostFileSave hook (does not block; only warns)
# -----------------------------------------------------------------------------
# Runs gitleaks on the working directory when a file is saved.
# Degrades safely: if gitleaks is not installed, it only warns.
# =============================================================================
set -uo pipefail

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks-scan: gitleaks not installed — skipping (https://github.com/gitleaks/gitleaks)" >&2
  exit 0
fi

cfg=""
[ -f .gitleaks.toml ] && cfg="--config .gitleaks.toml"

# shellcheck disable=SC2086
if ! gitleaks detect --no-git --no-banner --redact $cfg --source . >/dev/null 2>&1; then
  echo "gitleaks-scan: POSSIBLE SECRET detected in the working directory — review before committing." >&2
fi

exit 0
