#!/usr/bin/env bash
# =============================================================================
# guard-write.sh — PreToolUse hook for write tools (fs_write/write/str_replace)
# -----------------------------------------------------------------------------
# Receives the hook context as JSON on STDIN and BLOCKS (exit 2) writes to
# secret/credential files. Complements the deny in permissions.yaml and the
# .kiroignore. Degrades safely without 'jq'.
# =============================================================================
set -uo pipefail

payload="$(cat)"

path=""
if command -v jq >/dev/null 2>&1; then
  path="$(printf '%s' "$payload" | jq -r '.tool_input.path // .tool_input.file_path // .tool_input.targetFile // empty' 2>/dev/null || true)"
fi
haystack="${path:-$payload}"

# Canonical secret set — keep in sync with permissions.yaml, profiles/strict.yaml,
# kiroignore, and the guard binary (denyWriteRE); see payload_consistency_test.go.
deny_patterns=(
  '\.env($|[^a-zA-Z0-9])'   # .env and variations
  '\.env\.'                  # .env.local, .env.prod
  '(^|/)secrets/'            # secrets/ directory
  '\.pem'                    # PEM keys/certs
  '\.key'                    # keys
  'id_rsa'                   # SSH keys (RSA)
  'id_ed25519'               # SSH keys (Ed25519 — current default)
  'id_ecdsa'                 # SSH keys (ECDSA)
  '(^|/)credentials'         # credential files
  '\.p12'
  '\.pfx'
  '\.tfstate'                # Terraform state (holds secrets in cleartext)
  '(^|/)\.npmrc'             # npm auth tokens
  '(^|/)\.pypirc'            # PyPI auth tokens
)
for p in "${deny_patterns[@]}"; do
  if printf '%s' "$haystack" | grep -Eiq "$p"; then
    echo "guard-write: write BLOCKED to a sensitive/secret file (pattern: $p)." >&2
    echo "Use a secret manager (AWS Secrets Manager / SSM) instead of writing secrets to disk." >&2
    exit 2
  fi
done

exit 0
