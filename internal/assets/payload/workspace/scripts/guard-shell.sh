#!/usr/bin/env bash
# =============================================================================
# guard-shell.sh — PreToolUse hook for shell/execute_bash
# -----------------------------------------------------------------------------
# STDIN = the hook's JSON context.
#   exit 2  => BLOCKS (stderr goes back to the model)
#   exit 0  => allows; optionally emits JSON {permissionDecision:"ask"} to confirm
# Degrades safely: if 'jq' does not exist, it analyzes the raw payload.
# NOTE: a regex denylist is NOT a sandbox (bypassable via GTFOBins/base64/indirection).
#       Combine it with the project allowlist + permissions.yaml + least privilege.
# Taxonomy: sudo / git push --force / git reset --hard are in ASK (not BLOCK),
#           since they are legitimate under human confirmation.
# =============================================================================
set -uo pipefail

payload="$(cat)"
cmd=""
if command -v jq >/dev/null 2>&1; then
  cmd="$(printf '%s' "$payload" | jq -r '.tool_input.command // .tool_input.cmd // empty' 2>/dev/null || true)"
fi
haystack="${cmd:-$payload}"
# light anti-obfuscation normalization (collapses spaces/tabs)
norm="$(printf '%s' "$haystack" | tr '\t' ' ' | tr -s ' ')"

# --- BLOCK (exit 2): must never run ------------------------------------------
block_patterns=(
  'rm[[:space:]]+-[a-z]*r[a-z]*f[a-z]*[[:space:]]+(/|~|\$HOME|\.)([[:space:]]|/|\*|$)'  # rm -rf root/home
  'rm[[:space:]]+-[a-z]*f[a-z]*r[a-z]*[[:space:]]+(/|~|\$HOME)([[:space:]]|/|\*|$)'
  'rm[[:space:]]+(-[a-z]+[[:space:]]+)*--no-preserve-root'
  ':[[:space:]]*\(\)[[:space:]]*\{[^}]*:[[:space:]]*\|[[:space:]]*:'                    # fork bomb
  '\|[[:space:]]*(sudo[[:space:]]+)?(sh|bash|zsh|ksh|dash)([[:space:]]|$)'              # pipe -> shell
  '(base64|xxd|openssl[[:space:]]+enc)[[:space:]].*\|[[:space:]]*(sh|bash)'            # decode|shell
  '(sh|bash|zsh|dash)[[:space:]]+<[[:space:]]*\('                                      # bash <(curl ...)
  'eval[[:space:]]+.*(\$\(|`|curl|wget|base64)'                                        # eval of network/decode
  '/dev/(tcp|udp)/[0-9a-zA-Z]'                                                          # reverse shell
  '\bn(c|cat)\b[[:space:]]+.*(-e|-c)[[:space:]]+/'                                      # nc -e /bin/sh
  '\bmkfs(\.[[:alnum:]]+)?[[:space:]]'                                                  # format FS
  '\bdd\b[[:space:]].*[[:space:]]?of=/dev/(sd|nvme|hd|vd|disk|mmcblk)'                  # overwrite disk
  '>[[:space:]]*/dev/(sd|nvme|hd|vd|disk|mmcblk)'                                       # :> /dev/sda
  'chmod[[:space:]]+-[a-zA-Z]*R[a-zA-Z]*[[:space:]]+0*777'                              # chmod -R 777
  '\b(shred|wipefs|wipe)\b'                                                             # forensic destruction
  '>[[:space:]]*~?/?(\.bash_history|\.zsh_history)'                                     # erase history
)
for p in "${block_patterns[@]}"; do
  if printf '%s' "$norm" | grep -Eiq "$p"; then
    echo "guard-shell: command BLOCKED by security policy (pattern: $p)." >&2
    echo "Rewrite it without the pattern above or request human review." >&2
    exit 2
  fi
done

# --- ASK FOR CONFIRMATION (ask): high impact / privilege / network ------------
ask_patterns=(
  '(^|[[:space:]])sudo[[:space:]]'
  '(^|[[:space:]])su[[:space:]]+-?'
  'terraform[[:space:]]+(apply|destroy)'
  'kubectl[[:space:]]+delete'
  'helm[[:space:]]+(delete|uninstall|rollback)'
  'docker[[:space:]]+(push|system[[:space:]]+prune|rmi[[:space:]]+-[a-z]*f)'
  '(npm|yarn|pnpm)[[:space:]]+publish'
  'git[[:space:]]+push[[:space:]]+.*(--force|--force-with-lease|(^|[[:space:]])-f([[:space:]]|$))'
  'git[[:space:]]+reset[[:space:]]+--hard'
  'git[[:space:]]+clean[[:space:]]+-[a-z]*f'
  '(^|[[:space:]])(curl|wget)[[:space:]]'
  'chmod[[:space:]]+-[a-zA-Z]*R'                                    # -R non-777 (777 is BLOCK)
  '(>|>>|[[:space:]])(tee|cp|mv)?[[:space:]]*/(etc|usr|boot|System|Library)/'
  'aws[[:space:]]+(s3[[:space:]]+(rm|rb)|ec2[[:space:]]+terminate-instances|[a-z0-9-]+[[:space:]]+delete-)'
  'systemctl[[:space:]]+(stop|disable|mask)'
  '\bkill(all)?\b[[:space:]]+(-9|-KILL|-s[[:space:]]+9)'
  'crontab[[:space:]]+-r'
  'iptables[[:space:]]+(-F|--flush|-X)'
)
for p in "${ask_patterns[@]}"; do
  if printf '%s' "$norm" | grep -Eiq "$p"; then
    printf '%s\n' '{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"guard-shell: high-impact/privilege/network command detected — confirm before executing."}}'
    exit 0
  fi
done

exit 0
