# Review reference — Shell / Bash

Foot-guns (BAD→GOOD), ShellCheck codes, and tools. **Runtime blocking** of dangerous
commands is done by the `guard-shell.sh` guard (PreToolUse); this reference covers
**script review**. Based on: ShellCheck Wiki, OWASP OS Command Injection Cheat Sheet, CWE.

> A regex denylist **is not a sandbox** (bypassable via GTFOBins, base64, indirection). Treat
> it as one layer; combine with the project allowlist + `permissions.yaml` + least privilege.

## Foot-guns (BAD → GOOD)

### Command injection / unquoted variables — CWE-78 · SC2086, SC2046
```bash
# BAD
eval "$user_cmd"; grep $pattern $file; arr=($var)
# GOOD
grep -- "$pattern" "$file"        # quotes + '--' ends options (anti argument-injection)
run() { "$@"; }                    # argv array, no shell re-parse
[[ "$x" =~ ^[a-z0-9]{3,10}$ ]] || exit 1     # allowlist
```

### rm with a possibly empty variable — CWE-88 · SC2115
```bash
# BAD: if DIR is empty, deletes root/CWD
rm -rf "$DIR"/*
# GOOD
rm -rf "${DIR:?DIR not defined}"/*
```

### Download-and-execute without verification — CWE-494
```bash
# BAD
curl -s http://x/i.sh | sh
# GOOD
curl -fsSL https://x/i.sh -o i.sh
echo "<sha256>  i.sh" | sha256sum -c - && gpg --verify i.sh.sig i.sh && bash i.sh
```

### Insecure tempfile (TOCTOU) — CWE-377 · SC2064
```bash
# BAD
tmp=/tmp/app.$$
# GOOD
tmp="$(mktemp)" || exit 1; trap 'rm -f "$tmp"' EXIT   # SINGLE quotes in trap
```

### Secrets in argv/echo (visible in ps/history) — CWE-214/532
```bash
# BAD
curl -H "Authorization: Bearer $TOKEN" ...; mysql -p"$PASS"
# GOOD
read -rs TOKEN
printf 'machine h password %s\n' "$PASS" > ~/.netrc && chmod 600 ~/.netrc
export HISTCONTROL=ignorespace
```

### Missing strict mode / parsing `ls`
```bash
# GOOD — top of every script
set -euo pipefail; IFS=$'\n\t'
for f in *.txt; do [ -e "$f" ] || continue; process -- "$f"; done   # never $(ls)
```

## ShellCheck — relevant security codes
- **SC2086** unquoted variable → word split + glob (most important for injection)
- **SC2046** unquoted `$(...)`; **SC2068** unquoted `$@`
- **SC2064** `trap "..."` expands early → use single quotes
- **SC2115** `rm -rf "$X/"` without a guard → `"${X:?}"`
- **SC2029** `ssh host "cmd $var"` expands `$var` on the LOCAL host (remote injection)
- **SC1090/SC1091** `source` from a dynamic path (supply chain)

## Tools (commands)
```bash
shellcheck --severity=warning --enable=all script.sh
shfmt -d -i 2 -ci -s .            # deterministic formatting (reduces obfuscation and review errors)
gitleaks detect --no-git --redact --source .
```
pre-commit: `koalaman/shellcheck-precommit` + `scop/pre-commit-shfmt`.
