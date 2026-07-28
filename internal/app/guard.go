package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const maxGuardPayload = 1 << 20

var (
	spaceRE      = regexp.MustCompile(`\s+`)
	assignmentRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// blockRE covers dangerous patterns that are independent of tokenization (pipe->shell,
// reverse shell, mkfs, dd, fork bomb, wipe, writes to history/device).
// Recursive rm/find/chmod are handled by the structural analyzer (dangerousSegment),
// which is resilient to flag variation, quoting, `--`, and compound commands.
var blockRE = mustAll([]string{
	`:\s*\(\)\s*\{[^}]*:\s*\|\s*:`,                     // fork bomb
	`(?i)\|\s*(sudo\s+)?(sh|bash|zsh|ksh|dash)(\s|$)`,  // pipe -> shell
	`(?i)(base64|xxd|openssl\s+enc)\s.*\|\s*(sh|bash)`, // decode | shell
	`(?i)(sh|bash|zsh|dash)\s+<\s*\(`,                  // shell <(...)
	`(?i)eval\s+.*(\$\(|curl|wget|base64)`,             // eval of remote content
	`(?i)/dev/(tcp|udp)/[0-9a-z]`,                      // reverse shell
	`(?i)\bn(c|cat)\b\s+.*(-e|-c)\s+/`,                 // netcat exec
	`(?i)\bmkfs(\.[a-z0-9]+)?\s`,                       // format filesystem
	`(?i)\bdd\b\s.*\s?of=/dev/(sd|nvme|hd|vd|disk|mmcblk)`,
	`(?i)>\s*/dev/(sd|nvme|hd|vd|disk|mmcblk)`,
	`(?i)\b(shred|wipefs|wipe)\b`,
	`(?i)>\s*~?/?(\.bash_history|\.zsh_history)`,
})

// denyWriteRE: secret paths whose writes are blocked (the path field and redirection
// targets in shell commands). Separators are normalized beforehand.
// Keep in sync with the canonical secret set shared by permissions.yaml,
// profiles/strict.yaml, kiroignore, and guard-write.sh — enforced by
// payload_consistency_test.go.
var denyWriteRE = mustAll([]string{
	`(?i)\.env($|[^a-z0-9])`,
	`(?i)\.env\.`,
	`(?i)(^|/)secrets/`,
	`(?i)\.pem`,
	`(?i)\.key`,
	`(?i)id_rsa`,
	`(?i)id_ed25519`,
	`(?i)id_ecdsa`,
	`(?i)(^|/)credentials`,
	`(?i)\.p12`,
	`(?i)\.pfx`,
	`(?i)\.tfstate`,
	`(?i)(^|/)\.npmrc`,
	`(?i)(^|/)\.pypirc`,
})

// criticalRoots are top-level directories whose recursive removal is catastrophic.
var criticalRoots = map[string]bool{
	"/etc": true, "/usr": true, "/bin": true, "/sbin": true, "/lib": true, "/lib64": true,
	"/var": true, "/boot": true, "/sys": true, "/proc": true, "/dev": true, "/root": true,
	"/opt": true, "/home": true, "/Users": true, "/System": true, "/Library": true, "/Applications": true,
}

func mustAll(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		out = append(out, regexp.MustCompile(pattern))
	}
	return out
}

func matchesDenyWrite(p string) bool {
	p = strings.ReplaceAll(p, `\`, "/")
	for _, expression := range denyWriteRE {
		if expression.MatchString(p) {
			return true
		}
	}
	return false
}

func guardEval(command, path string) int {
	if path != "" && matchesDenyWrite(path) {
		return exitUsage // exit 2 is the PreToolUse block contract.
	}
	if command != "" {
		normalized := spaceRE.ReplaceAllString(command, " ")
		for _, expression := range blockRE {
			if expression.MatchString(normalized) {
				return exitUsage
			}
		}
		for _, segment := range splitSegments(command) {
			if dangerousSegment(segment) {
				return exitUsage
			}
		}
	}
	return exitOK
}

// splitSegments splits a compound command into executable segments, respecting
// single/double quotes (separators: ; && || | & and newline).
func splitSegments(cmd string) []string {
	var segments []string
	var b strings.Builder
	var quote rune
	runes := []rune(cmd)
	flush := func() {
		if s := strings.TrimSpace(b.String()); s != "" {
			segments = append(segments, s)
		}
		b.Reset()
	}
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if quote != 0 {
			b.WriteRune(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			b.WriteRune(c)
		case ';', '\n', '\r':
			flush()
		case '|':
			if i+1 < len(runes) && runes[i+1] == '|' {
				i++
			}
			flush()
		case '&':
			if i+1 < len(runes) && runes[i+1] == '&' {
				i++
			}
			flush()
		default:
			b.WriteRune(c)
		}
	}
	flush()
	return segments
}

// tokenizeSegment breaks a segment into tokens, stripping quotes and separating
// redirection operators (> >> <) even when glued to a name.
func tokenizeSegment(seg string) []string {
	var tokens []string
	var b strings.Builder
	runes := []rune(seg)
	flush := func() {
		if b.Len() > 0 {
			tokens = append(tokens, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch c {
		case '\'':
			j := i + 1
			for j < len(runes) && runes[j] != '\'' {
				b.WriteRune(runes[j])
				j++
			}
			i = j
		case '"':
			j := i + 1
			for j < len(runes) && runes[j] != '"' {
				if runes[j] == '\\' && j+1 < len(runes) {
					b.WriteRune(runes[j+1])
					j += 2
					continue
				}
				b.WriteRune(runes[j])
				j++
			}
			i = j
		case '\\':
			if i+1 < len(runes) {
				b.WriteRune(runes[i+1])
				i++
			}
		case ' ', '\t', '\n', '\r':
			flush()
		case '>':
			flush()
			if i+1 < len(runes) && runes[i+1] == '>' {
				tokens = append(tokens, ">>")
				i++
			} else {
				tokens = append(tokens, ">")
			}
		case '<':
			flush()
			tokens = append(tokens, "<")
		default:
			b.WriteRune(c)
		}
	}
	flush()
	return tokens
}

// dangerousSegment analyzes a single segment: redirection to a secret and
// recursive/destructive commands (rm/find/chmod/chown) on dangerous targets.
func dangerousSegment(seg string) bool {
	tokens := tokenizeSegment(seg)
	if len(tokens) == 0 {
		return false
	}
	for i := 0; i+1 < len(tokens); i++ {
		if (tokens[i] == ">" || tokens[i] == ">>") && matchesDenyWrite(tokens[i+1]) {
			return true
		}
	}

	i := 0
	for i < len(tokens) && assignmentRE.MatchString(tokens[i]) { // skip VAR=val at the start
		i++
	}
	if i >= len(tokens) {
		return false
	}
	cmd := baseName(tokens[i])
	args := tokens[i+1:]
	// unwrap transparent prefixes (sudo/env/...); skip the env's VAR=val.
	for isWrapper(cmd) {
		for len(args) > 0 && assignmentRE.MatchString(args[0]) {
			args = args[1:]
		}
		if len(args) == 0 {
			break
		}
		cmd = baseName(args[0])
		args = args[1:]
	}

	switch cmd {
	case "rm":
		return dangerousRm(args)
	case "find":
		return dangerousFind(args)
	case "chmod", "chown", "chgrp":
		return recursiveDangerous(args)
	}
	return false
}

func isWrapper(cmd string) bool {
	switch cmd {
	case "sudo", "doas", "env", "nice", "time", "command", "nohup", "stdbuf":
		return true
	}
	return false
}

func baseName(s string) string {
	if idx := strings.LastIndexByte(s, '/'); idx >= 0 {
		return s[idx+1:]
	}
	return s
}

// dangerousRm blocks recursive removal of dangerous targets, resilient to flag
// variation (short/long/separate), `--`, and quoting (already stripped during tokenization).
func dangerousRm(args []string) bool {
	recursive, noPreserve, endFlags := false, false, false
	var targets []string
	for _, a := range args {
		switch {
		case !endFlags && a == "--":
			endFlags = true
		case !endFlags && strings.HasPrefix(a, "--"):
			switch a {
			case "--recursive", "--recursive=true":
				recursive = true
			case "--no-preserve-root":
				noPreserve = true
			}
		case !endFlags && strings.HasPrefix(a, "-") && len(a) > 1:
			for _, r := range a[1:] {
				if r == 'r' || r == 'R' {
					recursive = true
				}
			}
		default:
			targets = append(targets, a)
		}
	}
	if noPreserve {
		return true
	}
	if !recursive {
		return false
	}
	for _, t := range targets {
		if dangerousTarget(t) {
			return true
		}
	}
	return false
}

// dangerousFind blocks find with a destructive -delete/-exec over a catastrophic target
// (it does not block find . -name ... -delete, which is common and legitimate).
func dangerousFind(args []string) bool {
	hasDelete, hasExec, rootSet := false, false, false
	var root string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-delete":
			hasDelete = true
		case a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir":
			if i+1 < len(args) && isDestructive(baseName(args[i+1])) {
				hasExec = true
			}
		case !rootSet && !strings.HasPrefix(a, "-"):
			root = a
			rootSet = true
		}
	}
	if !hasDelete && !hasExec {
		return false
	}
	return catastrophicTarget(root)
}

func isDestructive(cmd string) bool {
	switch cmd {
	case "rm", "unlink", "shred", "mkfs", "dd":
		return true
	}
	return false
}

// recursiveDangerous blocks recursive chmod/chown/chgrp on a dangerous target.
func recursiveDangerous(args []string) bool {
	recursive, endFlags := false, false
	var targets []string
	for _, a := range args {
		switch {
		case !endFlags && a == "--":
			endFlags = true
		case !endFlags && (a == "--recursive" || a == "-R"):
			recursive = true
		case !endFlags && strings.HasPrefix(a, "-") && len(a) > 1:
			for _, r := range a[1:] {
				if r == 'R' {
					recursive = true
				}
			}
		default:
			targets = append(targets, a) // includes mode/owner; harmless for the check
		}
	}
	if !recursive {
		return false
	}
	for _, t := range targets {
		if dangerousTarget(t) {
			return true
		}
	}
	return false
}

// dangerousTarget: targets whose recursive removal is destructive (includes . and * — cwd/glob).
func dangerousTarget(t string) bool {
	if t == "" {
		return false
	}
	switch t {
	case "/", "~", ".", "..", "*", "./*", "../*", "/*", "~/*", "$HOME", "${HOME}", "$HOME/*", "${HOME}/*":
		return true
	}
	if strings.HasPrefix(t, "~/") || strings.HasPrefix(t, "$HOME/") || strings.HasPrefix(t, "${HOME}/") {
		return true
	}
	return absoluteCritical(t)
}

// catastrophicTarget: like dangerousTarget, but without . and * (so as not to block
// find . -name ... -delete). Used by find.
func catastrophicTarget(t string) bool {
	switch t {
	case "/", "~", "$HOME", "${HOME}":
		return true
	}
	if strings.HasPrefix(t, "~/") || strings.HasPrefix(t, "$HOME/") || strings.HasPrefix(t, "${HOME}/") {
		return true
	}
	return absoluteCritical(t)
}

// absoluteCritical: absolute path to a critical system or top-level directory.
func absoluteCritical(t string) bool {
	if !strings.HasPrefix(t, "/") {
		return false
	}
	rest := strings.Trim(t, "/")
	if rest == "" {
		return true // "/"
	}
	first := "/" + rest
	if idx := strings.IndexByte(rest, '/'); idx >= 0 {
		first = "/" + rest[:idx]
	}
	if criticalRoots[first] {
		return true
	}
	// recursive removal of a single top-level directory (e.g.: /foo, /tmp)
	return !strings.Contains(rest, "/")
}

// cmdGuard reads a single, size-limited JSON payload. An invalid/unknown schema blocks:
// protocol changes must not silently disable the control.
func cmdGuard() int {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxGuardPayload+1))
	if err != nil || len(raw) > maxGuardPayload {
		fmt.Fprintln(os.Stderr, "kiro-secops guard: invalid payload or above the limit — BLOCKED.")
		return exitUsage
	}
	command, path, valid := extractPayload(raw)
	if !valid {
		fmt.Fprintln(os.Stderr, "kiro-secops guard: unknown tool_input schema — BLOCKED.")
		return exitUsage
	}
	if guardEval(command, path) == exitUsage {
		if command == "" && path != "" {
			fmt.Fprintln(os.Stderr, "kiro-secops guard: write BLOCKED to a sensitive/secret file. Use a secret manager.")
		} else {
			fmt.Fprintln(os.Stderr, "kiro-secops guard: command BLOCKED by security policy. Rewrite it or request human review.")
		}
		return exitUsage
	}
	return exitOK
}

func extractPayload(raw []byte) (command, path string, valid bool) {
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", "", false
	}
	var input map[string]any
	for _, key := range []string{"tool_input", "toolInput", "input"} {
		if candidate, ok := envelope[key].(map[string]any); ok {
			input = candidate
			break
		}
	}
	if input == nil {
		return "", "", false
	}
	command = firstString(input, "command", "cmd")
	path = firstString(input, "path", "file_path", "targetFile", "target_file")
	if command == "" && path == "" {
		return "", "", false
	}
	return command, path, true
}
