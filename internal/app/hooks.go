package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const guardBinaryEnv = "KIRO_SECOPS_BIN"

func resolveGuardBinary() (string, error) {
	if configured := os.Getenv(guardBinaryEnv); configured != "" {
		return validateGuardBinary(configured)
	}

	if home, err := kiroHome(); err == nil {
		candidate := filepath.Join(home, "bin", binName())
		if _, err := os.Lstat(candidate); err == nil {
			return validateGuardBinary(candidate)
		}
	}

	if self, err := os.Executable(); err == nil && executableNameMatches(filepath.Base(self)) {
		if validated, validateErr := validateGuardBinary(self); validateErr == nil {
			return validated, nil
		}
	}

	if candidate, err := exec.LookPath("kiro-secops"); err == nil {
		return validateGuardBinary(candidate)
	}
	return "", errors.New("kiro-secops binary not found; run 'kiro-secops install' before init or set KIRO_SECOPS_BIN with an absolute path")
}

func executableNameMatches(name string) bool {
	return name == "kiro-secops" || name == "kiro-secops.exe"
}

func validateGuardBinary(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must be absolute: %q", guardBinaryEnv, path)
	}
	canonical, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve guard binary %s: %w", path, err)
	}
	fi, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("inspect guard binary %s: %w", canonical, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("guard binary is not a regular file: %s", canonical)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("guard binary is not executable: %s", canonical)
	}
	return canonical, nil
}

const binToken = "kiro-secops"

// materializeHook rewrites every command action that invokes the kiro-secops binary
// to use the validated absolute path, making the hooks fail-closed and portable.
func materializeHook(rel string, data []byte, binary string) ([]byte, error) {
	if filepath.Ext(rel) != ".json" {
		return data, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if doc["version"] != "v1" {
		return nil, fmt.Errorf("unsupported hook version: %v", doc["version"])
	}
	hooks, ok := doc["hooks"].([]any)
	if !ok || len(hooks) == 0 {
		return nil, errors.New("hooks document contains no hooks")
	}
	replaced := 0
	for _, rawHook := range hooks {
		hook, ok := rawHook.(map[string]any)
		if !ok {
			return nil, errors.New("invalid hook entry")
		}
		action, ok := hook["action"].(map[string]any)
		if !ok || action["type"] != "command" {
			continue
		}
		cmd, _ := action["command"].(string)
		if rewritten, changed := rewriteBinaryCommand(cmd, binary); changed {
			action["command"] = rewritten
			replaced++
		}
	}
	if replaced == 0 {
		return nil, errors.New("no action invoking 'kiro-secops' found")
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// rewriteBinaryCommand swaps the leading "kiro-secops" token for the quoted
// absolute path, preserving the arguments (e.g., "guard", "scan --advisory").
func rewriteBinaryCommand(cmd, binary string) (string, bool) {
	quoted := quoteHookExecutable(binary)
	switch {
	case cmd == binToken:
		return quoted, true
	case strings.HasPrefix(cmd, binToken+" "):
		return quoted + cmd[len(binToken):], true
	default:
		return cmd, false
	}
}

func quoteHookExecutable(path string) string {
	if runtime.GOOS == "windows" {
		return `"` + strings.ReplaceAll(path, `"`, `\"`) + `"`
	}
	return "'" + strings.ReplaceAll(path, "'", "'\"'\"'") + "'"
}

// hookCommandExecutable extracts the executable token from a hook command,
// undoing the quoting applied by quoteHookExecutable (single quotes on POSIX,
// double quotes on Windows). A path with embedded quotes is pathological for
// a managed hook; a simple scan to the closing quote is enough here.
func hookCommandExecutable(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	switch cmd[0] {
	case '\'':
		if end := strings.IndexByte(cmd[1:], '\''); end >= 0 {
			return cmd[1 : 1+end]
		}
		return ""
	case '"':
		var b strings.Builder
		for i := 1; i < len(cmd); i++ {
			c := cmd[i]
			if c == '\\' && i+1 < len(cmd) && cmd[i+1] == '"' {
				b.WriteByte('"')
				i++
				continue
			}
			if c == '"' {
				return b.String()
			}
			b.WriteByte(c)
		}
		return ""
	default:
		if i := strings.IndexByte(cmd, ' '); i >= 0 {
			return cmd[:i]
		}
		return cmd
	}
}

// isKiroSecopsExecutable reports whether the executable refers to the
// kiro-secops binary, tolerating both path separators (hooks may have been
// materialized on another OS).
func isKiroSecopsExecutable(exe string) bool {
	name := exe
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	return executableNameMatches(name)
}

// resolveHookExecutable validates the executable pinned in a hook command:
// absolute paths are validated directly; a bare name falls back to PATH
// (covers hooks that were not materialized by init).
func resolveHookExecutable(exe string) (string, error) {
	if filepath.IsAbs(exe) {
		return validateGuardBinary(exe)
	}
	resolved, err := exec.LookPath(exe)
	if err != nil {
		return "", fmt.Errorf("hook executable not found on PATH: %q", exe)
	}
	return validateGuardBinary(resolved)
}

// workspaceHooksDir is where init materializes the workspace hooks.
const workspaceHooksDir = ".kiro/hooks"

// verifyWorkspaceHooks scans .kiro/hooks/*.json and validates the executable
// pinned by each command action (absolute paths, plus bare kiro-secops via
// PATH). This catches the fail-open after cloning: a hook pinned to another
// machine's absolute path exits 127, which Kiro treats as a silent
// (non-blocking) failure — the guard would be OFF without anyone noticing.
// Remediation: 'kiro-secops install' + 'kiro-secops init'.
func verifyWorkspaceHooks(root *safeRoot) ([]integrityStatus, error) {
	names, err := root.readDirNames(workspaceHooksDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var report []integrityStatus
	for _, name := range names {
		if filepath.Ext(name) != ".json" {
			continue
		}
		rel := workspaceHooksDir + "/" + name
		snap, err := root.snapshot(rel)
		if err != nil || !snap.exists {
			report = append(report, integrityStatus{Path: rel, Status: "ERROR"})
			continue
		}
		report = append(report, hookCommandStatuses(rel, snap.data)...)
	}
	return report, nil
}

// hookCommandStatuses returns one status per command action in a hooks JSON
// document whose executable we can meaningfully validate:
//   - absolute paths (what init materializes) — the post-clone fail-open case;
//   - bare "kiro-secops" invocations — must resolve on PATH.
//
// Other relative commands (user hooks such as "npm run lint") are skipped:
// their resolution is the user's concern and PATH lookup happens at runtime.
func hookCommandStatuses(rel string, data []byte) []integrityStatus {
	var doc struct {
		Hooks []struct {
			Name   string `json:"name"`
			Action struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"action"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return []integrityStatus{{Path: rel, Status: "ERROR"}}
	}
	var report []integrityStatus
	for _, hook := range doc.Hooks {
		if hook.Action.Type != "command" {
			continue
		}
		exe := hookCommandExecutable(hook.Action.Command)
		if exe == "" {
			continue
		}
		if !filepath.IsAbs(exe) && !isKiroSecopsExecutable(exe) {
			continue
		}
		status := integrityStatus{Path: rel + " :: " + hook.Name, Status: "OK"}
		if _, err := resolveHookExecutable(exe); err != nil {
			status.Status = "BROKEN"
		}
		report = append(report, status)
	}
	return report
}
