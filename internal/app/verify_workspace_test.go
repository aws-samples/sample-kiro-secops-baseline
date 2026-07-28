package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookCommandExecutable(t *testing.T) {
	cases := []struct{ cmd, want string }{
		{"'/home/dev/.kiro/bin/kiro-secops' guard", "/home/dev/.kiro/bin/kiro-secops"},
		{"'/home/dev/.kiro/bin/kiro-secops' scan --advisory", "/home/dev/.kiro/bin/kiro-secops"},
		{`"C:\Users\dev\.kiro\bin\kiro-secops.exe" guard`, `C:\Users\dev\.kiro\bin\kiro-secops.exe`},
		{`"C:\path with \"quote\"\kiro-secops.exe" guard`, `C:\path with "quote"\kiro-secops.exe`},
		{"kiro-secops guard", "kiro-secops"},
		{"kiro-secops", "kiro-secops"},
		{"npm run lint", "npm"},
		{"  'x y/z' a", "x y/z"},
		{"", ""},
		{"'unterminated", ""},
	}
	for _, c := range cases {
		if got := hookCommandExecutable(c.cmd); got != c.want {
			t.Errorf("hookCommandExecutable(%q) = %q; expected %q", c.cmd, got, c.want)
		}
	}
}

func TestIsKiroSecopsExecutable(t *testing.T) {
	for exe, want := range map[string]bool{
		"kiro-secops":                            true,
		"kiro-secops.exe":                        true,
		"/home/dev/.kiro/bin/kiro-secops":        true,
		`C:\Users\dev\.kiro\bin\kiro-secops.exe`: true,
		"npm":                                    false,
		"/usr/bin/python3":                       false,
	} {
		if got := isKiroSecopsExecutable(exe); got != want {
			t.Errorf("isKiroSecopsExecutable(%q) = %v; expected %v", exe, got, want)
		}
	}
}

// After a clean init, verify --project must pass (hooks pin THIS machine's
// test binary via KIRO_SECOPS_BIN).
func TestVerifyProjectAfterInit(t *testing.T) {
	t.Setenv("KIRO_HOME", t.TempDir())
	setTestGuard(t)
	project := t.TempDir()
	if rc := captureRC(t, func() int { return cmdInit(&opts{project: project}) }); rc != exitOK {
		t.Fatalf("init rc=%d", rc)
	}
	if rc := captureRC(t, func() int { return cmdVerify(false, project) }); rc != exitOK {
		t.Fatalf("verify --project after init rc=%d; expected 0", rc)
	}
}

// The post-clone fail-open: hooks pinned to another machine's absolute path
// must FAIL verify --project (those hooks exit 127 silently in Kiro).
func TestVerifyProjectDetectsForeignBinaryPath(t *testing.T) {
	t.Setenv("KIRO_HOME", t.TempDir())
	setTestGuard(t)
	project := t.TempDir()
	if rc := captureRC(t, func() int { return cmdInit(&opts{project: project}) }); rc != exitOK {
		t.Fatalf("init rc=%d", rc)
	}

	// Simulate the clone from another machine: rewrite the pinned path.
	// materializeHook writes the path inside a JSON string, so match its
	// JSON-escaped form (required on Windows, where the path has backslashes).
	hookPath := filepath.Join(project, ".kiro", "hooks", "kiro-secops.json")
	data := readFile(t, hookPath)
	foreign := jsonStringInner(t, quoteHookExecutable(filepath.Join(t.TempDir(), "elsewhere", "kiro-secops")))
	current := jsonStringInner(t, quoteHookExecutable(mustTestGuardPath(t)))
	rewritten := strings.ReplaceAll(data, current, foreign)
	if rewritten == data {
		t.Fatal("test setup: pinned path not found in hooks JSON")
	}
	writeFile(t, hookPath, rewritten)

	if rc := captureRC(t, func() int { return cmdVerify(false, project) }); rc != exitError {
		t.Fatalf("verify --project with foreign binary path rc=%d; expected %d", rc, exitError)
	}
}

func mustTestGuardPath(t *testing.T) string {
	t.Helper()
	validated, err := validateGuardBinary(os.Getenv(guardBinaryEnv))
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

// jsonStringInner returns s as it appears inside a JSON string value (with
// backslashes and quotes escaped), matching how materializeHook serializes the
// pinned path via encoding/json. On Windows the path contains backslashes, so
// the raw quoted form never appears verbatim in the hooks file.
func jsonStringInner(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b[1 : len(b)-1]) // strip the surrounding quotes json.Marshal adds
}

// MODIFIED managed artifacts are tolerated without --strict (customization),
// but fail with --strict; MISSING always fails.
func TestVerifyProjectStrictSemantics(t *testing.T) {
	t.Setenv("KIRO_HOME", t.TempDir())
	setTestGuard(t)
	project := t.TempDir()
	if rc := captureRC(t, func() int { return cmdInit(&opts{project: project}) }); rc != exitOK {
		t.Fatalf("init rc=%d", rc)
	}

	// Customize a committed artifact (legitimate team workflow).
	writeFile(t, filepath.Join(project, "trivy.yaml"), "severity: CRITICAL\n")
	if rc := captureRC(t, func() int { return cmdVerify(false, project) }); rc != exitOK {
		t.Fatalf("verify --project with customized artifact rc=%d; expected 0 (tolerated)", rc)
	}
	if rc := captureRC(t, func() int { return cmdVerify(true, project) }); rc != exitError {
		t.Fatalf("verify --project --strict with customized artifact rc=%d; expected %d", rc, exitError)
	}

	// Remove a managed artifact: fails regardless of --strict.
	if err := os.Remove(filepath.Join(project, ".gitleaks.toml")); err != nil {
		t.Fatal(err)
	}
	if rc := captureRC(t, func() int { return cmdVerify(false, project) }); rc != exitError {
		t.Fatalf("verify --project with missing artifact rc=%d; expected %d", rc, exitError)
	}
}

// A project without init (no hooks, no manifest) fails with guidance.
func TestVerifyProjectNotInitialized(t *testing.T) {
	t.Setenv("KIRO_HOME", t.TempDir())
	if rc := captureRC(t, func() int { return cmdVerify(false, t.TempDir()) }); rc != exitError {
		t.Fatalf("verify --project on empty dir rc=%d; expected %d", rc, exitError)
	}
}

// Hooks committed without the manifest (team gitignores .kiro/kiro-secops/):
// hook health remains the gate; the hash check is skipped informationally.
func TestVerifyProjectHooksWithoutManifest(t *testing.T) {
	t.Setenv("KIRO_HOME", t.TempDir())
	setTestGuard(t)
	project := t.TempDir()
	if rc := captureRC(t, func() int { return cmdInit(&opts{project: project}) }); rc != exitOK {
		t.Fatalf("init rc=%d", rc)
	}
	if err := os.RemoveAll(filepath.Join(project, ".kiro", "kiro-secops")); err != nil {
		t.Fatal(err)
	}
	if rc := captureRC(t, func() int { return cmdVerify(false, project) }); rc != exitOK {
		t.Fatalf("verify --project without manifest (healthy hooks) rc=%d; expected 0", rc)
	}
}
