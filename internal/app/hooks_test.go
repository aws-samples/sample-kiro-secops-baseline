package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveGuardBinaryViaEnv(t *testing.T) {
	self, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(guardBinaryEnv, self)
	got, err := resolveGuardBinary()
	if err != nil {
		t.Fatalf("resolveGuardBinary: %v", err)
	}
	canonical, _ := filepath.EvalSymlinks(self)
	if got != canonical {
		t.Fatalf("expected %q, got %q", canonical, got)
	}
}

func TestResolveGuardBinaryRejectsInvalid(t *testing.T) {
	t.Setenv(guardBinaryEnv, "relative/kiro-secops")
	if _, err := resolveGuardBinary(); err == nil {
		t.Fatal("relative path should be rejected")
	}

	t.Setenv(guardBinaryEnv, filepath.Join(t.TempDir(), "missing"))
	if _, err := resolveGuardBinary(); err == nil {
		t.Fatal("nonexistent path should be rejected")
	}

	dir := t.TempDir()
	t.Setenv(guardBinaryEnv, dir) // directory is not a regular file
	if _, err := resolveGuardBinary(); err == nil {
		t.Fatal("directory should be rejected")
	}
}

func TestResolveGuardBinaryViaKiroHome(t *testing.T) {
	_ = os.Unsetenv(guardBinaryEnv)
	home := t.TempDir()
	t.Setenv("KIRO_HOME", home)
	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(binDir, binName())
	if err := os.WriteFile(target, self, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveGuardBinary()
	if err != nil {
		t.Fatalf("resolveGuardBinary via KIRO_HOME: %v", err)
	}
	canonical, _ := filepath.EvalSymlinks(target)
	if got != canonical {
		t.Fatalf("expected %q, got %q", canonical, got)
	}
}

func TestExecutableNameMatches(t *testing.T) {
	if !executableNameMatches("kiro-secops") || !executableNameMatches("kiro-secops.exe") {
		t.Fatal("canonical names should match")
	}
	if executableNameMatches("something-else") {
		t.Fatal("an odd name should not match")
	}
}

func TestMaterializeHook(t *testing.T) {
	guard := "/opt/kiro/bin/kiro-secops"
	payload := []byte(`{"version":"v1","hooks":[{"trigger":"PreToolUse","action":{"type":"command","command":"kiro-secops guard"}}]}`)
	out, err := materializeHook("kiro-secops.json", payload, guard)
	if err != nil {
		t.Fatal(err)
	}
	// Verify the actual value of the command field after the JSON round-trip, instead of
	// matching raw bytes: quoteHookExecutable uses double quotes on Windows (which JSON
	// escapes as \") and single quotes on Unix, so a substring match on the serialized
	// text would be fragile across operating systems.
	var doc struct {
		Hooks []struct {
			Action struct {
				Command string `json:"command"`
			} `json:"action"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(doc.Hooks) != 1 {
		t.Fatalf("expected 1 materialized hook, got %d\n%s", len(doc.Hooks), out)
	}
	want := quoteHookExecutable(guard) + " guard"
	if got := doc.Hooks[0].Action.Command; got != want {
		t.Fatalf("command not materialized with absolute path:\nexpected %q\ngot      %q", want, got)
	}

	// Non-JSON file passes through unchanged.
	raw := []byte("not json")
	if out, err := materializeHook("notes.txt", raw, guard); err != nil || string(out) != string(raw) {
		t.Fatalf("passthrough failed: out=%q err=%v", out, err)
	}

	// Errors: invalid JSON, wrong version, no guard action.
	if _, err := materializeHook("h.json", []byte("{"), guard); err == nil {
		t.Fatal("invalid JSON should fail")
	}
	if _, err := materializeHook("h.json", []byte(`{"version":"v2","hooks":[]}`), guard); err == nil {
		t.Fatal("unsupported version should fail")
	}
	if _, err := materializeHook("h.json", []byte(`{"version":"v1","hooks":[{"action":{"type":"agent"}}]}`), guard); err == nil {
		t.Fatal("missing guard action should fail")
	}
}

func TestRunEntrypoint(t *testing.T) {
	_ = captureStdout(t, func() {
		if rc := Run([]string{"version"}); rc != exitOK {
			t.Fatalf("Run(version) = %d", rc)
		}
	})
}
