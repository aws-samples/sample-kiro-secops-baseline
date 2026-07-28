package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- stdin/stdout capture helpers (restore even on failure) ---

func withStdin(t *testing.T, payload string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Write in a goroutine: payloads larger than the pipe buffer (~64KB)
	// would block if written synchronously before the reader runs.
	go func() {
		_, _ = w.WriteString(payload)
		_ = w.Close()
	}()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old; _ = r.Close() }()
	fn()
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	out := make(chan string, 1)
	go func() { b, _ := io.ReadAll(r); out <- string(b) }()
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	return <-out
}

// captureRC runs fn discarding stdout and returns the exit code.
func captureRC(t *testing.T, fn func() int) int {
	t.Helper()
	var rc int
	_ = captureStdout(t, func() { rc = fn() })
	return rc
}

func TestRunDispatch(t *testing.T) {
	t.Setenv("KIRO_HOME", t.TempDir())
	t.Setenv(guardBinaryEnv, os.Args[0])
	proj := t.TempDir()
	table := []struct {
		args []string
		want int
	}{
		{[]string{"version"}, 0},
		{[]string{"help"}, 0},
		{nil, 2},
		{[]string{"bogus-command"}, 2},
		{[]string{"init", "--project", proj, "--dry-run"}, 0},
		{[]string{"uninstall", "--help"}, 0},
		{[]string{"init", "--nonexistent-flag"}, 2},
		{[]string{"install", "--nonexistent-flag"}, 2},
		{[]string{"install", "--help"}, 0},
		{[]string{"uninstall", proj, "--dry-run"}, 2},
		{[]string{"verify", "extra"}, 2},
	}
	_ = captureStdout(t, func() {
		for _, c := range table {
			if rc := run(c.args); rc != c.want {
				t.Errorf("run(%v) = %d; expected %d", c.args, rc, c.want)
			}
		}
		if os.Geteuid() != 0 {
			if rc := run([]string{"install", "--dry-run"}); rc != 0 {
				t.Errorf("run(install --dry-run) = %d; expected 0", rc)
			}
		}
	})
	// guard requires stdin
	_ = captureStdout(t, func() {
		withStdin(t, `{"tool_input":{"command":"ls"}}`, func() {
			if rc := run([]string{"guard"}); rc != 0 {
				t.Errorf("run(guard) = %d; expected 0", rc)
			}
		})
	})
}

func TestCmdGuard(t *testing.T) {
	guard := func(payload string) (int, string) {
		var rc int
		out := captureStdout(t, func() {
			withStdin(t, payload, func() { rc = cmdGuard() })
		})
		return rc, out
	}
	if rc, _ := guard(`{"tool_input":{"command":"rm -rf /"}}`); rc != 2 {
		t.Fatalf("block: rc=%d", rc)
	}
	if rc, out := guard(`{"tool_input":{"command":"sudo apt"}}`); rc != 0 || out != "" {
		t.Fatalf("high impact must be delegated to permissions: rc=%d out=%q", rc, out)
	}
	if rc, _ := guard(`{"tool_input":{"unknown":true}}`); rc != exitUsage {
		t.Fatalf("unknown schema should block: rc=%d", rc)
	}
	if rc, _ := guard(`{"tool_input":{"command":"ls -la"}}`); rc != 0 {
		t.Fatalf("allow: rc=%d", rc)
	}
	if rc, _ := guard(`{"tool_input":{"path":"x/.env"}}`); rc != 2 {
		t.Fatalf("write-block: rc=%d", rc)
	}
	// payload above the limit fails closed (exit 2)
	big := `{"tool_input":{"command":"` + strings.Repeat("a", maxGuardPayload+16) + `"}}`
	if rc, _ := guard(big); rc != exitUsage {
		t.Fatalf("large payload should block: rc=%d", rc)
	}
}

func TestCmdVerify(t *testing.T) {
	t.Setenv("KIRO_HOME", t.TempDir())
	// Without --strict: the guard self-test passes even without an installation.
	var rc int
	_ = captureStdout(t, func() { rc = cmdVerify(false, "") })
	if rc != exitOK {
		t.Fatalf("verify rc=%d (guard self-test should pass)", rc)
	}
	// With --strict and no manifest: it must fail.
	_ = captureStdout(t, func() { rc = cmdVerify(true, "") })
	if rc != exitError {
		t.Fatalf("verify --strict without installation rc=%d; expected %d", rc, exitError)
	}
}

func TestCmdVerifyStrictAfterInstall(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("install refuses to run as root")
	}
	home := t.TempDir()
	t.Setenv("KIRO_HOME", home)
	if rc := captureRC(t, func() int { return cmdInstall(&opts{}) }); rc != exitOK {
		t.Fatalf("install rc=%d", rc)
	}
	// Intact installation: strict passes.
	if rc := captureRC(t, func() int { return cmdVerify(true, "") }); rc != exitOK {
		t.Fatalf("verify --strict after clean install rc=%d", rc)
	}
	// Tamper with a managed artifact: strict fails.
	writeFile(t, filepath.Join(home, "agents", "kiro-secops-reviewer.md"), "edited")
	if rc := captureRC(t, func() int { return cmdVerify(true, "") }); rc != exitError {
		t.Fatalf("verify --strict with tampered artifact rc=%d; expected %d", rc, exitError)
	}
}

// fakeRunProcess replaces runProcess with a PURE-Go fake (no subprocess/exec): trivy
// "finds findings" (exit 1) and emits a secret-like marker to validate that the output does NOT
// leak into reports; the other scanners exit 0 (clean).
func fakeRunProcess(_ context.Context, _, name string, _ ...string) ([]byte, int, error) {
	tool := filepath.Base(name)
	out := []byte(fmt.Sprintf("%s (%s)\n", scanLeakMarker, tool))
	if tool == "trivy" {
		return out, 1, nil
	}
	return out, 0, nil
}

func TestCmdScan(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.py"), "x = 1\n")
	writeFile(t, filepath.Join(dir, "s.sh"), "echo hi\n")
	writeFile(t, filepath.Join(dir, "package.json"), "{}\n")

	oldLP, oldRP := lookPath, runProcess
	defer func() { lookPath, runProcess = oldLP, oldRP }()
	lookPath = func(f string) (string, error) { return "/usr/bin/" + f, nil } // all "present"
	runProcess = fakeRunProcess

	var rc int
	_ = captureStdout(t, func() { rc = cmdScan(dir) })
	if rc != exitError {
		t.Fatalf("cmdScan rc=%d; expected %d for findings", rc, exitError)
	}
	_ = captureStdout(t, func() {
		rc = cmdScanWithOptions(scanOpts{dir: dir, advisory: true, timeout: time.Minute, format: "text"})
	})
	if rc != exitOK {
		t.Fatalf("cmdScan advisory rc=%d; expected 0", rc)
	}
}

func TestCmdScanValidatesDirectoryAndRequireTools(t *testing.T) {
	// Nonexistent directory => operational error (exit 1).
	var rc int
	_ = captureStdout(t, func() { rc = cmdScan(filepath.Join(t.TempDir(), "does-not-exist")) })
	if rc != exitError {
		t.Fatalf("scan on a nonexistent directory rc=%d; expected %d", rc, exitError)
	}

	// --require-tools with a missing scanner => operational failure (exit 2).
	dir := t.TempDir()
	oldLP := lookPath
	defer func() { lookPath = oldLP }()
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	_ = captureStdout(t, func() {
		rc = cmdScanWithOptions(scanOpts{dir: dir, requireTools: true, timeout: time.Minute})
	})
	if rc != exitUsage {
		t.Fatalf("scan --require-tools without tools rc=%d; expected %d", rc, exitUsage)
	}
}

func TestParseScanErrors(t *testing.T) {
	if _, err := parseScan([]string{"a", "b"}); err == nil {
		t.Fatal("more than one directory should fail")
	}
	if _, err := parseScan([]string{"--timeout", "0"}); err == nil {
		t.Fatal("zero timeout should fail")
	}
	if _, err := parseScan([]string{"--format", "xml"}); err == nil {
		t.Fatal("invalid --format should fail")
	}
	o, err := parseScan([]string{"--advisory", "dir"})
	if err != nil || !o.advisory || o.dir != "dir" || o.format != "text" {
		t.Fatalf("unexpected parseScan: %+v err=%v", o, err)
	}
}

func TestScanReportJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.py"), "x = 1\n")
	out := filepath.Join(t.TempDir(), "report.json")

	oldLP, oldRP := lookPath, runProcess
	defer func() { lookPath, runProcess = oldLP, oldRP }()
	lookPath = func(f string) (string, error) { return "/usr/bin/" + f, nil }
	runProcess = fakeRunProcess

	rc := captureRC(t, func() int {
		return cmdScanWithOptions(scanOpts{dir: dir, advisory: true, timeout: time.Minute, format: "json", output: out})
	})
	if rc != exitOK {
		t.Fatalf("scan json advisory rc=%d; expected 0", rc)
	}
	var report scanReport
	if err := json.Unmarshal([]byte(readFile(t, out)), &report); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}
	if report.SchemaVersion != scanReportSchemaVersion || report.Tool != "kiro-secops" {
		t.Fatalf("unexpected report header: %+v", report)
	}
	if !report.Findings {
		t.Fatal("report should mark findings (trivy exits 1)")
	}
	foundTrivy := false
	for _, r := range report.Results {
		if r.Tool == "trivy" {
			foundTrivy = true
			if r.Status != statusFindings || r.ExitCode != 1 {
				t.Fatalf("trivy should have findings/exit 1: %+v", r)
			}
		}
	}
	if !foundTrivy {
		t.Fatal("trivy missing from report")
	}
}

func TestScanReportSARIF(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(t.TempDir(), "report.sarif")

	oldLP, oldRP := lookPath, runProcess
	defer func() { lookPath, runProcess = oldLP, oldRP }()
	lookPath = func(f string) (string, error) { return "/usr/bin/" + f, nil }
	runProcess = fakeRunProcess

	rc := captureRC(t, func() int {
		return cmdScanWithOptions(scanOpts{dir: dir, advisory: true, timeout: time.Minute, format: "sarif", output: out})
	})
	if rc != exitOK {
		t.Fatalf("scan sarif advisory rc=%d; expected 0", rc)
	}
	var log sarifLog
	if err := json.Unmarshal([]byte(readFile(t, out)), &log); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if log.Version != "2.1.0" || log.Schema == "" || len(log.Runs) != 1 {
		t.Fatalf("unexpected SARIF structure: %+v", log)
	}
	if log.Runs[0].Tool.Driver.Name != "kiro-secops" {
		t.Fatalf("unexpected SARIF driver: %+v", log.Runs[0].Tool.Driver)
	}
	// trivy exits 1 -> should become an error-level result with a corresponding rule.
	foundResult := false
	for _, res := range log.Runs[0].Results {
		if res.RuleID == "kiro-secops/trivy" && res.Level == "error" {
			foundResult = true
		}
	}
	if !foundResult {
		t.Fatalf("SARIF should contain an error result for trivy: %+v", log.Runs[0].Results)
	}
}

// scanLeakMarker is a secret-like marker emitted by the scanner fake in its output, so the
// tests can validate that the raw output does NOT leak into JSON/SARIF/file reports.
const scanLeakMarker = "KIRO-SECOPS-LEAK-MARKER-abc123"

func TestScanDoesNotLeakOutputInArtifacts(t *testing.T) {
	dir := t.TempDir()
	oldLP, oldRP := lookPath, runProcess
	defer func() { lookPath, runProcess = oldLP, oldRP }()
	lookPath = func(f string) (string, error) { return "/usr/bin/" + f, nil }
	runProcess = fakeRunProcess

	// JSON, SARIF, and text-in-file must NEVER contain the raw scanner output.
	for _, format := range []string{"json", "sarif", "text"} {
		out := filepath.Join(t.TempDir(), "report."+format)
		_ = captureRC(t, func() int {
			return cmdScanWithOptions(scanOpts{dir: dir, advisory: true, timeout: time.Minute, format: format, output: out})
		})
		if strings.Contains(readFile(t, out), scanLeakMarker) {
			t.Fatalf("format %s leaked the scanner output into the persisted file", format)
		}
	}

	// On interactive stdout (text), the output appears for human triage.
	stdout := captureStdout(t, func() {
		_ = cmdScanWithOptions(scanOpts{dir: dir, advisory: true, timeout: time.Minute, format: "text"})
	})
	if !strings.Contains(stdout, scanLeakMarker) {
		t.Fatal("text on stdout should show the scanner output for triage")
	}
}
