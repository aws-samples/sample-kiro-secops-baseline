package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallUninstallRoundtrip(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("install refuses to run as root")
	}
	home := t.TempDir()
	t.Setenv("KIRO_HOME", home)

	if rc := cmdInstall(&opts{}); rc != exitOK {
		t.Fatalf("install rc=%d", rc)
	}
	mustExist := []string{
		filepath.Join(home, "settings", "permissions.yaml"),
		filepath.Join(home, "settings", "kiroignore"),
		filepath.Join(home, "agents", "kiro-secops-reviewer.md"),
		filepath.Join(home, "skills", "kiro-secops-review", "SKILL.md"),
		filepath.Join(home, "steering", "security-policies.md"),
		filepath.Join(home, filepath.FromSlash(globalManifestPath)),
	}
	for _, path := range mustExist {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("artifact not installed: %s (%v)", path, err)
		}
	}
	if !strings.Contains(readFile(t, filepath.Join(home, "settings", "permissions.yaml")), "kiro-secops-managed") {
		t.Fatal("permissions.yaml without structural ownership")
	}
	if rc := cmdInstall(&opts{}); rc != exitOK {
		t.Fatalf("reinstall rc=%d", rc)
	}
	if rc := cmdUninstall(&opts{}); rc != exitOK {
		t.Fatalf("uninstall rc=%d", rc)
	}
	for _, path := range mustExist {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("originally absent artifact should be removed: %s", path)
		}
	}
}

func TestInstallRestoresPreexistingFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("install refuses to run as root")
	}
	home := t.TempDir()
	t.Setenv("KIRO_HOME", home)
	settings := filepath.Join(home, "settings")
	if err := os.MkdirAll(settings, 0o755); err != nil {
		t.Fatal(err)
	}
	permissions := filepath.Join(settings, "permissions.yaml")
	original := "owner: user\nrules:\n  - capability: shell\n    effect: allow\n"
	writeFile(t, permissions, original)
	if err := os.Chmod(permissions, 0o600); err != nil {
		t.Fatal(err)
	}

	if rc := cmdInstall(&opts{}); rc != exitOK {
		t.Fatalf("install rc=%d", rc)
	}
	if rc := cmdUninstall(&opts{}); rc != exitOK {
		t.Fatalf("uninstall rc=%d", rc)
	}
	if got := readFile(t, permissions); got != original {
		t.Fatalf("original file not restored:\n%s", got)
	}
	info, err := os.Stat(permissions)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("original mode not restored: %o", info.Mode().Perm())
	}
}

func TestInstallProfileStrict(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("install refuses to run as root")
	}
	home := t.TempDir()
	t.Setenv("KIRO_HOME", home)
	if rc := captureRC(t, func() int { return cmdInstall(&opts{profile: "strict"}) }); rc != exitOK {
		t.Fatalf("install --profile strict rc=%d", rc)
	}
	permissions := readFile(t, filepath.Join(home, "settings", "permissions.yaml"))
	if !strings.Contains(permissions, "profile=strict") {
		t.Fatalf("permissions does not mark profile=strict:\n%s", permissions)
	}
	// strict denies network (web_fetch: deny) — the baseline used ask.
	if !strings.Contains(permissions, "web_fetch") {
		t.Fatalf("strict profile without web_fetch rule:\n%s", permissions)
	}
	// verify --strict remains intact after installing the profile.
	if rc := captureRC(t, func() int { return cmdVerify(true, "") }); rc != exitOK {
		t.Fatalf("verify --strict after strict install rc=%d", rc)
	}
}

func TestParseInstallProfileInvalid(t *testing.T) {
	if _, err := parseInstall([]string{"--profile", "nonexistent"}); err != nil {
		// parseInstall does not validate the name (validation lives in resolveProfile); ok if it accepts.
		_ = err
	}
	if _, _, err := resolveProfile("nonexistent"); err == nil {
		t.Fatal("resolveProfile should reject an unknown profile")
	}
	name, source, err := resolveProfile("")
	if err != nil || name != defaultProfile || source == "" {
		t.Fatalf("unexpected default profile: name=%q source=%q err=%v", name, source, err)
	}
}

func TestInstallDryRun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("install refuses to run as root")
	}
	home := t.TempDir()
	t.Setenv("KIRO_HOME", home)
	if rc := cmdInstall(&opts{dryRun: true}); rc != exitOK {
		t.Fatalf("dry-run rc=%d", rc)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("dry-run should not write anything: %v", entries)
	}
}

func TestPathHasDir(t *testing.T) {
	separator := string(os.PathListSeparator)
	pathEnv := "/usr/bin" + separator + "/home/u/.kiro/bin" + separator + "/bin"
	if !pathHasDir(pathEnv, "/home/u/.kiro/bin") || pathHasDir(pathEnv, "/missing") || pathHasDir("", "/x") {
		t.Fatal("incorrect PATH detection")
	}
}

func TestPathHint(t *testing.T) {
	cases := []struct{ goos, shell, want string }{
		{"windows", "", "setx"},
		{"darwin", "/bin/zsh", ".zshrc"},
		{"linux", "/usr/bin/bash", ".bashrc"},
		{"linux", "/usr/bin/fish", "fish_add_path"},
		{"linux", "", "export PATH"},
	}
	for _, test := range cases {
		if got := pathHint(test.goos, test.shell, "/h/.kiro/bin"); !strings.Contains(got, test.want) {
			t.Fatalf("pathHint(%q,%q) = %q; should contain %q", test.goos, test.shell, got, test.want)
		}
	}
}
