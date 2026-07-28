package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type hooksParse struct {
	Version string
	Hooks   []struct {
		Name    string
		Trigger string
		Action  struct {
			Type    string
			Command string
			Prompt  string
		}
	}
}

func setTestGuard(t *testing.T) string {
	t.Helper()
	absolute, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(guardBinaryEnv, absolute)
	validated, err := validateGuardBinary(absolute)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func TestInitScaffold(t *testing.T) {
	guardBinary := setTestGuard(t)
	project := t.TempDir()
	if rc := cmdInit(&opts{project: project}); rc != exitOK {
		t.Fatalf("init rc=%d", rc)
	}

	hookPath := filepath.Join(project, ".kiro", "hooks", "kiro-secops.json")
	data, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("hooks not copied: %v", err)
	}
	var hooks hooksParse
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("invalid hooks JSON: %v", err)
	}
	if hooks.Version != "v1" || len(hooks.Hooks) == 0 {
		t.Fatalf("unexpected hooks structure: %+v", hooks)
	}
	guardOK, reviewOK, scanOK := false, false, false
	wantGuard := quoteHookExecutable(guardBinary) + " guard"
	wantScan := quoteHookExecutable(guardBinary) + " scan --advisory"
	for _, hook := range hooks.Hooks {
		if hook.Trigger == "PreToolUse" && hook.Action.Command == wantGuard {
			guardOK = true
		}
		if hook.Trigger == "Stop" && hook.Action.Type == "agent" && hook.Action.Prompt != "" {
			reviewOK = true
		}
		if hook.Trigger == "PostTaskExec" && hook.Action.Command == wantScan {
			scanOK = true
		}
	}
	if !guardOK {
		t.Fatalf("PreToolUse hook does not use absolute path %q", wantGuard)
	}
	if !reviewOK {
		t.Fatal("review hook on Stop missing")
	}
	if !scanOK {
		t.Fatalf("PostTaskExec scan hook not materialized for %q", wantScan)
	}

	for _, relative := range []string{
		".pre-commit-config.yaml", ".gitleaks.toml", "trivy.yaml", ".checkov.yaml",
		filepath.Join(".github", "workflows", "security-scan.yml"),
		filepath.FromSlash(workspaceManifestPath),
	} {
		if _, err := os.Stat(filepath.Join(project, relative)); err != nil {
			t.Fatalf("artifact not created: %s (%v)", relative, err)
		}
	}
}

func TestInitDryRun(t *testing.T) {
	setTestGuard(t)
	project := t.TempDir()
	if rc := cmdInit(&opts{project: project, dryRun: true}); rc != exitOK {
		t.Fatalf("init dry-run rc=%d", rc)
	}
	if entries, _ := os.ReadDir(project); len(entries) != 0 {
		t.Fatalf("dry-run should not write: %v", entries)
	}
}

func TestInitRequiresValidGuard(t *testing.T) {
	project := t.TempDir()
	t.Setenv(guardBinaryEnv, filepath.Join(project, "missing"))
	if rc := cmdInit(&opts{project: project}); rc == exitOK {
		t.Fatal("init should fail without a valid guard runtime")
	}
	if entries, _ := os.ReadDir(project); len(entries) != 0 {
		t.Fatalf("precondition failure should not write: %v", entries)
	}
}

func TestInitNonexistentProject(t *testing.T) {
	setTestGuard(t)
	if rc := cmdInit(&opts{project: filepath.Join(t.TempDir(), "does-not-exist")}); rc == exitOK {
		t.Fatal("init should fail for a nonexistent project")
	}
}

func TestUninstallProjectRestoresState(t *testing.T) {
	setTestGuard(t)
	project := t.TempDir()

	// Pre-existing user config must be restored byte for byte.
	preexisting := filepath.Join(project, ".pre-commit-config.yaml")
	original := "repos: []  # from the user\n"
	writeFile(t, preexisting, original)

	if rc := cmdInit(&opts{project: project, force: true}); rc != exitOK {
		t.Fatalf("init rc=%d", rc)
	}

	// Unmanaged file is preserved.
	custom := filepath.Join(project, "my-config.yaml")
	writeFile(t, custom, "keep: me\n")

	if rc := cmdUninstall(&opts{project: project, force: true}); rc != exitOK {
		t.Fatalf("uninstall --project rc=%d", rc)
	}

	// Originally absent artifacts were removed.
	for _, relative := range []string{
		filepath.Join(".kiro", "hooks", "kiro-secops.json"),
		".gitleaks.toml", "trivy.yaml", ".checkov.yaml",
		filepath.Join(".github", "workflows", "security-scan.yml"),
		filepath.FromSlash(workspaceManifestPath),
	} {
		if _, err := os.Stat(filepath.Join(project, relative)); !os.IsNotExist(err) {
			t.Fatalf("should have been removed: %s", relative)
		}
	}
	// Pre-existing config was restored to its original content.
	if got := readFile(t, preexisting); got != original {
		t.Fatalf("pre-existing config not restored:\n%s", got)
	}
	// Unmanaged file was preserved.
	if _, err := os.Stat(custom); err != nil {
		t.Fatalf("unmanaged file should be preserved: %v", err)
	}
}

func TestUninstallProjectDryRun(t *testing.T) {
	setTestGuard(t)
	project := t.TempDir()
	if rc := cmdInit(&opts{project: project}); rc != exitOK {
		t.Fatalf("init rc=%d", rc)
	}
	hook := filepath.Join(project, ".kiro", "hooks", "kiro-secops.json")
	if rc := cmdUninstall(&opts{project: project, dryRun: true}); rc != exitOK {
		t.Fatalf("uninstall --project dry-run rc=%d", rc)
	}
	if _, err := os.Stat(hook); err != nil {
		t.Fatalf("dry-run should not remove the hook: %v", err)
	}
}

func TestUninstallProjectWithoutManifest(t *testing.T) {
	project := t.TempDir()
	if rc := cmdUninstall(&opts{project: project}); rc == exitOK {
		t.Fatal("uninstall --project should fail without an ownership manifest")
	}
}

func TestUninstallProjectNonexistent(t *testing.T) {
	if rc := cmdUninstall(&opts{project: filepath.Join(t.TempDir(), "does-not-exist")}); rc == exitOK {
		t.Fatal("uninstall --project should fail for a nonexistent project")
	}
}
