package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	globalManifestPath    = "settings/.kiro-secops/manifest.json"
	globalBackupBase      = "settings/.kiro-secops/backups"
	workspaceManifestPath = ".kiro/kiro-secops/manifest.json"
	workspaceBackupBase   = ".kiro/kiro-secops/backups"

	defaultProfile = "baseline"
)

// profileSources maps the profile name -> embedded permissions file.
// baseline is the default floor; strict hardens (less broad allow, more ask/deny).
var profileSources = map[string]string{
	"baseline": "payload/global/settings/permissions.yaml",
	"strict":   "payload/global/settings/profiles/strict.yaml",
}

func profileNames() []string {
	names := make([]string, 0, len(profileSources))
	for name := range profileSources {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func resolveProfile(name string) (string, string, error) {
	if name == "" {
		name = defaultProfile
	}
	source, ok := profileSources[name]
	if !ok {
		return "", "", fmt.Errorf("unknown profile: %q (use %s)", name, strings.Join(profileNames(), "|"))
	}
	return name, source, nil
}

func binName() string { return binNameFor(runtime.GOOS) }

func binNameFor(goos string) string {
	if goos == "windows" {
		return "kiro-secops.exe"
	}
	return "kiro-secops"
}

func dryTag(o *opts) string {
	if o.dryRun {
		return "  [DRY-RUN]"
	}
	return ""
}

// cmdInstall deploys the global configuration in a single managed transaction.
func cmdInstall(o *opts) int {
	if err := mustNotRoot(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	profileName, profileSource, err := resolveProfile(o.profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	home, err := kiroHome()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	root, err := openSafeRoot(home, true, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	defer func() { _ = root.Close() }()

	tx, err := beginManagedTransaction(root, "global", globalManifestPath, globalBackupBase, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	fail := func(context string, cause error) int {
		rollbackErr := tx.Rollback()
		fmt.Fprintf(os.Stderr, "error %s: %v\n", context, cause)
		if rollbackErr != nil {
			fmt.Fprintln(os.Stderr, "additional rollback error:", rollbackErr)
		}
		return exitError
	}

	fmt.Printf("kiro-secops install -> %s (profile: %s)%s\n", home, profileName, dryTag(o))
	trees := []struct{ src, dst string }{
		{"payload/global/steering", "steering"},
		{"payload/global/skills", "skills"},
		{"payload/global/agents", "agents"},
	}
	for _, tree := range trees {
		if err := extractTree(tree.src, tree.dst, tx); err != nil {
			return fail("copying "+tree.src, err)
		}
	}

	permissionsPayload, err := payloadFS.ReadFile(profileSource)
	if err != nil {
		return fail("reading permissions profile", err)
	}
	permissionsPath := "settings/permissions.yaml"
	permissionsExisting, _, _, err := tx.Read(permissionsPath)
	if err != nil {
		return fail("reading existing permissions", err)
	}
	permissionsMerged, err := mergePermissionsData(permissionsExisting, permissionsPayload, profileName)
	if err != nil {
		return fail("merging permissions", err)
	}
	fmt.Printf("  ~ %s (structural YAML merge, profile %s)\n", root.display(permissionsPath), profileName)
	if err := tx.Write(permissionsPath, permissionsMerged, 0o644); err != nil {
		return fail("writing permissions", err)
	}

	ignorePayload, err := payloadFS.ReadFile("payload/global/settings/kiroignore")
	if err != nil {
		return fail("reading kiroignore payload", err)
	}
	ignorePath := "settings/kiroignore"
	ignoreExisting, _, _, err := tx.Read(ignorePath)
	if err != nil {
		return fail("reading existing kiroignore", err)
	}
	ignoreMerged, err := mergeKiroignoreData(ignoreExisting, ignorePayload)
	if err != nil {
		return fail("merging kiroignore", err)
	}
	fmt.Printf("  ~ %s (managed block)\n", root.display(ignorePath))
	if err := tx.Write(ignorePath, ignoreMerged, 0o644); err != nil {
		return fail("writing kiroignore", err)
	}

	if err := copySelf(filepath.Join("bin", binName()), tx); err != nil {
		return fail("copying binary", err)
	}
	if err := tx.Commit(); err != nil {
		fmt.Fprintln(os.Stderr, "error completing installation:", err)
		return exitError
	}

	binDir := filepath.Join(home, "bin")
	fmt.Printf("\nOK. Global config installed transactionally in %s\n", home)
	fmt.Printf("Ownership manifest: %s\n", filepath.Join(home, filepath.FromSlash(globalManifestPath)))
	if !pathHasDir(os.Getenv("PATH"), binDir) {
		fmt.Printf("Optional: add %s to PATH to invoke the CLI directly:\n", binDir)
		fmt.Print(pathHint(runtime.GOOS, os.Getenv("SHELL"), binDir))
	}
	fmt.Println("Workspace hooks use the validated absolute path of the binary.")
	return exitOK
}

// cmdUninstall restores exactly the previous state recorded in the global manifest.
func cmdUninstall(o *opts) int {
	if o.project != "" {
		return cmdUninstallProject(o)
	}
	if err := mustNotRoot(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	home, err := kiroHome()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	root, err := openSafeRoot(home, false, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	defer func() { _ = root.Close() }()

	fmt.Printf("kiro-secops uninstall <- %s%s\n", home, dryTag(o))
	if err := restoreManaged(root, "global", globalManifestPath, globalBackupBase, o); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	fmt.Println("\nOK. Previous global state restored from the manifest.")
	return exitOK
}

// cmdUninstallProject restores exactly the previous state of the workspace.
func cmdUninstallProject(o *opts) int {
	abs, err := filepath.Abs(o.project)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	root, err := openSafeRoot(abs, false, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	defer func() { _ = root.Close() }()

	fmt.Printf("kiro-secops uninstall (workspace) <- %s%s\n", abs, dryTag(o))
	if err := restoreManaged(root, "workspace", workspaceManifestPath, workspaceBackupBase, o); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	fmt.Println("\nOK. Previous workspace state restored from the manifest.")
	return exitOK
}

// pathHasDir reports whether dir is present in the PATH variable (pathEnv).
func pathHasDir(pathEnv, dir string) bool {
	if dir == "" {
		return false
	}
	for _, p := range filepath.SplitList(pathEnv) {
		if p == dir {
			return true
		}
	}
	return false
}

// shellName extracts the shell name from the path in $SHELL (e.g., /bin/zsh -> zsh).
func shellName(shell string) string {
	if shell == "" {
		return ""
	}
	return filepath.Base(shell)
}

// pathHint returns the instruction (OS/shell-dependent) for placing binDir on PATH.
func pathHint(goos, shell, binDir string) string {
	if goos == "windows" {
		return fmt.Sprintf("  PowerShell:  [Environment]::SetEnvironmentVariable(\"Path\", \"%s;\" + [Environment]::GetEnvironmentVariable(\"Path\",\"User\"), \"User\")\n"+
			"  cmd.exe:     setx PATH \"%s;%%PATH%%\"\n"+
			"  (or via Settings > Environment Variables; open a new terminal afterwards)\n", binDir, binDir)
	}
	line := fmt.Sprintf("export PATH=\"%s:$PATH\"", binDir)
	switch shellName(shell) {
	case "zsh":
		return fmt.Sprintf("  echo '%s' >> ~/.zshrc && source ~/.zshrc\n", line)
	case "bash":
		return fmt.Sprintf("  echo '%s' >> ~/.bashrc && source ~/.bashrc\n", line)
	case "fish":
		return fmt.Sprintf("  fish_add_path %s\n", binDir)
	default:
		return fmt.Sprintf("  %s   # add to your shell rc and reopen the terminal\n", line)
	}
}
