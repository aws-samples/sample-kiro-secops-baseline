package app

import (
	"fmt"
	"os"
	"path/filepath"
)

// workspaceHooksSrc is the hooks tree (data) in the payload — the single source for init.
const workspaceHooksSrc = "payload/workspace/kiro/hooks"

// workspaceConfigs maps payload config files -> destination relative to the project.
var workspaceConfigs = []struct{ src, dst string }{
	{"payload/workspace/pre-commit-config.yaml", ".pre-commit-config.yaml"},
	{"payload/workspace/gitleaks.toml", ".gitleaks.toml"},
	{"payload/workspace/trivy.yaml", "trivy.yaml"},
	{"payload/workspace/checkov.yaml", ".checkov.yaml"},
	{"payload/workspace/github/workflows/security-scan.yml", ".github/workflows/security-scan.yml"},
}

// cmdInit applies the workspace layer in a transaction and records ownership in the manifest.
func cmdInit(o *opts) int {
	project := o.project
	if project == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		project = wd
	}
	abs, err := filepath.Abs(project)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	guardBinary, err := resolveGuardBinary()
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

	tx, err := beginManagedTransaction(root, "workspace", workspaceManifestPath, workspaceBackupBase, o)
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

	fmt.Printf("kiro-secops init -> %s%s\n", abs, dryTag(o))
	transform := func(rel string, data []byte) ([]byte, error) {
		return materializeHook(rel, data, guardBinary)
	}
	if err := extractTreeWithTransform(workspaceHooksSrc, filepath.Join(".kiro", "hooks"), tx, transform); err != nil {
		return fail("installing hooks", err)
	}
	for _, config := range workspaceConfigs {
		if err := copyEmbedFile(config.src, filepath.FromSlash(config.dst), tx); err != nil {
			return fail("installing "+config.src, err)
		}
	}
	if err := tx.Commit(); err != nil {
		fmt.Fprintln(os.Stderr, "error completing init:", err)
		return exitError
	}

	fmt.Println("\nOK. Workspace configured transactionally. Commit the shareable artifacts.")
	fmt.Printf("Guard hook pinned to the executable: %s\n", guardBinary)
	fmt.Printf("Local ownership manifest: %s\n", filepath.Join(abs, filepath.FromSlash(workspaceManifestPath)))
	fmt.Println("NOTE: hooks pin THIS machine's binary path. After cloning, each teammate must run")
	fmt.Println("'kiro-secops install' + 'kiro-secops init' (check with 'kiro-secops verify --project .').")
	return exitOK
}
