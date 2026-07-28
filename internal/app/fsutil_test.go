package app

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestTransaction(t *testing.T, base string, options *opts) *managedTransaction {
	t.Helper()
	root, err := openSafeRoot(base, false, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	tx, err := beginManagedTransaction(root, "test", ".meta/manifest.json", ".meta/backups", options)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestExtractTree(t *testing.T) {
	destination := t.TempDir()
	tx := newTestTransaction(t, destination, &opts{})
	if err := extractTree("payload/global/agents", "agents", tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "agents", "kiro-secops-reviewer.md")); err != nil {
		t.Fatalf("agent not extracted: %v", err)
	}
}

func TestExtractTreeDryRun(t *testing.T) {
	destination := t.TempDir()
	tx := newTestTransaction(t, destination, &opts{dryRun: true})
	if err := extractTree("payload/global/steering", "steering", tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(destination); len(entries) != 0 {
		t.Fatalf("dry-run should not write: %v", entries)
	}
}

func TestWalkEmbedFiles(t *testing.T) {
	count := 0
	if err := walkEmbedFiles("payload/global/skills", func(string) { count++ }); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("no embedded file found under skills")
	}
}

func TestCopyEmbedFile(t *testing.T) {
	destination := t.TempDir()
	tx := newTestTransaction(t, destination, &opts{})
	if err := copyEmbedFile("payload/global/settings/permissions.yaml", "perms.yaml", tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(destination, "perms.yaml")); len(data) == 0 {
		t.Fatal("copied file is empty")
	}
}
