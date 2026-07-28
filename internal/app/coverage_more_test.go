package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitUsesCwdWhenNoProject(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv(guardBinaryEnv, os.Args[0])
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()
	if rc := cmdInit(&opts{dryRun: true}); rc != 0 { // without --project it uses the cwd
		t.Fatalf("init (cwd) rc=%d", rc)
	}
}

func TestDetectLangsIgnoresDirectories(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	writeFile(t, filepath.Join(dir, ".git", "ignored.py"), "x")
	_ = os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755)
	writeFile(t, filepath.Join(dir, "app.py"), "x = 1\n")
	writeFile(t, filepath.Join(dir, "s.sh"), "echo\n")
	writeFile(t, filepath.Join(dir, "c.ts"), "const x=1\n")
	m := detectLangs(dir)
	if !m["py"] || !m["sh"] || !m["node"] {
		t.Fatalf("detected languages incomplete: %v", m)
	}
}

func TestEmbedErrors(t *testing.T) {
	tx := newTestTransaction(t, t.TempDir(), &opts{})
	if err := copyEmbedFile("payload/does/not-exist.txt", "x", tx); err == nil {
		t.Fatal("copyEmbedFile should fail for a path that does not exist in the embed")
	}
	if err := extractTree("payload/does-not-exist", "dest", tx); err == nil {
		t.Fatal("extractTree should fail for a nonexistent prefix")
	}
	_ = tx.Rollback()
	if err := walkEmbedFiles("payload/does-not-exist", func(string) {}); err == nil {
		t.Fatal("walkEmbedFiles should fail for a nonexistent prefix")
	}
}
