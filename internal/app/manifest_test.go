package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func newTx(t *testing.T, base string, options *opts) (*safeRoot, *managedTransaction) {
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
	return root, tx
}

func TestWriteAheadBackupPersistedBeforeCommit(t *testing.T) {
	base := t.TempDir()
	preexisting := filepath.Join(base, "config.yaml")
	writeFile(t, preexisting, "original\n")

	_, tx := newTx(t, base, &opts{force: true})
	if err := tx.Write("config.yaml", []byte("managed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// BEFORE the commit: the file has already been overwritten, but the backup of the original
	// is ALREADY on disk (write-ahead) — recoverable even if a crash prevents the commit.
	if got := readFile(t, preexisting); got != "managed\n" {
		t.Fatalf("file should have been overwritten: %q", got)
	}
	backups, _ := filepath.Glob(filepath.Join(base, ".meta", "backups", "*", "*.bak"))
	if len(backups) != 1 {
		t.Fatalf("write-ahead backup missing before commit: %v", backups)
	}
	if got := readFile(t, backups[0]); got != "original\n" {
		t.Fatalf("backup does not contain the original content: %q", got)
	}
	// Rollback (simulates aborting before the commit) removes the backup and restores the original.
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, preexisting); got != "original\n" {
		t.Fatalf("rollback did not restore the original: %q", got)
	}
	if remaining, _ := filepath.Glob(filepath.Join(base, ".meta", "backups", "*", "*.bak")); len(remaining) != 0 {
		t.Fatalf("backup should have been cleaned up on rollback: %v", remaining)
	}
}

func TestTransactionRollbackRestoresState(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "keep.txt"), "orig")
	if err := os.Chmod(filepath.Join(base, "keep.txt"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, tx := newTx(t, base, &opts{force: true})

	if err := tx.Write("keep.txt", []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Write("sub/new.txt", []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	if got := readFile(t, filepath.Join(base, "keep.txt")); got != "orig" {
		t.Fatalf("original content not restored: %q", got)
	}
	info, err := os.Stat(filepath.Join(base, "keep.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o640 {
		t.Fatalf("original mode not restored: %o", info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(base, "sub", "new.txt")); !os.IsNotExist(err) {
		t.Fatal("new file should have been reverted")
	}
	if _, err := os.Stat(filepath.Join(base, ".meta", "manifest.json")); !os.IsNotExist(err) {
		t.Fatal("manifest should not exist after rollback")
	}
}

func TestCommitAndThenRestoresExactly(t *testing.T) {
	base := t.TempDir()
	preexisting := filepath.Join(base, "config.yaml")
	writeFile(t, preexisting, "user: original\n")
	if err := os.Chmod(preexisting, 0o600); err != nil {
		t.Fatal(err)
	}

	_, tx := newTx(t, base, &opts{force: true})
	if err := tx.Write("config.yaml", []byte("managed: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Write("new.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(base, ".meta", "manifest.json")); err != nil {
		t.Fatalf("manifest not created: %v", err)
	}

	root, err := openSafeRoot(base, false, &opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := restoreManaged(root, "test", ".meta/manifest.json", ".meta/backups", &opts{}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := readFile(t, preexisting); got != "user: original\n" {
		t.Fatalf("pre-existing config not restored: %q", got)
	}
	info, err := os.Stat(preexisting)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("original mode not restored: %o", info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(base, "new.txt")); !os.IsNotExist(err) {
		t.Fatal("originally absent file should be removed")
	}
	if _, err := os.Stat(filepath.Join(base, ".meta", "manifest.json")); !os.IsNotExist(err) {
		t.Fatal("manifest should be removed at the end of the restore")
	}
}

func TestRestoreDetectsTamperedArtifact(t *testing.T) {
	base := t.TempDir()
	_, tx := newTx(t, base, &opts{})
	if err := tx.Write("f.txt", []byte("managed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// User edited the managed artifact after installation.
	writeFile(t, filepath.Join(base, "f.txt"), "edited by hand")

	root, err := openSafeRoot(base, false, &opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := restoreManaged(root, "test", ".meta/manifest.json", ".meta/backups", &opts{}); err == nil {
		t.Fatal("restore should refuse a tampered artifact without --force")
	}
	if err := restoreManaged(root, "test", ".meta/manifest.json", ".meta/backups", &opts{force: true}); err != nil {
		t.Fatalf("restore --force should proceed: %v", err)
	}
}

func TestRestoreDetectsTamperedBackup(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "c.yaml"), "orig\n")
	_, tx := newTx(t, base, &opts{force: true})
	if err := tx.Write("c.yaml", []byte("managed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Corrupt the backup of the original.
	backups, _ := filepath.Glob(filepath.Join(base, ".meta", "backups", "*", "*.bak"))
	if len(backups) == 0 {
		t.Fatal("backup of the original not found")
	}
	writeFile(t, backups[0], "corrupted content")

	root, err := openSafeRoot(base, false, &opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := restoreManaged(root, "test", ".meta/manifest.json", ".meta/backups", &opts{force: true}); err == nil {
		t.Fatal("restore should fail when the backup does not match the recorded hash")
	}
}

func TestWriteRejectsModifiedArtifactWithoutForce(t *testing.T) {
	base := t.TempDir()
	_, tx := newTx(t, base, &opts{})
	if err := tx.Write("f.txt", []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(base, "f.txt"), "modified")

	_, tx2 := newTx(t, base, &opts{})
	if err := tx2.Write("f.txt", []byte("v2"), 0o644); err == nil {
		t.Fatal("Write should refuse to overwrite a modified managed artifact without --force")
	}
	_ = tx2.Rollback()
}

func TestLoadManagedManifestRejectsInvalid(t *testing.T) {
	base := t.TempDir()
	root, err := openSafeRoot(base, true, &opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	cases := map[string]string{
		"wrong version": `{"version":99,"scope":"test","entries":[]}`,
		"wrong scope":   `{"version":1,"scope":"other","entries":[]}`,
		"unknown field": `{"version":1,"scope":"test","entries":[],"x":1}`,
		"extra json":    `{"version":1,"scope":"test","entries":[]}{}`,
		"absolute path": `{"version":1,"scope":"test","entries":[{"path":"/etc/x","installedSha256":"` + strings.Repeat("a", 64) + `","mode":420,"previous":{"existed":false}}]}`,
	}
	for name, content := range cases {
		if err := root.atomicWrite(".meta/manifest.json", []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadManagedManifest(root, "test", ".meta/manifest.json", ".meta/backups"); err == nil {
			t.Fatalf("%s: should be rejected", name)
		}
	}
}
