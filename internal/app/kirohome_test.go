package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestKiroHome(t *testing.T) {
	absHome := filepath.Join(t.TempDir(), "kiro") // absolute on any OS
	t.Setenv("KIRO_HOME", absHome)
	if home, err := kiroHome(); err != nil || home != filepath.Clean(absHome) {
		t.Fatalf("absolute: home=%q err=%v", home, err)
	}
	t.Setenv("KIRO_HOME", filepath.Join("relative", "kiro"))
	if _, err := kiroHome(); err == nil {
		t.Fatal("relative KIRO_HOME should be rejected")
	}
	_ = os.Unsetenv("KIRO_HOME")
	if home, err := kiroHome(); err != nil || !strings.HasSuffix(home, ".kiro") {
		t.Fatalf("default: home=%q err=%v", home, err)
	}
}

func TestFirstString(t *testing.T) {
	values := map[string]any{"a": "", "b": "x", "c": 3}
	if got := firstString(values, "a", "b"); got != "x" {
		t.Fatalf("first non-empty: %q", got)
	}
	if got := firstString(values, "c", "nonexistent"); got != "" {
		t.Fatalf("non-string value should be ignored: %q", got)
	}
}

func TestSafeRootAtomicWritePreservesMode(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "f.txt")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := openSafeRoot(base, false, &opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.atomicWrite("f.txt", []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != "v2" {
		t.Fatalf("unexpected content: %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode should be preserved: %o", info.Mode().Perm())
	}
}

func TestSafeRootRejectsFinalAndParentSymlink(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "target"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "target"), filepath.Join(base, "link")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "parent")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	root, err := openSafeRoot(base, false, &opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.atomicWrite("link", []byte("x"), 0o644); err == nil {
		t.Fatal("final symlink should be rejected")
	}
	if err := root.atomicWrite(filepath.Join("parent", "escape"), []byte("x"), 0o644); err == nil {
		t.Fatal("parent symlink should be rejected")
	}
	if _, err := os.Stat(filepath.Join(outside, "escape")); !os.IsNotExist(err) {
		t.Fatal("no file should be created outside the root")
	}
}

func TestOpenSafeRootRejectsSymlinkRoot(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if _, err := openSafeRoot(link, false, &opts{}); err == nil {
		t.Fatal("symlink root should be rejected")
	}
}
