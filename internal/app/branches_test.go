package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckRoot(t *testing.T) {
	if checkRoot("linux", 0) == nil {
		t.Fatal("linux+root should fail")
	}
	if checkRoot("linux", 1000) != nil {
		t.Fatal("linux+non-root should pass")
	}
	if checkRoot("windows", 0) != nil {
		t.Fatal("windows should pass")
	}
}

func TestBinNameFor(t *testing.T) {
	if binNameFor("windows") != "kiro-secops.exe" || binNameFor("linux") != "kiro-secops" || binName() == "" {
		t.Fatal("unexpected binary name")
	}
}

func TestSafeRootRejectsTraversal(t *testing.T) {
	root, err := openSafeRoot(t.TempDir(), false, &opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := root.cleanRel("../escape"); err == nil {
		t.Fatal("traversal should be rejected")
	}
	if err := root.atomicWrite("../escape", []byte("x"), 0o644); err == nil {
		t.Fatal("a write outside the root should be rejected")
	}
}

func TestSafeRootDryRun(t *testing.T) {
	base := t.TempDir()
	root, err := openSafeRoot(base, false, &opts{dryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.atomicWrite("new/f.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "new", "f.txt")); !os.IsNotExist(err) {
		t.Fatal("dry-run should not write")
	}
}

func TestInstallKiroHomeInvalid(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root, mustNotRoot fails before kiroHome")
	}
	t.Setenv("KIRO_HOME", "relative/path")
	if rc := cmdInstall(&opts{}); rc == 0 {
		t.Fatal("cmdInstall should fail with a relative KIRO_HOME")
	}
}

func TestInstallKiroHomeIsFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root, mustNotRoot fails first")
	}
	file := filepath.Join(t.TempDir(), "kirofile")
	writeFile(t, file, "x")
	t.Setenv("KIRO_HOME", file)
	if rc := cmdInstall(&opts{}); rc == 0 {
		t.Fatal("cmdInstall should fail when KIRO_HOME is a file")
	}
}
