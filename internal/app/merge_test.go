package app

import (
	"os"
	"strings"
	"testing"
)

func TestMergePermissionsStructuralAndIdempotent(t *testing.T) {
	managed := []byte("rules:\n  - capability: fs_read\n    effect: deny\n")
	first, err := mergePermissionsData(nil, managed, "baseline")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), "capability: fs_read") || !strings.Contains(string(first), managedRuleToken) {
		t.Fatalf("incomplete merge:\n%s", first)
	}
	if !strings.Contains(string(first), "profile=baseline") {
		t.Fatalf("profile marker missing:\n%s", first)
	}
	second, err := mergePermissionsData(first, managed, "baseline")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(second), "capability: fs_read") != 1 {
		t.Fatalf("duplicated managed rule:\n%s", second)
	}
	// Switching profiles replaces the marker without duplicating the rule.
	third, err := mergePermissionsData(second, managed, "strict")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(third), "capability: fs_read") != 1 || !strings.Contains(string(third), "profile=strict") {
		t.Fatalf("unexpected profile switch:\n%s", third)
	}
	if detectProfileFromPermissions(third) != "strict" {
		t.Fatalf("detectProfileFromPermissions should return strict:\n%s", third)
	}
}

func TestMergePermissionsPreservesUserStructure(t *testing.T) {
	existing := []byte("foo: bar\nrules: []\n")
	managed := []byte("rules:\n  - capability: fs_write\n    effect: deny\n")
	out, err := mergePermissionsData(existing, managed, "baseline")
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "foo: bar") || !strings.Contains(text, "capability: fs_write") {
		t.Fatalf("user structure lost:\n%s", text)
	}
}

func TestMergePermissionsRejectsDangerousYAML(t *testing.T) {
	managed := []byte("rules:\n  - capability: fs_read\n    effect: deny\n")
	for _, existing := range []string{
		"rules: []\nrules: []\n",
		"rules: invalid\n",
		mgrStart + "\nrules:\n",
	} {
		if _, err := mergePermissionsData([]byte(existing), managed, "baseline"); err == nil {
			t.Fatalf("should reject invalid YAML/block:\n%s", existing)
		}
	}
}

func TestMergeKiroignoreManagedAndIdempotent(t *testing.T) {
	existing := []byte(".env\n")
	managed := []byte("# comment\n.env\n*.pem\n.env.*\n!.env.example\n")
	first, err := mergeKiroignoreData(existing, managed)
	if err != nil {
		t.Fatal(err)
	}
	text := string(first)
	if strings.Count(text, ".env\n") != 1 || !strings.Contains(text, mgrStart) || !strings.Contains(text, "!.env.example") {
		t.Fatalf("unexpected merge:\n%s", text)
	}
	second, err := mergeKiroignoreData(first, managed)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(first) {
		t.Fatalf("merge not idempotent:\nfirst=%s\nsecond=%s", first, second)
	}
}

// helpers shared across the package tests.
func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readFile %s: %v", path, err)
	}
	return string(data)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
}
