package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// kiroHome resolves the Kiro base directory, respecting KIRO_HOME (must be absolute).
func kiroHome() (string, error) {
	if value := os.Getenv("KIRO_HOME"); value != "" {
		if !filepath.IsAbs(value) {
			return "", fmt.Errorf("KIRO_HOME must be an absolute path: %q", value)
		}
		return filepath.Clean(value), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not resolve the user home: %w", err)
	}
	return filepath.Join(home, ".kiro"), nil
}

// mustNotRoot refuses execution as root (avoids root-owned files in ~/.kiro).
func mustNotRoot() error { return checkRoot(runtime.GOOS, os.Geteuid()) }

// checkRoot is the testable logic (independent of the real platform).
func checkRoot(goos string, euid int) error {
	if goos != "windows" && euid == 0 {
		return fmt.Errorf("do not run as root: kiro-secops installs into the user's ~/.kiro (no sudo)")
	}
	return nil
}

// firstString returns the first non-empty string value among the given keys.
func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			if text, ok := value.(string); ok && text != "" {
				return text
			}
		}
	}
	return ""
}
