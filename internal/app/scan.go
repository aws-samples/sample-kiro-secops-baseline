package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Injectable for testing.
var (
	lookPath           = exec.LookPath
	execCommandContext = exec.CommandContext
)

type projectFiles struct {
	langs      map[string]bool
	shellFiles []string
}

// cmdScan runs scanners in blocking mode, preserving the historical internal API.
func cmdScan(dir string) int {
	return cmdScanWithOptions(scanOpts{dir: dir, timeout: 10 * time.Minute})
}

// cmdScanWithOptions validates the target, runs the applicable scanners (capturing
// each one's result), emits the report in the requested format, and returns the exit code:
// 2 (operational failure), 1 (findings, unless --advisory), or 0.
func cmdScanWithOptions(o scanOpts) int {
	abs, err := filepath.Abs(o.dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	info, err := os.Stat(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: scan directory:", err)
		return exitError
	}
	if !info.IsDir() {
		fmt.Fprintln(os.Stderr, "error: scan target is not a directory:", abs)
		return exitError
	}

	files, err := inspectProject(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error inspecting project:", err)
		return exitError
	}

	report := runScanners(abs, files, o)
	if err := renderScanReport(report, o); err != nil {
		fmt.Fprintln(os.Stderr, "error emitting report:", err)
		return exitError
	}

	switch {
	case report.Operational:
		return exitUsage
	case report.Findings && !o.advisory:
		return exitError
	default:
		return exitOK
	}
}

func inspectProject(root string) (projectFiles, error) {
	result := projectFiles{langs: map[string]bool{}}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".terraform":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		switch {
		case strings.HasSuffix(name, ".py"):
			result.langs["py"] = true
		case name == "package.json",
			strings.HasSuffix(name, ".ts"), strings.HasSuffix(name, ".tsx"),
			strings.HasSuffix(name, ".js"), strings.HasSuffix(name, ".jsx"):
			result.langs["node"] = true
		case strings.HasSuffix(name, ".sh"):
			result.langs["sh"] = true
			rel, relErr := filepath.Rel(root, p)
			if relErr != nil {
				return relErr
			}
			result.shellFiles = append(result.shellFiles, rel)
		}
		return nil
	})
	return result, err
}

func detectLangs(root string) map[string]bool {
	files, err := inspectProject(root)
	if err != nil {
		return map[string]bool{}
	}
	return files.langs
}
