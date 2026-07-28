package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	scanReportSchemaVersion = 1
	maxToolOutput           = 4096 // limits the output captured per scanner in the report
	sarifSchemaURL          = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	toolInformationURI      = "https://github.com/aws-samples/sample-kiro-secops-baseline"
)

type scanStatus string

const (
	statusClean    scanStatus = "clean"
	statusFindings scanStatus = "findings"
	statusSkipped  scanStatus = "skipped"
	statusError    scanStatus = "error"
	statusTimeout  scanStatus = "timeout"
)

// toolResult is the result of a single scanner within a scan run.
// Output holds the captured raw output, but it is shown ONLY on interactive stdout
// (text mode). It is never serialized to JSON/SARIF nor written to a file (--output),
// so as not to leak secrets that scanners might print into persisted reports.
type toolResult struct {
	Tool       string     `json:"tool"`
	Args       []string   `json:"args"`
	Status     scanStatus `json:"status"`
	ExitCode   int        `json:"exitCode"`
	DurationMs int64      `json:"durationMs"`
	Output     string     `json:"-"`
}

// scanReport is the consolidated report (own schema) of a scan run.
type scanReport struct {
	SchemaVersion int          `json:"schemaVersion"`
	Tool          string       `json:"tool"`
	Version       string       `json:"version"`
	Dir           string       `json:"dir"`
	Timestamp     string       `json:"timestamp"`
	Findings      bool         `json:"findings"`
	Operational   bool         `json:"operational"`
	Results       []toolResult `json:"results"`
}

// runProcess is the injectable seam for executing a scanner. The default uses exec BEHIND the
// execCommandContext variable (avoiding the literal exec.Command call in tests); tests replace it
// with a pure-Go fake, without a subprocess. It returns (combined output, exit code, operational error):
// exit code 0 = ok, >0 = findings; error != nil only on a failure to start/run (not on exit != 0).
var runProcess = defaultRunProcess

func defaultRunProcess(ctx context.Context, dir, name string, args ...string) ([]byte, int, error) {
	cmd := execCommandContext(ctx, name, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	if err == nil {
		return buf.Bytes(), 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return buf.Bytes(), exitErr.ExitCode(), nil // non-zero exit = findings, not an operational error
	}
	return buf.Bytes(), -1, err // did not start / canceled / timeout
}

// runScanners runs the applicable scanners, capturing each one's result.
func runScanners(abs string, files projectFiles, o scanOpts) scanReport {
	report := scanReport{
		SchemaVersion: scanReportSchemaVersion,
		Tool:          "kiro-secops",
		Version:       version,
		Dir:           abs,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}

	run := func(tool string, args ...string) {
		fmt.Fprintf(os.Stderr, "kiro-secops scan: %s...\n", tool)
		res := toolResult{Tool: tool, Args: args}

		resolved, err := lookPath(tool)
		if err != nil {
			res.Status = statusSkipped
			if o.requireTools {
				report.Operational = true
			}
			report.Results = append(report.Results, res)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
		defer cancel()
		start := time.Now()
		out, exitCode, runErr := runProcess(ctx, abs, resolved, args...)
		res.DurationMs = time.Since(start).Milliseconds()
		res.Output = truncateOutput(string(out))

		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			res.Status = statusTimeout
			report.Operational = true
		case runErr != nil:
			res.Status = statusError
			report.Operational = true
		case exitCode != 0:
			res.Status = statusFindings
			res.ExitCode = exitCode
			report.Findings = true
		default:
			res.Status = statusClean
		}
		report.Results = append(report.Results, res)
	}

	run("semgrep", "scan", "--quiet", "--config", "p/ci", "--error", ".")
	if files.langs["py"] {
		run("bandit", "-r", ".", "-ll", "-q")
		run("pip-audit")
	}
	if files.langs["node"] {
		run("njsscan", "-w", ".")
		run("npm", "audit", "--audit-level=high")
	}
	if len(files.shellFiles) > 0 {
		run("shellcheck", append([]string{"--severity=warning", "--"}, files.shellFiles...)...)
	}
	run("trivy", "fs", "--quiet", "--scanners", "vuln,secret,misconfig", "--severity", "HIGH,CRITICAL", ".")
	run("gitleaks", "detect", "--no-git", "--redact", "--source", ".")

	return report
}

// renderScanReport emits the report in the chosen format, to stdout or --output.
// The scanners' raw output is only printed on interactive stdout (text) — never in
// JSON/SARIF (Output has the tag json:"-") nor to a file, to avoid persisting secrets.
func renderScanReport(report scanReport, o scanOpts) error {
	var data []byte
	var err error
	switch o.format {
	case "json":
		data, err = json.MarshalIndent(report, "", "  ")
	case "sarif":
		data, err = json.MarshalIndent(toSARIF(report), "", "  ")
	case "", "text":
		includeOutput := o.output == "" // raw output only on the interactive console
		return writeScanOutput([]byte(renderScanText(report, includeOutput)), o.output)
	default:
		return fmt.Errorf("unknown format: %q", o.format)
	}
	if err != nil {
		return err
	}
	return writeScanOutput(append(data, '\n'), o.output)
}

func writeScanOutput(data []byte, output string) error {
	if output == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(filepath.Clean(output), data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "kiro-secops scan: report written to %s\n", output)
	return nil
}

func renderScanText(report scanReport, includeOutput bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "kiro-secops scan -> %s\n", report.Dir)
	for _, r := range report.Results {
		switch r.Status {
		case statusSkipped:
			fmt.Fprintf(&b, "  [%-8s] %s (missing)\n", r.Status, r.Tool)
		case statusClean:
			fmt.Fprintf(&b, "  [%-8s] %s (%dms)\n", r.Status, r.Tool, r.DurationMs)
		default:
			fmt.Fprintf(&b, "  [%-8s] %s (exit %d, %dms)\n", r.Status, r.Tool, r.ExitCode, r.DurationMs)
			trimmed := strings.TrimSpace(r.Output)
			switch {
			case includeOutput && trimmed != "":
				for _, line := range strings.Split(trimmed, "\n") {
					fmt.Fprintf(&b, "      | %s\n", line)
				}
			case trimmed != "":
				fmt.Fprintf(&b, "      | (output omitted from the file; run '%s %s' for details)\n", r.Tool, strings.Join(r.Args, " "))
			}
		}
	}
	switch {
	case report.Operational:
		b.WriteString("\nkiro-secops scan: operational failure — the gate did not complete.\n")
	case report.Findings:
		b.WriteString("\nkiro-secops scan: findings detected — review before finishing.\n")
	default:
		b.WriteString("\nkiro-secops scan: no findings.\n")
	}
	return b.String()
}

// --- SARIF 2.1.0 (minimal, valid for upload to code scanning) ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID  string    `json:"ruleId"`
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

// toSARIF converts the report into a SARIF with a single run (driver kiro-secops),
// one rule per executed scanner and one result per scanner with a finding/error/timeout.
func toSARIF(report scanReport) sarifLog {
	driver := sarifDriver{
		Name:           "kiro-secops",
		InformationURI: toolInformationURI,
		Version:        report.Version,
	}
	var results []sarifResult
	for _, r := range report.Results {
		if r.Status == statusSkipped || r.Status == statusClean {
			continue
		}
		ruleID := "kiro-secops/" + r.Tool
		driver.Rules = append(driver.Rules, sarifRule{
			ID:               ruleID,
			Name:             r.Tool,
			ShortDescription: sarifText{Text: fmt.Sprintf("%s scanner result", r.Tool)},
		})
		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(r.Status),
			Message: sarifText{Text: sarifMessage(r)},
		})
	}
	if driver.Rules == nil {
		driver.Rules = []sarifRule{}
	}
	if results == nil {
		results = []sarifResult{}
	}
	return sarifLog{
		Schema:  sarifSchemaURL,
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	}
}

func sarifLevel(status scanStatus) string {
	switch status {
	case statusFindings:
		return "error"
	case statusTimeout, statusError:
		return "warning"
	default:
		return "note"
	}
}

func sarifMessage(r toolResult) string {
	switch r.Status {
	case statusFindings:
		return fmt.Sprintf("%s reported findings (exit %d). Run '%s %s' for details.", r.Tool, r.ExitCode, r.Tool, strings.Join(r.Args, " "))
	case statusTimeout:
		return fmt.Sprintf("%s exceeded the scan timeout.", r.Tool)
	default:
		return fmt.Sprintf("%s failed operationally during the scan.", r.Tool)
	}
}

func truncateOutput(s string) string {
	if len(s) <= maxToolOutput {
		return s
	}
	return s[:maxToolOutput] + "\n...[truncated]"
}
