package app

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

var (
	version = "1.1.0" // -ldflags "-X kiro-secops/internal/app.version=..."
	commit  = ""      // -ldflags "-X kiro-secops/internal/app.commit=..."
	date    = ""      // -ldflags "-X kiro-secops/internal/app.date=..."
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

type opts struct {
	dryRun  bool
	force   bool
	project string
	profile string
}

type scanOpts struct {
	dir          string
	advisory     bool
	requireTools bool
	timeout      time.Duration
	format       string
	output       string
}

// Run is the CLI entry point (invoked by cmd/kiro-secops). It returns the exit code.
func Run(args []string) int { return run(args) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "install":
		o, err := parseInstall(rest)
		if err != nil {
			return parseExit(err)
		}
		return cmdInstall(o)
	case "init":
		o, err := parseInit(rest)
		if err != nil {
			return parseExit(err)
		}
		return cmdInit(o)
	case "guard":
		if rc, done := noArgsCommand("guard", rest); done {
			return rc
		}
		return cmdGuard()
	case "scan":
		o, err := parseScan(rest)
		if err != nil {
			return parseExit(err)
		}
		return cmdScanWithOptions(o)
	case "verify":
		strict, project, err := parseVerify(rest)
		if err != nil {
			return parseExit(err)
		}
		return cmdVerify(strict, project)
	case "uninstall":
		o, err := parseUninstall(rest)
		if err != nil {
			return parseExit(err)
		}
		return cmdUninstall(o)
	case "version", "--version", "-v":
		if len(rest) != 0 {
			fmt.Fprintf(os.Stderr, "%s does not accept arguments: %q\n", cmd, rest)
			return exitUsage
		}
		fmt.Println("kiro-secops", version)
		if commit != "" || date != "" {
			fmt.Printf("  commit %s  date %s\n", commit, date)
		}
		return exitOK
	case "help", "--help", "-h":
		if len(rest) != 0 {
			fmt.Fprintf(os.Stderr, "%s does not accept arguments: %q\n", cmd, rest)
			return exitUsage
		}
		usage()
		return exitOK
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		usage()
		return exitUsage
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage
	return fs
}

func parseInstall(args []string) (*opts, error) {
	fs := newFlagSet("install")
	o := &opts{}
	fs.BoolVar(&o.dryRun, "dry-run", false, "show what would be done without writing")
	fs.BoolVar(&o.force, "force", false, "replace managed artifacts after a safe backup")
	fs.StringVar(&o.profile, "profile", defaultProfile, "permissions profile: baseline|strict")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("install does not accept positional arguments: %q", fs.Args())
	}
	return o, nil
}

func parseInit(args []string) (*opts, error) {
	fs := newFlagSet("init")
	o := &opts{}
	fs.BoolVar(&o.dryRun, "dry-run", false, "show what would be done without writing")
	fs.BoolVar(&o.force, "force", false, "replace managed artifacts after a safe backup")
	fs.StringVar(&o.project, "project", "", "project directory (default: cwd)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("init does not accept positional arguments; use --project DIR: %q", fs.Args())
	}
	return o, nil
}

func parseUninstall(args []string) (*opts, error) {
	fs := newFlagSet("uninstall")
	o := &opts{}
	fs.BoolVar(&o.dryRun, "dry-run", false, "show what would be done without writing")
	fs.BoolVar(&o.force, "force", false, "remove managed artifact even if it has been modified")
	fs.StringVar(&o.project, "project", "", "remove this project's WORKSPACE layer (default: global in ~/.kiro)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("uninstall does not accept positional arguments; use --project DIR: %q", fs.Args())
	}
	return o, nil
}

func parseScan(args []string) (scanOpts, error) {
	fs := newFlagSet("scan")
	o := scanOpts{dir: ".", timeout: 10 * time.Minute, format: "text"}
	fs.BoolVar(&o.advisory, "advisory", false, "report findings without returning a failure")
	fs.BoolVar(&o.requireTools, "require-tools", false, "fail if an applicable scanner is not installed")
	fs.DurationVar(&o.timeout, "timeout", o.timeout, "maximum timeout per scanner")
	fs.StringVar(&o.format, "format", o.format, "report format: text|json|sarif")
	fs.StringVar(&o.output, "output", "", "write the report to this file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return scanOpts{}, err
	}
	if fs.NArg() > 1 {
		return scanOpts{}, fmt.Errorf("scan accepts at most one directory: %q", fs.Args())
	}
	if fs.NArg() == 1 {
		o.dir = fs.Arg(0)
	}
	if o.timeout <= 0 {
		return scanOpts{}, errors.New("--timeout must be greater than zero")
	}
	switch o.format {
	case "text", "json", "sarif":
	default:
		return scanOpts{}, fmt.Errorf("invalid --format: %q (use text|json|sarif)", o.format)
	}
	return o, nil
}

func parseVerify(args []string) (bool, string, error) {
	fs := newFlagSet("verify")
	strict := fs.Bool("strict", false, "validate the global installation against the manifest (hash + presence) and fail if it diverges")
	project := fs.String("project", "", "also verify this project's WORKSPACE layer (hook health + manifest)")
	if err := fs.Parse(args); err != nil {
		return false, "", err
	}
	if fs.NArg() != 0 {
		return false, "", fmt.Errorf("verify does not accept positional arguments: %q", fs.Args())
	}
	return *strict, *project, nil
}

func parseExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return exitUsage
}

func noArgsCommand(name string, args []string) (int, bool) {
	if len(args) == 0 {
		return exitOK, false
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		usage()
		return exitOK, true
	}
	fmt.Fprintf(os.Stderr, "%s does not accept arguments: %q\n", name, args)
	return exitUsage, true
}

func usage() {
	fmt.Fprint(os.Stderr, `kiro-secops — DevSecOps baseline for Kiro

USAGE:
  kiro-secops install   [--profile baseline|strict] [--dry-run] [--force]
                                             Installs GLOBAL config in ~/.kiro (respects KIRO_HOME)
  kiro-secops init      [--project DIR] [--dry-run] [--force]
                                             Scaffolds the WORKSPACE layer in a project
  kiro-secops guard                             Hook runtime: reads JSON from stdin; allow/block (fail-closed)
  kiro-secops scan      [--advisory] [--require-tools] [--timeout D] [--format text|json|sarif] [--output FILE] [DIR]
                                             Runs scanners; findings block by default
  kiro-secops verify   [--strict] [--project DIR]
                                             Guard self-test (+ install integrity with --strict;
                                             + workspace hooks/manifest with --project)
  kiro-secops uninstall [--project DIR] [--dry-run] [--force]
                                             Removes/restores only managed artifacts
  kiro-secops version                           Shows the version

Guard (PreToolUse): exit 0 allows; exit 2 blocks (stderr to the model).
Confirmations must be enforced by permissions.yaml (effect: ask); they do not depend on the hook's stdout.
Does not require sudo. Respects KIRO_HOME.
`)
}
