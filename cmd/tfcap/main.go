// Command tfcap inventories what Terraform/OpenTofu modules and providers
// can do (run programs, call the network, read credentials, grant IAM)
// and flags when an upgrade changes that.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/r-morato/tfcap/internal/diff"
	"github.com/r-morato/tfcap/internal/discover"
	"github.com/r-morato/tfcap/internal/lock"
	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/output"
	"github.com/r-morato/tfcap/internal/pin"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `tfcap: capability inventory and supply-chain guard for Terraform/OpenTofu modules

Usage:
  tfcap scan   [dir]              Inventory capabilities of a configuration and its modules
  tfcap diff   <base> <head>      Show capabilities added/removed between two dirs or JSON reports
  tfcap lock   [dir]              Write tfcap.lock.json pinning module content + reviewed capabilities
  tfcap verify [dir]              Check modules against tfcap.lock.json (tag mutation, new capabilities)
  tfcap pin    [dir]              Rewrite git module sources to the commit they resolved to
  tfcap rules                     List detection rules
  tfcap version                   Print version

Run 'tfcap <command> -h' for flags. Exit codes: 0 ok, 1 policy failure (--fail-on), 2 error.
`

func main() {
	if version == "dev" {
		// `go install ...@v1.2.3` embeds the module version.
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			version = bi.Main.Version
		}
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "scan":
		err = cmdScan(args[1:], stdout, stderr)
	case "diff":
		err = cmdDiff(args[1:], stdout, stderr)
	case "lock":
		err = cmdLock(args[1:], stdout, stderr)
	case "verify":
		err = cmdVerify(args[1:], stdout, stderr)
	case "rules":
		err = cmdRules(args[1:], stdout, stderr)
	case "pin":
		err = cmdPin(args[1:], stdout, stderr)
	case "validate-lock":
		err = cmdValidateLock(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "tfcap", version)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "tfcap: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	var ee exitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.code
	case errors.Is(err, flag.ErrHelp):
		return 0
	default:
		fmt.Fprintln(stderr, "tfcap:", err)
		return 2
	}
}

// common flags
type common struct {
	format    string
	out       string
	failOn    string
	minSev    string
	noColor   bool
	dataDir   string
	third     bool
	sarifBase string
}

func (c *common) register(fs *flag.FlagSet, formats, defFailOn string) {
	fs.StringVar(&c.format, "format", "text", "output format: "+formats)
	fs.StringVar(&c.out, "output", "", "write output to file instead of stdout")
	fs.StringVar(&c.failOn, "fail-on", defFailOn, "exit 1 if any finding is at or above this severity (none|info|low|medium|high|critical)")
	fs.StringVar(&c.minSev, "min-severity", "info", "hide findings below this severity")
	fs.BoolVar(&c.noColor, "no-color", false, "disable colored output (also honors NO_COLOR)")
	fs.StringVar(&c.dataDir, "data-dir", "", "Terraform data dir (default: $TF_DATA_DIR or .terraform)")
	fs.BoolVar(&c.third, "third-party-only", false, "only report capabilities from third-party (non-local) modules")
	fs.StringVar(&c.sarifBase, "sarif-base", "", "SARIF only: path of the scanned directory relative to the repository root (default: the directory argument)")
}

// sarifURIBase returns the prefix for SARIF artifact URIs.
func (c *common) sarifURIBase(dir string) string {
	if c.sarifBase != "" {
		return filepath.ToSlash(c.sarifBase)
	}
	return filepath.ToSlash(dir)
}

func (c *common) writer(stdout io.Writer) (io.Writer, func() error, error) {
	if c.out == "" || c.out == "-" {
		return stdout, func() error { return nil }, nil
	}
	f, err := os.Create(c.out)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

func (c *common) style(w io.Writer) output.Style {
	if c.noColor || os.Getenv("NO_COLOR") != "" || c.out != "" {
		return output.Style{}
	}
	f, ok := w.(*os.File)
	if !ok {
		return output.Style{}
	}
	st, err := f.Stat()
	return output.Style{Color: err == nil && st.Mode()&os.ModeCharDevice != 0}
}

func (c *common) filter(caps []model.Capability) ([]model.Capability, error) {
	min, ok := model.ParseSeverity(c.minSev)
	if !ok {
		return nil, fmt.Errorf("invalid --min-severity %q", c.minSev)
	}
	out := make([]model.Capability, 0, len(caps))
	for _, cp := range caps {
		if cp.Severity >= min {
			out = append(out, cp)
		}
	}
	return out, nil
}

func (c *common) gate(caps []model.Capability) error {
	if c.failOn == "" || c.failOn == "none" {
		return nil
	}
	th, ok := model.ParseSeverity(c.failOn)
	if !ok {
		return fmt.Errorf("invalid --fail-on %q", c.failOn)
	}
	if m, any := model.Max(caps); any && m >= th {
		return exitError{1}
	}
	return nil
}

func parse(fs *flag.FlagSet, args []string) error {
	// Allow flags after positional args: tfcap scan . --format json
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") {
				if f := fs.Lookup(name); f != nil {
					if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
						if i+1 < len(args) {
							flags = append(flags, args[i+1])
							i++
						}
					}
				}
			}
			continue
		}
		pos = append(pos, a)
	}
	return fs.Parse(append(flags, pos...))
}

func newFlagSet(name, synopsis string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s\n\nFlags:\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

func dirArg(fs *flag.FlagSet) string {
	if fs.NArg() > 0 {
		return fs.Arg(0)
	}
	return "."
}

// ---- scan ----

func cmdScan(args []string, stdout, stderr io.Writer) error {
	var c common
	fs := newFlagSet("scan", "tfcap scan [dir] [flags]", stderr)
	c.register(fs, "text|json|sarif", "none")
	if err := parse(fs, args); err != nil {
		return err
	}
	rep, err := discover.Scan(dirArg(fs), discover.Options{DataDir: c.dataDir, ThirdPartyOnly: c.third, Version: version})
	if err != nil {
		return err
	}
	if rep.Capabilities, err = c.filter(rep.Capabilities); err != nil {
		return err
	}
	w, closeFn, err := c.writer(stdout)
	if err != nil {
		return err
	}
	switch c.format {
	case "text":
		output.Report(w, rep, c.style(w))
	case "json":
		err = output.JSON(w, rep)
	case "sarif":
		err = output.SARIF(w, rep.Capabilities, rep.Modules, c.sarifURIBase(dirArg(fs)), version)
	default:
		err = fmt.Errorf("unknown --format %q", c.format)
	}
	if cerr := closeFn(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return c.gate(rep.Capabilities)
}

// ---- diff ----

func loadReport(p string, c *common) (*model.Report, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return discover.Scan(p, discover.Options{DataDir: c.dataDir, ThirdPartyOnly: c.third, Version: version})
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var rep model.Report
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&rep); err != nil {
		return nil, fmt.Errorf("%s: not a tfcap JSON report: %w", p, err)
	}
	if rep.Schema != model.ReportSchema {
		return nil, fmt.Errorf("%s: unsupported report schema %q", p, rep.Schema)
	}
	if c.third {
		third := map[string]bool{}
		for _, m := range rep.Modules {
			third[m.Key] = m.ThirdParty
		}
		kept := rep.Capabilities[:0]
		for _, cp := range rep.Capabilities {
			if third[cp.Module] {
				kept = append(kept, cp)
			}
		}
		rep.Capabilities = kept
	}
	return &rep, nil
}

func cmdDiff(args []string, stdout, stderr io.Writer) error {
	var c common
	fs := newFlagSet("diff", "tfcap diff <base dir|report.json> <head dir|report.json> [flags]", stderr)
	c.register(fs, "text|json|markdown|sarif", "high")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return exitError{2}
	}
	base, err := loadReport(fs.Arg(0), &c)
	if err != nil {
		return err
	}
	head, err := loadReport(fs.Arg(1), &c)
	if err != nil {
		return err
	}
	d := diff.Compare(base, head)
	if d.Added, err = c.filter(d.Added); err != nil {
		return err
	}
	w, closeFn, err := c.writer(stdout)
	if err != nil {
		return err
	}
	switch c.format {
	case "text":
		output.Diff(w, d, c.style(w))
	case "json":
		err = output.JSON(w, d)
	case "markdown", "md":
		output.DiffMarkdown(w, d)
	case "sarif":
		uriBase := fs.Arg(1)
		if st, e := os.Stat(uriBase); e == nil && !st.IsDir() {
			uriBase = head.Root
		}
		err = output.SARIF(w, d.Added, head.Modules, c.sarifURIBase(uriBase), version)
	default:
		err = fmt.Errorf("unknown --format %q", c.format)
	}
	if cerr := closeFn(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return c.gate(d.Added)
}

// ---- lock / verify ----

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdLock(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("lock", "tfcap lock [dir] [flags]", stderr)
	file := fs.String("file", "", "lock file path (default: <dir>/tfcap.lock.json)")
	dataDir := fs.String("data-dir", "", "Terraform data dir (default: $TF_DATA_DIR or .terraform)")
	acceptMutated := fs.Bool("accept-mutated", false, "also accept modules whose content changed without a version change (normally refused)")
	var only stringList
	fs.Var(&only, "module", "only update this module's entry (module key, e.g. network or vpc.subnets); repeatable")
	if err := parse(fs, args); err != nil {
		return err
	}
	dir := dirArg(fs)
	rep, err := discover.Scan(dir, discover.Options{DataDir: *dataDir, Version: version})
	if err != nil {
		return err
	}
	path := *file
	if path == "" {
		path = filepath.Join(dir, "tfcap.lock.json")
	}

	var old *lock.File
	if f, err := lock.Read(path); err == nil {
		old = f
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Never silently accept a module whose code changed behind an unchanged
	// version: that is the attack the lock file exists to catch.
	if old != nil && !*acceptMutated {
		selected := map[string]bool{}
		for _, k := range only {
			selected[k] = true
		}
		var mutated []string
		v := lock.Verify(old, rep)
		for _, m := range v.Modules {
			if m.Status == lock.StatusMutated && (len(only) == 0 || selected[m.Key]) {
				mutated = append(mutated, displayModule(m.Key))
			}
		}
		for _, p := range v.Providers {
			if p.Status == "mutated" && len(only) == 0 {
				mutated = append(mutated, "provider "+p.Address)
			}
		}
		if len(mutated) > 0 {
			fmt.Fprintf(stderr, "tfcap: refusing to lock: %s changed content without a version change (MUTATED).\n", strings.Join(mutated, ", "))
			fmt.Fprintln(stderr, "       This is what a moved git tag or a tampered registry release looks like.")
			fmt.Fprintln(stderr, "       Run `tfcap verify` to see what changed. Only if you are sure it is legitimate, re-run with --accept-mutated.")
			return exitError{1}
		}
	}

	fresh := lock.Build(rep)
	lf, err := lock.Merge(old, fresh, only)
	if err != nil {
		return err
	}
	if len(lf.Modules) == 0 {
		fmt.Fprintln(stderr, "tfcap: warning: no third-party modules found. Did you run `terraform init`?")
	}
	if err := lf.Write(path); err != nil {
		return err
	}

	changes := lock.Diff(old, lf)
	unchanged := 0
	fmt.Fprintf(stdout, "Wrote %s\n", path)
	for _, ch := range changes {
		switch ch.Kind {
		case "added":
			fmt.Fprintf(stdout, "  + %s  added: %s (%d capabilities)\n", displayModule(ch.Key), shortSource(ch.To), ch.NewCaps)
		case "updated":
			fmt.Fprintf(stdout, "  ~ %s  %s → %s (%d new capabilities)\n", displayModule(ch.Key), shortSource(ch.From), shortSource(ch.To), ch.NewCaps)
		case "removed":
			fmt.Fprintf(stdout, "  - %s  removed\n", displayModule(ch.Key))
		default:
			unchanged++
		}
	}
	if unchanged > 0 {
		fmt.Fprintf(stdout, "  = %d unchanged\n", unchanged)
	}
	return nil
}

func displayModule(key string) string { return "module." + strings.ReplaceAll(key, ".", ".module.") }

func cmdVerify(args []string, stdout, stderr io.Writer) error {
	var c common
	fs := newFlagSet("verify", "tfcap verify [dir] [flags]", stderr)
	c.register(fs, "text|json|markdown|sarif", "high")
	file := fs.String("file", "", "lock file path (default: <dir>/tfcap.lock.json)")
	if err := parse(fs, args); err != nil {
		return err
	}
	dir := dirArg(fs)
	path := *file
	if path == "" {
		path = filepath.Join(dir, "tfcap.lock.json")
	}
	lf, err := lock.Read(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no lock file at %s; run `tfcap lock` first", path)
		}
		return err
	}
	rep, err := discover.Scan(dir, discover.Options{DataDir: c.dataDir, Version: version})
	if err != nil {
		return err
	}
	v := lock.Verify(lf, rep)
	if v.Findings, err = c.filter(v.Findings); err != nil {
		return err
	}
	w, closeFn, err := c.writer(stdout)
	if err != nil {
		return err
	}
	switch c.format {
	case "text":
		output.Verify(w, v, c.style(w))
	case "json":
		err = output.JSON(w, v)
	case "markdown", "md":
		output.VerifyMarkdown(w, v)
	case "sarif":
		err = output.SARIF(w, v.Findings, rep.Modules, c.sarifURIBase(dir), version)
	default:
		err = fmt.Errorf("unknown --format %q", c.format)
	}
	if cerr := closeFn(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return c.gate(v.Findings)
}

func cmdRules(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("rules", "tfcap rules [--format text|markdown]", stderr)
	format := fs.String("format", "text", "text|markdown")
	if err := parse(fs, args); err != nil {
		return err
	}
	output.Rules(stdout, *format == "markdown" || *format == "md")
	return nil
}

// cmdValidateLock strictly checks a lock file without trusting it; used by
// the GitHub Action before committing a lock file produced by another job.
func cmdValidateLock(args []string, stdout, stderr io.Writer) error {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "Usage: tfcap validate-lock <file>")
		return exitError{2}
	}
	if err := lock.Validate(args[0]); err != nil {
		fmt.Fprintln(stderr, "tfcap:", err)
		return exitError{1}
	}
	fmt.Fprintln(stdout, "ok")
	return nil
}

func cmdPin(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("pin", "tfcap pin [dir] [flags]", stderr)
	exact := fs.Bool("exact-registry", false, "also pin registry modules to the exact version installed")
	check := fs.Bool("check", false, "don't write anything; exit 1 if something would be pinned (for CI)")
	dataDir := fs.String("data-dir", "", "Terraform data dir (default: $TF_DATA_DIR or .terraform)")
	if err := parse(fs, args); err != nil {
		return err
	}
	dir := dirArg(fs)
	rep, err := discover.Scan(dir, discover.Options{DataDir: *dataDir, Version: version})
	if err != nil {
		return err
	}
	changes, notes, edits := pin.Plan(dir, rep, pin.Options{ExactRegistry: *exact})
	for _, n := range notes {
		fmt.Fprintln(stderr, "tfcap: note:", n)
	}
	if len(changes) == 0 {
		fmt.Fprintln(stdout, "Nothing to pin: every third-party module is already pinned.")
		return nil
	}
	verb := "Pinned"
	if *check {
		verb = "Would pin"
	}
	for _, c := range changes {
		fmt.Fprintf(stdout, "%s %s (%s:%d)\n    %s\n  → %s\n", verb, c.Module, c.File, c.Line, c.From, c.To)
	}
	if *check {
		return exitError{1}
	}
	if err := pin.Apply(edits); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "\nNext: run `terraform init` (sources changed), then `tfcap verify` and `tfcap lock`.")
	return nil
}

// shortSource keeps lock summaries readable: git sources show only their
// ref (SHAs shortened), registry sources their address and version.
func shortSource(s string) string {
	if i := strings.Index(s, "?ref="); i >= 0 {
		ref := s[i+5:]
		if len(ref) >= 40 {
			ref = ref[:12]
		}
		return "ref=" + ref
	}
	return strings.TrimPrefix(s, "registry.terraform.io/")
}
