//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ChildArg is the hidden subcommand the sandbox re-executes itself with.
const ChildArg = "__sandbox-child"

const configEnv = "TFCAP_SANDBOX_CONFIG"

// Options configure a sandbox run.
type Options struct {
	Dir     string        // working directory (absolute)
	Command []string      // command to run
	Timeout time.Duration // kill after this long
	Self    string        // path of the tfcap binary
	Stdout  io.Writer     // the command's output
	Stderr  io.Writer
}

// Result is what a sandbox run observed.
type Result struct {
	Events   []Event  `json:"events"`
	ExitCode int      `json:"exit_code"`
	Strace   bool     `json:"strace"`
	Notes    []string `json:"notes,omitempty"`
	TimedOut bool     `json:"timed_out,omitempty"`
}

type childConfig struct {
	Dir     string
	Command []string
	Timeout time.Duration
	Honey   *Honey
}

// Supported reports whether sandboxing can work here.
func Supported() error { return nil }

// Run starts the sandbox: a child in new user, network, mount and PID
// namespaces that sets everything up and runs the command.
func Run(opts Options) (*Result, error) {
	h := NewHoney()
	cfg, _ := json.Marshal(childConfig{Dir: opts.Dir, Command: opts.Command, Timeout: opts.Timeout, Honey: h})
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(opts.Self, ChildArg)
	cmd.Env = append(os.Environ(), configEnv+"="+string(cfg))
	cmd.Stdout, cmd.Stderr = opts.Stdout, opts.Stderr
	cmd.ExtraFiles = []*os.File{w}
	cmd.Dir = opts.Dir
	flags := uintptr(syscall.CLONE_NEWNET | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID)
	attr := &syscall.SysProcAttr{Cloneflags: flags, Pdeathsig: syscall.SIGKILL}
	if os.Geteuid() != 0 {
		attr.Cloneflags |= syscall.CLONE_NEWUSER
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
		attr.GidMappingsEnableSetgroups = false
	}
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		w.Close()
		r.Close()
		return nil, fmt.Errorf("could not create the sandbox namespaces (%v). On Ubuntu 23.10+ unprivileged user namespaces are restricted by AppArmor: run with sudo -E, or set kernel.apparmor_restrict_unprivileged_userns=0", err)
	}
	w.Close()
	out, _ := io.ReadAll(r)
	r.Close()
	waitErr := cmd.Wait()
	var res Result
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("sandbox child failed (%v); no results", waitErr)
	}
	return &res, nil
}

// Child runs inside the namespaces. It never returns.
func Child() {
	res := &Result{}
	results := os.NewFile(3, "results")
	finish := func(code int) {
		_ = json.NewEncoder(results).Encode(res)
		results.Close()
		os.Exit(code)
	}
	var cfg childConfig
	if err := json.Unmarshal([]byte(os.Getenv(configEnv)), &cfg); err != nil {
		res.Notes = append(res.Notes, "bad config: "+err.Error())
		finish(2)
	}
	rec := NewRecorder(cfg.Honey)
	note := func(f string, a ...any) { res.Notes = append(res.Notes, fmt.Sprintf(f, a...)) }

	// Mounts are private to this namespace from here on.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		note("mount namespace unavailable: %v", err)
		finish(2)
	}
	_ = syscall.Mount("proc", "/proc", "proc", 0, "")

	work, err := os.MkdirTemp("", "tfcap-sandbox-")
	if err != nil {
		note("temp dir: %v", err)
		finish(2)
	}
	_ = syscall.Mount("tmpfs", work, "tmpfs", 0, "mode=0700")
	home := filepath.Join(work, "home")
	if err := cfg.Honey.Write(home); err != nil {
		note("honeytokens: %v", err)
		finish(2)
	}
	maskCredentials(home, note)

	resolv := filepath.Join(work, "resolv.conf")
	_ = os.WriteFile(resolv, []byte("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n"), 0o644)
	if err := syscall.Mount(resolv, "/etc/resolv.conf", "", syscall.MS_BIND, ""); err != nil {
		note("could not redirect DNS: %v", err)
	}

	if err := loUp(); err != nil {
		note("loopback: %v", err)
		finish(2)
	}
	if err := routeAllLocal(); err != nil {
		note("could not route all addresses to the sandbox (%v); connections to raw IPs are not recorded", err)
	}
	if pc, err := net.ListenPacket("udp", "0.0.0.0:53"); err == nil {
		go ServeDNS(pc, rec)
	} else {
		note("DNS listener: %v", err)
	}
	for _, p := range listenPorts {
		if l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p)); err == nil {
			go ServeTCP(l, p, rec)
		}
	}

	env := sandboxEnv(home, cfg.Honey)
	argv := cfg.Command
	straceLog := filepath.Join(work, "strace.log")
	if sp, err := exec.LookPath("strace"); err == nil {
		argv = append([]string{sp, "-f", "-qq", "-s", "300", "-e", "trace=execve,openat,open,clone,clone3,fork,vfork", "-o", straceLog, "--"}, argv...)
		res.Strace = true
	} else {
		note("strace not found: programs run and files opened are not recorded (install strace for full coverage)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir, cmd.Env = cfg.Dir, env
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case ctx.Err() != nil:
		res.TimedOut = true
		res.ExitCode = -1
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	case err != nil:
		note("could not run %s: %v", cfg.Command[0], err)
		res.ExitCode = -1
	}
	time.Sleep(300 * time.Millisecond) // let listeners finish recording
	if res.Strace {
		parseStrace(straceLog, home, rec)
	}
	res.Events = rec.Events()
	finish(0)
}

// listenPorts are the TCP ports with a recording listener. Connections to
// other ports are refused and not recorded.
var listenPorts = []int{21, 22, 23, 25, 80, 443, 1080, 1337, 2375, 3128, 4444, 5000, 5555, 6379, 6667, 8000, 8080, 8443, 8888, 9000, 9001}

// credentialPaths under the real home are hidden behind the decoys (or an
// empty tmpfs / /dev/null), so absolute paths cannot reach real secrets.
var credentialPaths = []string{".aws", ".ssh", ".kube", ".docker", ".config/gcloud", ".azure", ".gnupg", ".config/gh",
	".git-credentials", ".netrc", ".npmrc", ".pypirc", ".vault-token", ".terraform.d/credentials.tfrc.json", ".terraformrc", ".oci"}

func maskCredentials(honeyHome string, note func(string, ...any)) {
	homes := map[string]bool{}
	if h, err := os.UserHomeDir(); err == nil {
		homes[h] = true
	}
	homes["/root"] = true
	for h := range homes {
		for _, rel := range credentialPaths {
			real := filepath.Join(h, filepath.FromSlash(rel))
			st, err := os.Lstat(real)
			if err != nil {
				continue
			}
			decoy := filepath.Join(honeyHome, filepath.FromSlash(rel))
			if _, err := os.Stat(decoy); err != nil {
				if st.IsDir() {
					decoy = ""
				} else {
					decoy = "/dev/null"
				}
			}
			if decoy == "" {
				err = syscall.Mount("tmpfs", real, "tmpfs", 0, "mode=0700")
			} else {
				err = syscall.Mount(decoy, real, "", syscall.MS_BIND, "")
			}
			if err != nil {
				note("could not hide %s: %v", real, err)
			}
		}
	}
}

var secretEnvRe = regexp.MustCompile(`(?i)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|_KEY$|_KEY_|PRIVATE|SESSION|AUTH|COOKIE)`)

func sandboxEnv(home string, h *Honey) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if secretEnvRe.MatchString(k) || strings.HasPrefix(k, "TFCAP_SANDBOX") || k == "HOME" ||
			strings.HasSuffix(strings.ToUpper(k), "_PROXY") || strings.HasPrefix(k, "TF_TOKEN_") || strings.HasPrefix(k, "AWS_") ||
			strings.HasPrefix(k, "ARM_") || strings.HasPrefix(k, "GOOGLE_") || strings.HasPrefix(k, "ACTIONS_") {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range h.Env {
		env = append(env, k+"="+v)
	}
	proxy := "http://127.0.0.1:8080"
	return append(env, "HOME="+home, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "http_proxy="+proxy, "https_proxy="+proxy,
		"ALL_PROXY="+proxy, "NO_PROXY=", "no_proxy=", "CHECKPOINT_DISABLE=1", "TF_IN_AUTOMATION=1", "TF_INPUT=0")
}

var (
	straceExecRe = regexp.MustCompile(`^(\d+)\s+execve\("([^"]*)", \[(.*)\], .*\)\s+=\s+0`)
	straceOpenRe = regexp.MustCompile(`^(\d+)\s+open(?:at)?\((?:[A-Z_]+, )?"([^"]*)", ([A-Z_|]+).*\)\s+=\s+\d+`)
	straceArgRe  = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	// "123 clone(...) = 456", "123 vfork() = 456", "123 clone3({...}, 88) = 456"
	straceCloneRe = regexp.MustCompile(`^(\d+)\s+(?:clone3?|v?fork)\(.*\)\s+=\s+(\d+)$`)
)

// parseStrace turns execve and successful opens of decoy files into
// events. Programs started by another non-Terraform program are folded
// into the first one, so a script shows up once with what it ran.
func parseStrace(path, home string, rec *Recorder) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	exe := map[string]string{}    // pid -> program
	parent := map[string]string{} // pid -> parent pid
	decoys := map[string]bool{}
	for rel := range rec.honey.Files {
		decoys[filepath.Join(home, filepath.FromSlash(rel))] = true
	}
	type run struct {
		prog, args string
		children   []string
		leak       bool
	}
	var tops []*run
	topOf := map[string]*run{} // pid -> top-level run it belongs to
	rootPid := ""
	for _, line := range joinResumed(strings.Split(string(b), "\n")) {
		if m := straceCloneRe.FindStringSubmatch(line); m != nil {
			parent[m[2]] = m[1]
			if t, ok := topOf[m[1]]; ok {
				topOf[m[2]] = t
			}
			if exe[m[2]] == "" {
				exe[m[2]] = exe[m[1]]
			}
			continue
		}
		if m := straceExecRe.FindStringSubmatch(line); m != nil {
			pid, prog := m[1], m[2]
			var args []string
			for _, a := range straceArgRe.FindAllStringSubmatch(m[3], -1) {
				if s, err := strconv.Unquote(`"` + a[1] + `"`); err == nil {
					args = append(args, s)
				} else {
					args = append(args, a[1])
				}
			}
			base := filepath.Base(prog)
			exe[pid] = base
			if rootPid == "" { // the command itself
				rootPid = pid
				continue
			}
			argStr := strings.Join(args, " ")
			if t, ok := topOf[pid]; ok && !expectedProc(base) {
				t.children = append(t.children, base)
				t.leak = t.leak || rec.honey.Leaks(argStr)
				continue
			}
			if expectedProc(base) {
				delete(topOf, pid)
				continue
			}
			r := &run{prog: prog, args: argStr, leak: rec.honey.Leaks(argStr)}
			tops = append(tops, r)
			topOf[pid] = r
			continue
		}
		if m := straceOpenRe.FindStringSubmatch(line); m != nil {
			p := m[2]
			if decoys[p] || strings.HasPrefix(p, home+"/") && isCredential(strings.TrimPrefix(p, home+"/")) {
				proc, detail := exe[m[1]], ""
				if t, ok := topOf[m[1]]; ok {
					proc, detail = filepath.Base(t.prog), t.args
				}
				rec.Add(Event{Kind: "open", Host: "~/" + strings.TrimPrefix(p, home+"/"), Proc: proc, Detail: detail})
			}
		}
	}
	for _, r := range tops {
		d := r.args
		if len(r.children) > 0 {
			d += "; then ran: " + strings.Join(dedupe(r.children), ", ")
		}
		rec.Add(Event{Kind: "exec", Host: r.prog, Detail: d, Proc: filepath.Base(r.prog), Leak: r.leak})
	}
}

var resumedRe = regexp.MustCompile(`^(\d+)\s+<\.\.\. \S+ resumed>(.*)$`)

// joinResumed stitches strace's "<unfinished ...>" / "<... resumed>"
// halves back into whole lines.
func joinResumed(lines []string) []string {
	pending := map[string]string{}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.HasSuffix(l, " <unfinished ...>") {
			pid, _, _ := strings.Cut(l, " ")
			pending[pid] = strings.TrimSuffix(l, " <unfinished ...>")
			continue
		}
		if m := resumedRe.FindStringSubmatch(l); m != nil {
			if head, ok := pending[m[1]]; ok {
				delete(pending, m[1])
				out = append(out, head+m[2])
				continue
			}
		}
		out = append(out, l)
	}
	return out
}

func dedupe(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func isCredential(rel string) bool {
	for _, c := range credentialPaths {
		if rel == c || strings.HasPrefix(rel, c+"/") {
			return true
		}
	}
	return false
}
