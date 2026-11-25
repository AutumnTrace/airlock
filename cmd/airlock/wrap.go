package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AutumnTrace/airlock/internal/audit"
	"github.com/AutumnTrace/airlock/internal/guard"
	"github.com/AutumnTrace/airlock/internal/pin"
	"github.com/AutumnTrace/airlock/internal/policy"
	"github.com/AutumnTrace/airlock/internal/proxy"
)

func cmdWrap(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	logDir := fs.String("log", "", "directory for session logs (default ~/.airlock/logs, or $AIRLOCK_LOG_DIR)")
	logFile := fs.String("log-file", "", "write the session log to exactly this file instead")
	noLog := fs.Bool("no-log", false, "do not write a session log")
	signKey := fs.String("sign-key", "", "Ed25519 private key (from airlock keygen) used to sign checkpoints")
	every := fs.Int("checkpoint-every", 256, "records between signed checkpoints")
	quiet := fs.Bool("quiet", false, "do not print the log path and chain head on exit")
	lockPath := fs.String("lock", "", "lockfile for tool pins (default: pins last for this session only)")
	onDrift := fs.String("on-drift", guard.Warn, "what to do when a tool's definition changes: warn or block")
	repin := fs.Bool("repin", false, "accept the server's current tool definitions as the new pins")
	policyPath := fs.String("policy", "", "TOML policy file (see examples/policies)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: airlock wrap [flags] -- <server command> [args...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fs.Usage()
		return 2
	}
	warn := func(msg string) { fmt.Fprintln(stderr, "airlock: "+msg) }
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	gopt := guard.Options{Repin: *repin, Warn: warn}
	var pol *policy.Policy
	if *policyPath != "" {
		var err error
		if pol, err = policy.Load(*policyPath); err != nil {
			warn(err.Error())
			return 2
		}
		gopt.Policy = pol
		gopt.OnDrift = pol.Pinning.OnDrift
		gopt.OnNewTool = pol.Pinning.OnNewTool
		gopt.OnSuspicious = pol.Pinning.OnSuspicious
		if !set["lock"] {
			*lockPath = pol.Pinning.Lockfile
		}
	}
	if set["on-drift"] || pol == nil {
		gopt.OnDrift = *onDrift
	}
	if gopt.OnDrift != guard.Warn && gopt.OnDrift != guard.Block {
		warn(fmt.Sprintf("--on-drift must be warn or block, not %q", gopt.OnDrift))
		return 2
	}
	pins, err := pin.Load(*lockPath)
	if err != nil {
		warn(err.Error())
		return 2
	}
	gopt.Pins = pins
	opts := audit.Options{CheckpointEvery: *every}
	if *signKey != "" {
		k, err := audit.LoadPrivateKey(*signKey)
		if err != nil {
			warn(err.Error())
			return 2
		}
		opts.Key = k
	}

	child, err := proxy.Start(argv)
	if err != nil {
		warn(fmt.Sprintf("cannot start %s: %v", argv[0], err))
		return 127
	}
	stop := child.ForwardSignals()
	defer stop()

	var log *audit.Writer
	if !*noLog {
		path := *logFile
		if path == "" {
			dir := *logDir
			if dir == "" {
				dir = defaultLogDir()
			}
			path = filepath.Join(dir, logName(argv, child.PID(), time.Now()))
		}
		cwd, _ := os.Getwd()
		hdr := audit.Header{
			Airlock:  buildVersion(),
			Command:  argv,
			Dir:      cwd,
			PID:      child.PID(),
			Lockfile: pins.Path(),
		}
		if pol != nil {
			hdr.Policy, hdr.PolicyHash = pol.Path, pol.Hash
		}
		log, err = audit.Create(path, hdr, opts)
		if err != nil {
			// A broken log directory must not take the server down with it.
			warn(fmt.Sprintf("not recording this session: %v", err))
			log = nil
		}
	}

	var rec guard.Recorder
	if log != nil {
		rec = log
	}
	g := guard.New(rec, gopt)
	err = proxy.Run(proxy.Pipes{
		ClientIn:  stdin,
		ClientOut: stdout,
		ServerIn:  child.Stdin,
		ServerOut: child.Stdout,
		ServerErr: child.Stderr,
		ErrOut:    stderr,
	}, g)
	code := child.Wait()
	if err != nil {
		warn(err.Error())
	}
	if log != nil {
		head, lerr := log.Close(code)
		switch {
		case lerr != nil:
			warn(fmt.Sprintf("session log %s is incomplete: %v", log.Path, lerr))
		case !*quiet:
			warn(fmt.Sprintf("session log %s (head %s)", log.Path, head[:16]))
		}
	}
	return code
}

func defaultLogDir() string {
	if d := os.Getenv("AIRLOCK_LOG_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".airlock/logs"
	}
	return filepath.Join(home, ".airlock", "logs")
}

// launchers are commands whose first non-flag argument names the server.
var launchers = map[string]bool{
	"npx": true, "uvx": true, "bunx": true, "pnpx": true, "node": true, "deno": true,
	"python": true, "python3": true, "uv": true, "docker": true, "podman": true, "go": true, "cmd": true,
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// logName picks a file name like 20261125T101500Z-server-filesystem-4242.jsonl,
// skipping launchers (npx, uvx, docker run, cmd /c ...) to find the part of
// the command line that names the server.
func logName(argv []string, pid int, now time.Time) string {
	name := "server"
	for _, a := range argv {
		base := a
		if i := strings.LastIndexAny(base, `/\`); i >= 0 && i < len(base)-1 {
			base = base[i+1:]
		}
		base = strings.TrimSuffix(base, filepath.Ext(base))
		if i := strings.Index(base, "@"); i > 0 {
			base = base[:i]
		}
		if a == "" || strings.HasPrefix(a, "-") || strings.EqualFold(a, "/c") || a == "run" || a == "tool" || launchers[strings.ToLower(base)] {
			continue
		}
		name = base
		break
	}
	name = strings.Trim(unsafeName.ReplaceAllString(name, "-"), "-")
	if name == "" {
		name = "server"
	}
	return fmt.Sprintf("%s-%s-%d.jsonl", now.UTC().Format("20060102T150405Z"), name, pid)
}
