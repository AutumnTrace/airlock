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

	opts := audit.Options{CheckpointEvery: *every}
	if *signKey != "" {
		k, err := audit.LoadPrivateKey(*signKey)
		if err != nil {
			fmt.Fprintf(stderr, "airlock: %v\n", err)
			return 2
		}
		opts.Key = k
	}

	child, err := proxy.Start(argv)
	if err != nil {
		fmt.Fprintf(stderr, "airlock: cannot start %s: %v\n", argv[0], err)
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
		log, err = audit.Create(path, audit.Header{
			Airlock: buildVersion(),
			Command: argv,
			Dir:     cwd,
			PID:     child.PID(),
		}, opts)
		if err != nil {
			// A broken log directory must not take the server down with it.
			fmt.Fprintf(stderr, "airlock: not recording this session: %v\n", err)
			log = nil
		}
	}

	var rec guard.Recorder
	if log != nil {
		rec = log
	}
	err = proxy.Run(proxy.Pipes{
		ClientIn:  stdin,
		ClientOut: stdout,
		ServerIn:  child.Stdin,
		ServerOut: child.Stdout,
		ServerErr: child.Stderr,
		ErrOut:    stderr,
	}, guard.New(rec))
	code := child.Wait()
	if err != nil {
		fmt.Fprintf(stderr, "airlock: %v\n", err)
	}
	if log != nil {
		head, lerr := log.Close(code)
		switch {
		case lerr != nil:
			fmt.Fprintf(stderr, "airlock: session log %s is incomplete: %v\n", log.Path, lerr)
		case !*quiet:
			fmt.Fprintf(stderr, "airlock: session log %s (head %s)\n", log.Path, head[:16])
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
