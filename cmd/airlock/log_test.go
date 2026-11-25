package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AutumnTrace/airlock/internal/audit"
)

func readLog(t *testing.T, path string) []audit.Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recs, err := audit.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestWrapRecordsTheSession(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "s.jsonl")
	p := start(t, "wrap", "--log-file", logPath, "--", fakeBin, "-stderr")
	p.call("server/discover", nil)
	p.toolText("echo", map[string]any{"text": "hi"})
	p.send("garbage line")
	p.recv() // the server's parse error
	if code := p.wait(); code != 0 {
		t.Fatal(code)
	}
	mustContain(t, p.stderr.String(), "session log "+logPath)

	recs := readLog(t, logPath)
	var kinds, msgs []string
	for _, r := range recs {
		kinds = append(kinds, r.Kind)
		if r.Kind == audit.KindMsg {
			msgs = append(msgs, r.Dir)
		}
	}
	if got := strings.Join(msgs, " "); got != "c2s s2c c2s s2c c2s s2c" {
		t.Fatalf("message directions %q", got)
	}
	got := strings.Join(kinds, " ")
	for _, want := range []string{"open ", "stderr", " close"} {
		if !strings.Contains(got, want) {
			t.Fatalf("record kinds %q missing %q", got, want)
		}
	}
	if recs[0].Session == nil || recs[0].Session.PID == 0 || filepath.Base(recs[0].Session.Command[0]) != filepath.Base(fakeBin) {
		t.Fatalf("header: %+v", recs[0].Session)
	}
	f, _ := os.Open(logPath)
	defer f.Close()
	rep, err := audit.Verify(f, nil)
	if err != nil || !rep.OK() || !rep.Closed {
		t.Fatalf("%+v %v", rep, err)
	}
}

func runCLI(args ...string) (int, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(""), &out, &errb)
	return code, out.String() + errb.String()
}

func TestSignAndVerifyCLI(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "airlock.key")
	code, out := runCLI("keygen", "-o", key)
	if code != 0 {
		t.Fatal(out)
	}
	pub := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if !strings.HasPrefix(pub, "ed25519:") {
		t.Fatalf("keygen printed %q", out)
	}

	logPath := filepath.Join(dir, "s.jsonl")
	p := start(t, "wrap", "--log-file", logPath, "--sign-key", key, "--checkpoint-every", "2", "--", fakeBin)
	for range 3 {
		p.toolText("echo", map[string]any{"text": "hi"})
	}
	p.wait()

	if code, out := runCLI("verify", "--pubkey", pub, logPath); code != 0 || !strings.Contains(out, "ok, ") {
		t.Fatalf("verify: %d\n%s", code, out)
	}

	// Flip one byte inside a recorded message.
	b, _ := os.ReadFile(logPath)
	b = bytes.Replace(b, []byte(`"text":"hi"`), []byte(`"text":"ho"`), 1)
	tampered := filepath.Join(dir, "tampered.jsonl")
	os.WriteFile(tampered, b, 0o600)
	if code, out := runCLI("verify", tampered); code != 1 || !strings.Contains(out, "hash mismatch") {
		t.Fatalf("verify tampered: %d\n%s", code, out)
	}
}

func TestVerifyHeadCatchesTruncation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "s.jsonl")
	p := start(t, "wrap", "--log-file", logPath, "--", fakeBin)
	p.toolText("echo", map[string]any{"text": "hi"})
	p.wait()
	line := p.stderr.String()
	i := strings.Index(line, "(head ")
	if i < 0 {
		t.Fatalf("no head in %q", line)
	}
	head := line[i+6 : i+6+16]

	b, _ := os.ReadFile(logPath)
	lines := strings.SplitAfter(string(b), "\n")
	short := filepath.Join(dir, "short.jsonl")
	os.WriteFile(short, []byte(strings.Join(lines[:len(lines)-3], "")), 0o600)
	if code, out := runCLI("verify", "--head", head, logPath); code != 0 {
		t.Fatalf("intact log with head: %d\n%s", code, out)
	}
	if code, out := runCLI("verify", "--head", head, short); code != 1 || !strings.Contains(out, "expected") {
		t.Fatalf("truncated log with head: %d\n%s", code, out)
	}
}

func TestLogName(t *testing.T) {
	now := time.Date(2026, 11, 25, 10, 15, 0, 0, time.UTC)
	cases := map[string][]string{
		"server-filesystem": {"npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"},
		"mcp-server-git":    {"uvx", "mcp-server-git", "--repository", "."},
		"github-mcp-server": {"docker", "run", "-i", "--rm", "ghcr.io/github/github-mcp-server"},
		"weather":           {"cmd", "/c", "npx", "weather@1.2.0"},
		"fakemcp":           {`C:\tools\fakemcp.exe`},
	}
	for want, argv := range cases {
		got := logName(argv, 42, now)
		if got != "20261125T101500Z-"+want+"-42.jsonl" {
			t.Errorf("logName(%q) = %s", argv, got)
		}
	}
}
