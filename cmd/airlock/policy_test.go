package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPolicy = `
default = "deny"

[schema]
validate = true

[[rule]]
tools = ["echo", "env", "big"]
action = "allow"

[[rule]]
tools = ["read_file"]
action = "allow"
args.path.prefix = ["/work"]

[[rule]]
tools = ["write_file"]
action = "allow"
rate = "2/min"
args.path.prefix = ["/work/out"]
`

func startWithPolicy(t *testing.T, src string, extra ...string) (*proc, string) {
	t.Helper()
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(pol, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "s.jsonl")
	args := append([]string{"wrap", "--policy", pol, "--log-file", logPath}, extra...)
	p := start(t, append(args, "--", fakeBin)...)
	return p, logPath
}

func TestPolicyEnforcement(t *testing.T) {
	p, logPath := startWithPolicy(t, testPolicy)
	p.call("initialize", map[string]any{"protocolVersion": "2025-11-25"})
	listNames(t, p)

	allowed := func(tool string, args map[string]any) string {
		t.Helper()
		txt, isErr := p.toolText(tool, args)
		if isErr {
			t.Fatalf("%s %v was blocked: %s", tool, args, txt)
		}
		return txt
	}
	blocked := func(tool string, args map[string]any, why string) {
		t.Helper()
		txt, isErr := p.toolText(tool, args)
		if !isErr || !strings.Contains(txt, "airlock blocked this call") || !strings.Contains(txt, why) {
			t.Fatalf("%s %v: isError=%v %q, want a block mentioning %q", tool, args, isErr, txt, why)
		}
	}

	allowed("echo", map[string]any{"text": "hi"})
	allowed("read_file", map[string]any{"path": "/work/notes.md"})
	blocked("read_file", map[string]any{"path": "/work/../etc/passwd"}, "outside /work")
	blocked("read_file", map[string]any{"path": "notes.md"}, "absolute path")
	blocked("write_file", map[string]any{"path": "/work/out/a"}, "content") // schema: required
	blocked("echo", map[string]any{"text": "hi", "exfil": "x"}, "exfil")    // schema: additionalProperties
	blocked("echo", map[string]any{"text": 42}, "/text")                    // schema: type
	blocked("nonexistent", map[string]any{}, "has not seen a definition")   // unknown tool
	allowed("write_file", map[string]any{"path": "/work/out/a", "content": "1"})
	allowed("write_file", map[string]any{"path": "/work/out/b", "content": "2"})
	blocked("write_file", map[string]any{"path": "/work/out/c", "content": "3"}, "rate limit of 2/min")

	env := allowed("env", nil)
	if strings.Contains(env, "AKIA") || !strings.Contains(env, "[redacted:aws-access-key-id]") || !strings.Contains(env, "REGION=eu-west-1") {
		t.Fatalf("env result: %q", env)
	}

	// A message with a repeated member is refused outright.
	p.send(`{"jsonrpc":"2.0","id":"dup","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/work/a"},"name":"write_file"}}`)
	var r response
	_ = json.Unmarshal(p.recv(), &r)
	if r.Error == nil || r.Error.Code != -32600 || !strings.Contains(r.Error.Message, `"name" appears twice`) {
		t.Fatalf("duplicate member: %+v", r)
	}

	// Under default = "deny", a line that is not JSON-RPC never reaches the
	// server (which would otherwise answer it with a parse error).
	p.send(`{"this is": "not json-rpc"}`)
	if got := p.call("server/discover", nil); got.Result == nil {
		t.Fatalf("discover after malformed: %+v", got)
	}

	p.wait()
	mustContain(t, p.stderr.String(), "redacted 3 secret(s) from the result of env")

	counts := map[string]int{}
	var raw string
	for _, rec := range readLog(t, logPath) {
		if rec.Kind == "event" {
			var ev struct{ Type, By string }
			_ = json.Unmarshal(rec.Event, &ev)
			counts[ev.Type+":"+ev.By]++
		}
		raw += string(rec.Msg)
	}
	want := map[string]int{"allow:rule": 5, "deny:args": 2, "deny:schema": 3, "deny:unknown-tool": 1, "deny:rate": 1, "redact:": 1, "malformed:": 2}
	for k, n := range want {
		if counts[k] != n {
			t.Errorf("%d %s events, want %d (all: %v)", counts[k], k, n, counts)
		}
	}
	if strings.Contains(raw, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("the secret reached the log")
	}
}

func TestPolicyFileErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.toml")
	os.WriteFile(bad, []byte("default_action = \"deny\"\n"), 0o600)
	p := start(t, "wrap", "--policy", bad, "--", fakeBin)
	if code := p.wait(); code != 2 {
		t.Fatalf("exit %d", code)
	}
	mustContain(t, p.stderr.String(), "unknown setting(s): default_action")
}

func TestCheckCommand(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "p.toml")
	os.WriteFile(pol, []byte(testPolicy), 0o600)
	if code, out := runCLI("check", pol); code != 0 || !strings.Contains(out, "3 rule(s), default deny") {
		t.Fatalf("%d %s", code, out)
	}
	if code, out := runCLI("check", pol, "read_file", `{"path":"/etc/passwd"}`); code != 1 || !strings.Contains(out, "outside /work") {
		t.Fatalf("%d %s", code, out)
	}
	if code, out := runCLI("check", pol, "echo"); code != 0 || !strings.Contains(out, "allow: rule 1") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestPolicyOnDriftFromFile(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "weather.toml")
	os.WriteFile(pol, []byte("[pinning]\non_drift = \"block\"\nlockfile = \"w.lock.json\"\n"), 0o600)
	p := start(t, "wrap", "--no-log", "--policy", pol, "--", rugpullBin)
	listNames(t, p)
	p.toolText("get_forecast", map[string]any{"city": "Porto"})
	p.recv()
	if got := strings.Join(listNames(t, p), ","); got != "get_alerts" {
		t.Fatalf("policy on_drift not applied: %s", got)
	}
	p.wait()
	// The lockfile path is relative to the policy file.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "w.lock.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lockfile not written next to the policy")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
