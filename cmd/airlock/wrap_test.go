package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWrapIsTransparent(t *testing.T) {
	p := start(t, "wrap", "--", fakeBin)
	r := p.call("initialize", map[string]any{"protocolVersion": "2025-11-25"})
	mustContain(t, string(r.Result), `"fakemcp"`)
	p.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	r = p.call("tools/list", map[string]any{})
	var list struct {
		Tools []struct{ Name string } `json:"tools"`
	}
	if err := json.Unmarshal(r.Result, &list); err != nil || len(list.Tools) != 5 {
		t.Fatalf("tools/list: %s (%v)", r.Result, err)
	}
	if got, _ := p.toolText("echo", map[string]any{"text": "hello"}); got != "hello" {
		t.Fatalf("echo returned %q", got)
	}
	if code := p.wait(); code != 0 {
		t.Fatalf("exit code %d", code)
	}
}

func TestWrapPassesExitCodeThrough(t *testing.T) {
	p := start(t, "wrap", "--", fakeBin, "-exit", "7")
	p.call("server/discover", nil)
	if code := p.wait(); code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
}

func TestWrapServerCrash(t *testing.T) {
	p := start(t, "wrap", "--", fakeBin)
	p.request("crash", nil)
	for range p.lines {
	}
	if code := p.wait(); code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
}

func TestWrapCopiesStderr(t *testing.T) {
	p := start(t, "wrap", "--", fakeBin, "-stderr")
	p.call("server/discover", nil)
	p.wait()
	mustContain(t, p.stderr.String(), "fakemcp: starting")
	mustContain(t, p.stderr.String(), "stdin closed, bye")
}

func TestWrapForwardsMalformedFrames(t *testing.T) {
	p := start(t, "wrap", "--", fakeBin, "-garbage")
	p.send(`this is not json`)
	// The server answers the bad line with a parse error, and first prints
	// a garbage line of its own. Both must reach the client.
	if got := string(p.recv()); got != "this line is not JSON" {
		t.Fatalf("got %q", got)
	}
	mustContain(t, string(p.recv()), "-32700")
	r := p.call("server/discover", nil)
	mustContain(t, string(r.Result), "2026-07-28")
	p.wait()
}

func TestWrapLargeFrame(t *testing.T) {
	p := start(t, "wrap", "--", fakeBin)
	got, _ := p.toolText("big", map[string]any{"n": 4 << 20})
	if len(got) != 4<<20 || strings.Trim(got, "x") != "" {
		t.Fatalf("big frame came back as %d bytes", len(got))
	}
	p.wait()
}

func TestWrapMissingCommand(t *testing.T) {
	p := start(t, "wrap", "--", "definitely-not-a-real-command-xyz")
	if code := p.wait(); code != 127 {
		t.Fatalf("exit code %d, want 127", code)
	}
	mustContain(t, p.stderr.String(), "cannot start")
}
