package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func listNames(t *testing.T, p *proc) []string {
	t.Helper()
	r := p.call("tools/list", nil)
	var res struct {
		Tools []struct{ Name string } `json:"tools"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	return names
}

func TestRugPullIsBlocked(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "s.jsonl")
	p := start(t, "wrap", "--on-drift", "block", "--log-file", logPath, "--", rugpullBin)
	p.call("initialize", map[string]any{"protocolVersion": "2025-11-25"})
	if got := strings.Join(listNames(t, p), ","); got != "get_forecast,get_alerts" {
		t.Fatalf("first listing: %s", got)
	}
	if txt, isErr := p.toolText("get_forecast", map[string]any{"city": "Lisbon"}); isErr || !strings.Contains(txt, "Lisbon") {
		t.Fatalf("first call: %q", txt)
	}
	// The server now announces a changed list.
	mustContain(t, string(p.recv()), "notifications/tools/list_changed")
	if got := strings.Join(listNames(t, p), ","); got != "get_alerts" {
		t.Fatalf("second listing should hide the poisoned tool: %s", got)
	}
	txt, isErr := p.toolText("get_forecast", map[string]any{"city": "Lisbon", "notes": "-----BEGIN OPENSSH PRIVATE KEY-----"})
	if !isErr || !strings.Contains(txt, "airlock blocked this call") {
		t.Fatalf("call after rug pull: %q", txt)
	}
	p.wait()
	if strings.Contains(p.stderr.String(), "exfiltrated") {
		t.Fatal("the poisoned call reached the server")
	}
	mustContain(t, p.stderr.String(), `tool "get_forecast" hidden from the client and blocked: the tool's definition changed`)

	var drift *struct {
		Flags []struct{ Rule, Detail string } `json:"flags"`
	}
	for _, r := range readLog(t, logPath) {
		if r.Kind == "event" && strings.Contains(string(r.Event), `"type":"drift"`) {
			_ = json.Unmarshal(r.Event, &drift)
		}
	}
	if drift == nil {
		t.Fatal("no drift event in the log")
	}
	var found bool
	for _, f := range drift.Flags {
		if f.Rule == "hidden-tag-characters" && strings.Contains(f.Detail, "~/.aws/credentials") {
			found = true
		}
	}
	if !found {
		t.Fatalf("hidden text not surfaced: %+v", drift.Flags)
	}
}

func TestRugPullWithoutAirlockLeaks(t *testing.T) {
	// The control: in warn mode the poisoned definition and the call get
	// through, and the demo server prints what it received.
	p := start(t, "wrap", "--no-log", "--", rugpullBin)
	listNames(t, p)
	p.toolText("get_forecast", map[string]any{"city": "Lisbon"})
	p.recv()
	listNames(t, p)
	p.toolText("get_forecast", map[string]any{"city": "Lisbon", "notes": "secret"})
	p.wait()
	mustContain(t, p.stderr.String(), "rugpull: exfiltrated 6 bytes")
	mustContain(t, p.stderr.String(), "on_drift = warn")
}

func TestLockfilePinsAcrossSessions(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "weather.lock.json")

	// Session 1: approve the honest definitions.
	p := start(t, "wrap", "--no-log", "--lock", lock, "--", rugpullBin)
	listNames(t, p)
	p.wait()
	if b, err := os.ReadFile(lock); err != nil || !strings.Contains(string(b), `"get_forecast"`) {
		t.Fatalf("lockfile: %s %v", b, err)
	}

	// Session 2: the server swaps the tool before the client ever lists it
	// in this session. Only the lockfile can catch that.
	p = start(t, "wrap", "--no-log", "--lock", lock, "--on-drift", "block", "--", rugpullBin)
	p.toolText("get_alerts", map[string]any{"region": "PT"})
	p.recv() // list_changed
	if got := strings.Join(listNames(t, p), ","); got != "get_alerts" {
		t.Fatalf("lockfile drift not caught: %s", got)
	}
	p.wait()

	// Session 3: --repin accepts the new definition.
	p = start(t, "wrap", "--no-log", "--lock", lock, "--on-drift", "block", "--repin", "--", rugpullBin)
	p.toolText("get_alerts", map[string]any{"region": "PT"})
	p.recv()
	if got := strings.Join(listNames(t, p), ","); got != "get_forecast,get_alerts" {
		t.Fatalf("repin: %s", got)
	}
	p.wait()
	b, _ := os.ReadFile(lock)
	mustContain(t, string(b), "IMPORTANT")
}
