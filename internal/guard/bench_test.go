package guard

import (
	"io"
	"testing"

	"github.com/AutumnTrace/airlock/internal/audit"
	"github.com/AutumnTrace/airlock/internal/policy"
)

// BenchmarkGuard measures airlock's own work for one tools/call round trip
// (request in, response out), without any pipes: parsing, the policy, the
// schema check, redaction scanning and writing three log records.
func BenchmarkGuard(b *testing.B) {
	list := `{"jsonrpc":"2.0","id":0,"result":{"tools":[{"name":"read_file","description":"Read a file.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"head":{"type":"integer"}},"required":["path"],"additionalProperties":false}}]}}`
	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/work/src/main.go"}}}`)
	resp := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n"}]}}`)
	pol, err := policy.Parse([]byte(`
default = "deny"
[[rule]]
tools = ["read_file"]
action = "allow"
args.path.prefix = ["/work"]
`))
	if err != nil {
		b.Fatal(err)
	}
	for _, c := range []struct {
		name string
		log  bool
		pol  *policy.Policy
	}{
		{"record-only", true, nil},
		{"policy-no-log", false, pol},
		{"policy-and-log", true, pol},
	} {
		b.Run(c.name, func(b *testing.B) {
			var rec Recorder
			if c.log {
				w, err := audit.NewWriter(io.Discard, audit.Header{Airlock: "bench"}, audit.Options{})
				if err != nil {
					b.Fatal(err)
				}
				rec = w
			}
			g := New(rec, Options{Policy: c.pol})
			g.FromClient([]byte(`{"jsonrpc":"2.0","id":0,"method":"tools/list"}`))
			g.FromServer([]byte(list))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if act := g.FromClient(req); len(act.Forward) != 1 {
					b.Fatal("blocked")
				}
				g.FromServer(resp)
			}
		})
	}
}
