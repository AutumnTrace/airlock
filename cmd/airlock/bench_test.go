package main

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// roundTripper drives one server process with sequential tools/call
// requests, the way an agent does.
type roundTripper struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

func startRT(b *testing.B, argv ...string) *roundTripper {
	b.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		b.Fatal(err)
	}
	rt := &roundTripper{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<20)}
	rt.do(b, `{"jsonrpc":"2.0","id":0,"method":"tools/list"}`) // warm up, and let airlock pin
	return rt
}

func (rt *roundTripper) do(b *testing.B, frame string) {
	if _, err := io.WriteString(rt.in, frame+"\n"); err != nil {
		b.Fatal(err)
	}
	if _, err := rt.out.ReadBytes('\n'); err != nil {
		b.Fatal(err)
	}
}

func (rt *roundTripper) stop() {
	rt.in.Close()
	_ = rt.cmd.Wait()
}

const benchPolicy = `
default = "deny"
[[rule]]
tools = ["echo", "big", "read_file"]
action = "allow"
[[rule]]
tools = ["write_file"]
action = "allow"
args.path.prefix = ["/work"]
`

// BenchmarkRoundTrip measures one tools/call round trip between two
// processes, with and without airlock in the middle. The difference is
// airlock's cost per call: two extra pipe hops plus whatever it does.
func BenchmarkRoundTrip(b *testing.B) {
	dir := b.TempDir()
	pol := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(pol, []byte(benchPolicy), 0o600); err != nil {
		b.Fatal(err)
	}
	key := filepath.Join(dir, "k.pem")
	if code, out := runCLI("keygen", "-o", key); code != 0 {
		b.Fatal(out)
	}
	logf := func(name string) string { return filepath.Join(dir, name+".jsonl") }

	small := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello from the benchmark"}}}`
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"big","arguments":{"n":65536}}}`

	setups := []struct {
		name string
		argv []string
	}{
		{"direct", []string{fakeBin}},
		{"airlock-nolog", []string{airlockBin, "wrap", "--no-log", "--", fakeBin}},
		{"airlock-log", []string{airlockBin, "wrap", "--log-file", logf("log"), "--", fakeBin}},
		{"airlock-log-signed", []string{airlockBin, "wrap", "--log-file", logf("signed"), "--sign-key", key, "--", fakeBin}},
		{"airlock-policy-log", []string{airlockBin, "wrap", "--policy", pol, "--log-file", logf("policy"), "--", fakeBin}},
	}
	for _, payload := range []struct{ name, frame string }{{"small", small}, {"64KiB-result", big}} {
		for _, s := range setups {
			b.Run(payload.name+"/"+s.name, func(b *testing.B) {
				for _, f := range []string{"log", "signed", "policy"} {
					os.Remove(logf(f))
				}
				rt := startRT(b, s.argv...)
				defer rt.stop()
				b.ResetTimer()
				for b.Loop() {
					rt.do(b, payload.frame)
				}
			})
		}
	}
}
