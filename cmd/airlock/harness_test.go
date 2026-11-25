package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Binaries built once for the whole package.
var (
	airlockBin string
	fakeBin    string
	rugpullBin string
)

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "airlock-it-")
	if err != nil {
		panic(err)
	}
	build := func(out, pkg string) string {
		p := filepath.Join(dir, exe(out))
		cmd := exec.Command("go", "build", "-o", p, pkg)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			panic(fmt.Sprintf("building %s: %v", pkg, err))
		}
		return p
	}
	airlockBin = build("airlock", "github.com/AutumnTrace/airlock/cmd/airlock")
	fakeBin = build("fakemcp", "github.com/AutumnTrace/airlock/internal/fakemcp")
	if _, err := os.Stat("../../examples/rugpull"); err == nil {
		rugpullBin = build("rugpull", "github.com/AutumnTrace/airlock/examples/rugpull")
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// proc is a running airlock wrap, driven the way an MCP client drives it.
type proc struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan []byte
	stderr *lockedBuf
	nextID int
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func start(t *testing.T, args ...string) *proc {
	t.Helper()
	cmd := exec.Command(airlockBin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &proc{t: t, cmd: cmd, stdin: stdin, lines: make(chan []byte, 64), stderr: &lockedBuf{}}
	cmd.Stderr = p.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		br := bufio.NewReaderSize(stdout, 1<<20)
		for {
			line, err := br.ReadBytes('\n')
			if len(line) > 0 {
				p.lines <- bytes.TrimRight(line, "\r\n")
			}
			if err != nil {
				close(p.lines)
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = stdin.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
	})
	return p
}

func (p *proc) send(frame string) {
	p.t.Helper()
	if _, err := io.WriteString(p.stdin, frame+"\n"); err != nil {
		p.t.Fatalf("write: %v", err)
	}
}

// request sends a request with a fresh numeric id and returns that id.
func (p *proc) request(method string, params any) int {
	p.t.Helper()
	p.nextID++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": p.nextID, "method": method, "params": params})
	p.send(string(b))
	return p.nextID
}

func (p *proc) recv() []byte {
	p.t.Helper()
	select {
	case line, ok := <-p.lines:
		if !ok {
			p.t.Fatalf("stdout closed; stderr:\n%s", p.stderr.String())
		}
		return line
	case <-time.After(10 * time.Second):
		p.t.Fatalf("timed out waiting for a frame; stderr:\n%s", p.stderr.String())
	}
	return nil
}

type response struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (p *proc) call(method string, params any) response {
	p.t.Helper()
	id := p.request(method, params)
	var r response
	if err := json.Unmarshal(p.recv(), &r); err != nil {
		p.t.Fatal(err)
	}
	if string(r.ID) != fmt.Sprint(id) {
		p.t.Fatalf("response id %s, want %d", r.ID, id)
	}
	return r
}

// toolText calls a tool and returns the first text item and isError.
func (p *proc) toolText(name string, args any) (string, bool) {
	p.t.Helper()
	r := p.call("tools/call", map[string]any{"name": name, "arguments": args})
	if r.Error != nil {
		p.t.Fatalf("tools/call %s: JSON-RPC error %d %s", name, r.Error.Code, r.Error.Message)
	}
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	_ = json.Unmarshal(r.Result, &res)
	if len(res.Content) == 0 {
		return "", res.IsError
	}
	return res.Content[0].Text, res.IsError
}

func (p *proc) wait() int {
	p.t.Helper()
	_ = p.stdin.Close()
	for range p.lines {
	}
	err := p.cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	} else if err != nil {
		p.t.Fatal(err)
	}
	return 0
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("%q does not contain %q", haystack, needle)
	}
}
