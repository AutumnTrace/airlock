package proxy

import (
	"bufio"
	"io"
	"strings"
	"sync"
	"testing"
)

// upper is a handler that answers "ping" itself and upper-cases everything
// the server says. Its methods run on different goroutines, as in airlock.
type upper struct {
	mu     sync.Mutex
	stderr []string
}

func (*upper) FromClient(f []byte) Action {
	if string(f) == "ping" {
		return Action{Reply: [][]byte{[]byte("pong")}}
	}
	return Pass(f)
}
func (*upper) FromServer(f []byte) Action {
	return Pass([]byte(strings.ToUpper(string(f))))
}
func (u *upper) Stderr(l []byte) {
	u.mu.Lock()
	u.stderr = append(u.stderr, string(l))
	u.mu.Unlock()
}

func TestRunRoutesActions(t *testing.T) {
	clientR, clientW := io.Pipe() // client -> proxy
	outR, outW := io.Pipe()       // proxy -> client
	srvInR, srvInW := io.Pipe()   // proxy -> server
	srvOutR, srvOutW := io.Pipe() // server -> proxy
	errR, errW := io.Pipe()

	// The "server" echoes each line it gets, then closes on EOF.
	go func() {
		br := bufio.NewReader(srvInR)
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				io.WriteString(srvOutW, "echo "+line)
			}
			if err != nil {
				errW.Write([]byte("server: bye\n"))
				errW.Close()
				srvOutW.Close()
				return
			}
		}
	}()

	h := &upper{}
	var stderrCopy strings.Builder
	done := make(chan error, 1)
	go func() {
		err := Run(Pipes{ClientIn: clientR, ClientOut: outW, ServerIn: srvInW, ServerOut: srvOutR, ServerErr: errR, ErrOut: &stderrCopy}, h)
		outW.Close()
		done <- err
	}()

	go func() {
		io.WriteString(clientW, "hello\nping\nworld\n")
		clientW.Close()
	}()

	out, _ := io.ReadAll(outR)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{"pong\n", "ECHO HELLO\n", "ECHO WORLD\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "PING") {
		t.Errorf("ping reached the server: %q", got)
	}
	if len(h.stderr) != 1 || h.stderr[0] != "server: bye" || stderrCopy.String() != "server: bye\n" {
		t.Errorf("stderr: %q / %q", h.stderr, stderrCopy.String())
	}
}
