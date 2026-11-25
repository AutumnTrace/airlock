package proxy

import (
	"errors"
	"io"
	"os"
	"os/exec"
)

// Child is the wrapped MCP server process.
type Child struct {
	cmd    *exec.Cmd
	Stdin  io.WriteCloser
	Stdout io.ReadCloser
	Stderr io.ReadCloser
	plat   platform
}

// Start launches argv with pipes on all three standard streams. The child
// inherits airlock's environment and working directory.
func Start(argv []string) (*Child, error) {
	if len(argv) == 0 {
		return nil, errors.New("no server command given")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = os.Environ()
	configure(cmd)

	c := &Child{cmd: cmd}
	var err error
	if c.Stdin, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}
	if c.Stdout, err = cmd.StdoutPipe(); err != nil {
		return nil, err
	}
	if c.Stderr, err = cmd.StderrPipe(); err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c.plat = attach(cmd)
	return c, nil
}

// PID is the child's process id.
func (c *Child) PID() int { return c.cmd.Process.Pid }

// ForwardSignals relays the signals a supervisor would send to airlock on to
// the child. The returned function stops relaying.
func (c *Child) ForwardSignals() (stop func()) { return forwardSignals(c.cmd.Process) }

// Wait waits for the child and turns its end into a shell-style exit code:
// the status it exited with, or 128+N if signal N killed it. Call it only
// after Stdout and Stderr have been read to EOF.
func (c *Child) Wait() int {
	err := c.cmd.Wait()
	c.plat.release()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return exitCode(ee)
	}
	return 1
}
