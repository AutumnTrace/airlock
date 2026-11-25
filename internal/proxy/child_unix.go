//go:build !windows

package proxy

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

type platform struct{}

func (platform) release() {}

func configure(cmd *exec.Cmd) {
	// Own process group: a Ctrl+C in a terminal reaches the child once,
	// through forwardSignals, instead of twice.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	setDeathSignal(cmd.SysProcAttr)
}

func attach(*exec.Cmd) platform { return platform{} }

func forwardSignals(p *os.Process) func() {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-ch:
				_ = p.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	return func() { signal.Stop(ch); close(done) }
}

func exitCode(ee *exec.ExitError) int {
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ee.ExitCode()
}
