//go:build !windows && !linux

package proxy

import "syscall"

// Without Pdeathsig the child still notices airlock's death: its stdin pipe
// closes and an MCP stdio server exits on EOF.
func setDeathSignal(*syscall.SysProcAttr) {}
