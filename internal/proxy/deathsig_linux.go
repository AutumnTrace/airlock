package proxy

import "syscall"

// setDeathSignal asks the kernel to SIGTERM the child if airlock dies
// without getting to clean up (SIGKILL, OOM killer).
func setDeathSignal(a *syscall.SysProcAttr) { a.Pdeathsig = syscall.SIGTERM }
