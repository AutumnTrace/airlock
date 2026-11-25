package proxy

import (
	"os"
	"os/exec"
	"os/signal"
	"unsafe"

	"golang.org/x/sys/windows"
)

// platform holds the job object that ties the child's lifetime to airlock's.
type platform struct{ job windows.Handle }

func (p platform) release() {
	if p.job != 0 {
		_ = windows.CloseHandle(p.job)
	}
}

func configure(*exec.Cmd) {}

// attach puts the child in a job object that is killed when its last handle
// closes. airlock holds the only handle, so if airlock is terminated (which
// is how Node's child.kill() stops a process on Windows) the server and
// anything it spawned go with it instead of lingering.
func attach(cmd *exec.Cmd) platform {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return platform{}
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return platform{}
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = windows.CloseHandle(job)
		return platform{}
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		_ = windows.CloseHandle(job)
		return platform{}
	}
	return platform{job: job}
}

// forwardSignals swallows Ctrl+C. The child shares airlock's console and
// gets the same event directly; airlock keeps running so it can record the
// child's last words and exit with its status.
func forwardSignals(*os.Process) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	return func() { signal.Stop(ch) }
}

func exitCode(ee *exec.ExitError) int { return ee.ExitCode() }
