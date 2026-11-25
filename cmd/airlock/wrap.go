package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/AutumnTrace/airlock/internal/proxy"
)

func cmdWrap(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: airlock wrap [flags] -- <server command> [args...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fs.Usage()
		return 2
	}

	child, err := proxy.Start(argv)
	if err != nil {
		fmt.Fprintf(stderr, "airlock: cannot start %s: %v\n", argv[0], err)
		return 127
	}
	stop := child.ForwardSignals()
	defer stop()

	err = proxy.Run(proxy.Pipes{
		ClientIn:  stdin,
		ClientOut: stdout,
		ServerIn:  child.Stdin,
		ServerOut: child.Stdout,
		ServerErr: child.Stderr,
		ErrOut:    stderr,
	}, proxy.Passthrough{})
	code := child.Wait()
	if err != nil {
		fmt.Fprintf(stderr, "airlock: %v\n", err)
	}
	return code
}
