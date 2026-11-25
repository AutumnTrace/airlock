package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"

	"github.com/AutumnTrace/airlock/internal/viewer"
)

func cmdView(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("view", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:0", "address to listen on")
	noOpen := fs.Bool("no-open", false, "print the URL instead of opening a browser")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: airlock view [flags] [session.jsonl | directory]...\n\nWith no arguments, shows the sessions in the default log directory.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{defaultLogDir()}
	}
	sessions, err := viewer.Find(paths)
	if err != nil {
		fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	if len(sessions) == 0 {
		fmt.Fprintf(stderr, "airlock: no session logs in %v\n", paths)
		return 1
	}
	srv, err := viewer.Start(*addr, sessions)
	if err != nil {
		fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	defer srv.Close()
	fmt.Fprintf(stdout, "airlock: viewing %s at %s (Ctrl+C to stop)\n", viewer.Describe(sessions), srv.URL)
	if !*noOpen {
		if err := openBrowser(srv.URL); err != nil {
			fmt.Fprintf(stderr, "airlock: could not open a browser: %v\n", err)
		}
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	return 0
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
