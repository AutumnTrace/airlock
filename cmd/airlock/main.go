// Command airlock records and polices the traffic between an MCP client and
// an MCP server that speaks the stdio transport.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// version is set by the release build with -ldflags "-X main.version=...".
var version = "dev"

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

const usage = `airlock: a flight recorder and firewall for MCP servers

Usage:
  airlock wrap [flags] -- <server command> [args...]
  airlock verify [flags] <session.jsonl>...
  airlock keygen [-o airlock.key]
  airlock check <policy.toml> [tool [arguments-json]]
  airlock version

Run "airlock <command> -h" for the flags of a command.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "wrap":
		return cmdWrap(args[1:], stdin, stdout, stderr)
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	case "keygen":
		return cmdKeygen(args[1:], stdout, stderr)
	case "check":
		return cmdCheck(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "airlock", buildVersion())
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "airlock: unknown command %q\n\n%s", args[0], usage)
	return 2
}
