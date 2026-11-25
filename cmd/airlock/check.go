package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/AutumnTrace/airlock/internal/policy"
)

// cmdCheck parses a policy and, given a tool name and arguments, says what
// the rules would do with that call. It cannot apply schema validation or
// pinning, which need the server's tool list.
func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: airlock check <policy.toml> [tool [arguments-json]]

Without a tool, check that the policy parses and summarise it. With one,
evaluate a call against the rules, e.g.

  airlock check policy.toml read_text_file '{"path":"/etc/passwd"}'`)
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 || fs.NArg() > 3 {
		fs.Usage()
		return 2
	}
	pol, err := policy.Load(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	if fs.NArg() == 1 {
		def := "allow"
		if !pol.DefaultAllow {
			def = "deny"
		}
		fmt.Fprintf(stdout, "%s: ok\n  %d rule(s), default %s, schema validation %v\n", fs.Arg(0), pol.RuleCount(), def, pol.ValidateSchema)
		fmt.Fprintf(stdout, "  pinning: on_drift %s, on_new_tool %s, on_suspicious %s", pol.Pinning.OnDrift, pol.Pinning.OnNewTool, pol.Pinning.OnSuspicious)
		if pol.Pinning.Lockfile != "" {
			fmt.Fprintf(stdout, ", lockfile %s", pol.Pinning.Lockfile)
		}
		fmt.Fprintf(stdout, "\n  sha256 %s\n", pol.Hash)
		return 0
	}

	callArgs := map[string]any{}
	if fs.NArg() == 3 {
		dec := json.NewDecoder(bytes.NewReader([]byte(fs.Arg(2))))
		dec.UseNumber()
		if err := dec.Decode(&callArgs); err != nil {
			fmt.Fprintf(stderr, "airlock: arguments must be a JSON object: %v\n", err)
			return 2
		}
	}
	d := pol.Evaluate(fs.Arg(1), callArgs)
	switch {
	case !d.Allow:
		fmt.Fprintf(stdout, "deny: %s\n", d.Reason)
		return 1
	case d.Rule > 0:
		fmt.Fprintf(stdout, "allow: rule %d\n", d.Rule)
	default:
		fmt.Fprintln(stdout, "allow: no rule matched and the default is allow")
	}
	return 0
}
