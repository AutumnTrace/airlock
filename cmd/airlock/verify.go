package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/AutumnTrace/airlock/internal/audit"
)

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pubFlag := fs.String("pubkey", "", `trusted public key ("ed25519:..." or a file holding it); the log must be signed with it`)
	head := fs.String("head", "", "expected chain head (from the line airlock prints on exit); catches truncation of unsigned logs")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: airlock verify [flags] <session.jsonl>...")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	var trusted ed25519.PublicKey
	if *pubFlag != "" {
		k, err := audit.ParsePublicKey(*pubFlag)
		if err != nil {
			fmt.Fprintf(stderr, "airlock: %v\n", err)
			return 2
		}
		trusted = k
	}

	status := 0
	for _, path := range fs.Args() {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(stderr, "airlock: %v\n", err)
			status = 1
			continue
		}
		rep, err := audit.Verify(f, trusted)
		f.Close()
		if err != nil {
			fmt.Fprintf(stderr, "airlock: %s: %v\n", path, err)
			status = 1
			continue
		}
		if *head != "" && !hasPrefixFold(rep.Head, *head) {
			rep.Problems = append(rep.Problems, audit.Problem{Line: rep.Records, Msg: fmt.Sprintf("chain head is %s, expected %s: records were added or removed at the end", rep.Head[:16], *head)})
		}
		verdict := "ok"
		if !rep.OK() {
			verdict = "FAILED"
			status = 1
		}
		fmt.Fprintf(stdout, "%s: %s, %d records, head %s\n", path, verdict, rep.Records, rep.Head[:16])
		if rep.Key != "" {
			fmt.Fprintf(stdout, "  signed by %s, %d valid signature(s), last at record %d\n", rep.Key, rep.Checkpoints, rep.SignedUpTo)
		}
		if rep.ExitCode != nil {
			fmt.Fprintf(stdout, "  server exited with status %d\n", *rep.ExitCode)
		}
		for _, p := range rep.Problems {
			fmt.Fprintf(stdout, "  problem: %s\n", p)
		}
		for _, n := range rep.Notes {
			fmt.Fprintf(stdout, "  note: %s\n", n)
		}
	}
	return status
}

func hasPrefixFold(full, prefix string) bool {
	if len(prefix) < 8 || len(prefix) > len(full) {
		return false
	}
	for i := range len(prefix) {
		a, b := full[i], prefix[i]
		if 'A' <= b && b <= 'F' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("o", "airlock.key", "where to write the private key")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	priv, pub, err := audit.GenerateKey()
	if err != nil {
		fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	if _, err := f.Write(priv); err != nil {
		f.Close()
		fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "airlock: private key written to %s; keep it where the agent cannot read it\n", *out)
	fmt.Fprintln(stdout, pub)
	return 0
}
