package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AutumnTrace/airlock/internal/audit"
)

// The sample sessions on the published viewer must verify against the demo
// key, byte for byte. This also catches a checkout that rewrote their line
// endings.
func TestPublishedSamplesVerify(t *testing.T) {
	pubBytes, err := os.ReadFile("../../docs/samples/demo.pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := audit.ParsePublicKey(string(pubBytes))
	if err != nil {
		t.Fatal(err)
	}
	logs, _ := filepath.Glob("../../docs/samples/*.jsonl")
	if len(logs) < 2 {
		t.Fatalf("expected the sample logs, found %v", logs)
	}
	for _, p := range logs {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := audit.Verify(f, pub)
		f.Close()
		if err != nil || !rep.OK() || !rep.Closed || rep.SignedUpTo != rep.Records {
			t.Errorf("%s: %+v %v", p, rep, err)
		}
	}
}
