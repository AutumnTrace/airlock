package pin

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustCanon(t *testing.T, s string) Tool {
	t.Helper()
	tool, err := Canonical([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return tool
}

func TestCanonicalIgnoresFormattingAndMeta(t *testing.T) {
	a := mustCanon(t, `{"name":"read_file","description":"Read a file.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}`)
	b := mustCanon(t, `{
	  "inputSchema": {"properties": {"path": {"type": "string"}}, "type": "object"},
	  "description": "Read a file.",
	  "_meta": {"io.example/rev": 7},
	  "name": "read_file"
	}`)
	if a.Hash != b.Hash {
		t.Fatalf("formatting changed the hash:\n%s\n%s", a.Def, b.Def)
	}
	if string(a.Schema) != `{"properties":{"path":{"type":"string"}},"type":"object"}` {
		t.Fatalf("schema: %s", a.Schema)
	}
}

func TestCanonicalSeesRealChanges(t *testing.T) {
	base := mustCanon(t, `{"name":"x","description":"Read a file.","inputSchema":{"type":"object"}}`)
	for _, changed := range []string{
		`{"name":"x","description":"Read a file. ","inputSchema":{"type":"object"}}`,
		`{"name":"x","description":"Read a file.","inputSchema":{"type":"object","properties":{"notes":{"type":"string"}}}}`,
		`{"name":"x","description":"Read a file.","inputSchema":{"type":"object"},"annotations":{"destructiveHint":true}}`,
		`{"name":"x","description":"Read a file.<b>","inputSchema":{"type":"object"}}`,
	} {
		if mustCanon(t, changed).Hash == base.Hash {
			t.Errorf("change not detected: %s", changed)
		}
	}
	if _, err := Canonical([]byte(`{"description":"no name"}`)); err == nil {
		t.Error("accepted a tool without a name")
	}
}

func TestCanonicalKeepsHTMLUnescaped(t *testing.T) {
	tool := mustCanon(t, `{"name":"x","description":"<IMPORTANT>& more"}`)
	if !strings.Contains(string(tool.Def), "<IMPORTANT>& more") {
		t.Fatalf("%s", tool.Def)
	}
}

func TestLockfileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "server.lock.json")
	s, err := Load(path)
	if err != nil || s.FromLockfile() {
		t.Fatalf("%v %v", err, s.FromLockfile())
	}
	a := mustCanon(t, `{"name":"a","description":"A"}`)
	b := mustCanon(t, `{"name":"b","description":"B"}`)
	s.Pin(a, time.Now())
	s.Pin(b, time.Now())
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	s2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.FromLockfile() || strings.Join(s2.Names(), ",") != "a,b" {
		t.Fatalf("reloaded %v", s2.Names())
	}
	if st, _ := s2.Check(a); st != Same {
		t.Fatalf("a is %v", st)
	}
	if st, e := s2.Check(mustCanon(t, `{"name":"a","description":"A, but evil"}`)); st != Changed || e.SHA256 != a.Hash {
		t.Fatalf("changed a is %v", st)
	}
	if st, _ := s2.Check(mustCanon(t, `{"name":"c"}`)); st != New {
		t.Fatalf("c is %v", st)
	}
}

func TestInMemorySetDoesNotWrite(t *testing.T) {
	s, _ := Load("")
	s.Pin(mustCanon(t, `{"name":"a"}`), time.Now())
	if err := s.Save(); err != nil || s.Path() != "" {
		t.Fatal(err)
	}
}
