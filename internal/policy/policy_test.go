package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const sample = `
default = "deny"

[pinning]
lockfile = "fs.lock.json"
on_drift = "block"

[[rule]]
tools = ["read_*", "list_directory", "search_files"]
action = "allow"
args.path.prefix = ["/workspace"]
args.paths.prefix = ["/workspace"]

[[rule]]
tools = ["write_file", "edit_file"]
action = "allow"
rate = "2/min"
  [rule.args.path]
  prefix = ["/workspace/src", "/workspace/docs"]
  not_regex = '(^|/)\.env'

[[rule]]
tools = ["move_file"]
action = "deny"
reason = "moves need a human"
`

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func eval(p *Policy, tool, args string) Decision {
	var a map[string]any
	_ = json.Unmarshal([]byte(args), &a)
	return p.Evaluate(tool, a)
}

func TestEvaluate(t *testing.T) {
	p := mustParse(t, sample)
	cases := []struct {
		tool, args string
		allow      bool
		why        string
	}{
		{"read_text_file", `{"path":"/workspace/README.md"}`, true, ""},
		{"read_text_file", `{"path":"/workspace"}`, true, ""},
		{"read_text_file", `{"path":"/workspace/../etc/passwd"}`, false, "outside /workspace"},
		{"read_text_file", `{"path":"/workspace2/x"}`, false, "outside"},
		{"read_text_file", `{"path":"README.md"}`, false, "absolute path"},
		{"read_text_file", `{"path":"~/.ssh/id_rsa"}`, false, "absolute path"},
		{"read_text_file", `{"path":7}`, false, "must be a string"},
		{"read_multiple_files", `{"paths":["/workspace/a","/workspace/b"]}`, true, ""},
		{"read_multiple_files", `{"paths":["/workspace/a","/etc/shadow"]}`, false, "/etc/shadow"},
		{"write_file", `{"path":"/workspace/src/main.go","content":"x"}`, true, ""},
		{"write_file", `{"path":"/workspace/src/.env","content":"x"}`, false, "forbidden pattern"},
		{"write_file", `{"path":"/workspace/README.md","content":"x"}`, false, "outside"},
		{"move_file", `{"source":"/workspace/a","destination":"/workspace/b"}`, false, "moves need a human"},
		{"delete_everything", `{}`, false, "default is deny"},
	}
	for _, c := range cases {
		d := eval(p, c.tool, c.args)
		if d.Allow != c.allow || !strings.Contains(d.Reason, c.why) {
			t.Errorf("%s %s: allow=%v reason=%q, want allow=%v reason containing %q", c.tool, c.args, d.Allow, d.Reason, c.allow, c.why)
		}
	}
}

func TestFirstMatchWins(t *testing.T) {
	p := mustParse(t, `
[[rule]]
tools = ["*"]
action = "deny"
[[rule]]
tools = ["read_file"]
action = "allow"
`)
	if d := eval(p, "read_file", `{}`); d.Allow || d.Rule != 1 {
		t.Fatalf("%+v", d)
	}
}

func TestDefaultAllow(t *testing.T) {
	p := mustParse(t, ``)
	if d := eval(p, "anything", `{}`); !d.Allow || d.By != "default" || p.DropMalformed || !p.UnknownAllow {
		t.Fatalf("%+v", d)
	}
	if !mustParse(t, `default = "deny"`).DropMalformed {
		t.Fatal("deny-by-default should drop malformed frames")
	}
}

func TestRateLimit(t *testing.T) {
	p := mustParse(t, sample)
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	p.SetClock(func() time.Time { return now })
	args := `{"path":"/workspace/src/a.go","content":""}`
	for i := range 2 {
		if r := p.Take(eval(p, "write_file", args)); r != "" {
			t.Fatalf("call %d limited: %s", i+1, r)
		}
	}
	r := p.Take(eval(p, "write_file", args))
	if !strings.Contains(r, "rate limit of 2/min") || !strings.Contains(r, "30s") {
		t.Fatalf("third call: %q", r)
	}
	// Other tools under the same rule have their own bucket.
	if r := p.Take(eval(p, "edit_file", args)); r != "" {
		t.Fatalf("edit_file shares write_file's bucket: %s", r)
	}
	now = now.Add(31 * time.Second)
	if r := p.Take(eval(p, "write_file", args)); r != "" {
		t.Fatalf("not refilled after 31s: %s", r)
	}
}

func TestParseErrors(t *testing.T) {
	for src, want := range map[string]string{
		`default_action = "deny"`:                                                   "unknown setting",
		`default = "maybe"`:                                                         "default must be",
		"[[rule]]\naction = \"allow\"":                                              "no tools",
		"[[rule]]\ntools=[\"x\"]\naction=\"permit\"":                                "action must be",
		"[[rule]]\ntools=[\"x\"]\naction=\"allow\"\nrate=\"5\"":                     "rate",
		"[[rule]]\ntools=[\"x\"]\naction=\"deny\"\nrate=\"5/s\"":                    "only make sense",
		"[[rule]]\ntools=[\"x\"]\naction=\"allow\"\nargs.path.prefix=[\"rel/dir\"]": "absolute",
		"[[rule]]\ntools=[\"x\"]\naction=\"allow\"\nargs.path.regex=\"(\"":          "regex",
		"[pinning]\non_drift = \"panic\"":                                           "on_drift",
		"[[redact.pattern]]\nname = \"x\"":                                          "name and regex",
	} {
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want error containing %q", src, err, want)
		}
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		pat, name string
		want      bool
	}{
		{"*", "anything", true},
		{"read_*", "read_file", true},
		{"read_*", "unread_file", false},
		{"*_file", "write_file", true},
		{"git.*", "git.status", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"*a*b*", "xxaxxbxx", true},
		{"*a*b*", "xxbxxaxx", false},
		{"[x]", "[x]", true},
	} {
		if got := glob(c.pat, c.name); got != c.want {
			t.Errorf("glob(%q, %q) = %v", c.pat, c.name, got)
		}
	}
}

func TestNormPath(t *testing.T) {
	for in, want := range map[string]string{
		"/a/b/../c":        "/a/c",
		"/a//b/":           "/a/b",
		`C:\Users\me\proj`: "C:/Users/me/proj",
		`c:/Users/../x`:    "C:/x",
		"relative/path":    "",
		"~/x":              "",
		`\\server\share\x`: "",
		"/a/\x00b":         "",
	} {
		got, ok := normPath(in)
		if (want == "") == ok || got != want && ok {
			t.Errorf("normPath(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if !underAny("C:/USERS/me/proj/x", []string{"C:/Users/me/proj"}) {
		t.Error("drive-letter paths should compare case-insensitively")
	}
}

func TestRedactor(t *testing.T) {
	r, err := NewRedactor(true, []PatternCfg{{Name: "hostname", Regex: `\b[a-z]+\.corp\.example\b`}})
	if err != nil {
		t.Fatal(err)
	}
	in := `{"content":[{"type":"text","text":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nhost db.corp.example"}],"structuredContent":{"t":"ghp_` + strings.Repeat("A1b2", 9) + `","n":1.50}}`
	out, counts, err := r.JSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "AKIA") || strings.Contains(s, "ghp_") || strings.Contains(s, "db.corp") {
		t.Fatalf("not redacted: %s", s)
	}
	if counts["aws-access-key-id"] != 1 || counts["github-token"] != 1 || counts["hostname"] != 1 {
		t.Fatalf("counts %v", counts)
	}
	if !strings.Contains(s, `"n":1.50`) {
		t.Fatalf("numbers should keep their spelling: %s", s)
	}

	clean := []byte(`{"content":[{"type":"text","text":"nothing to see"}]}`)
	if out, counts, _ := r.JSON(clean); string(out) != string(clean) || counts != nil {
		t.Fatal("clean input was rewritten")
	}
	// A key spelled with a unicode escape is still found.
	escaped := []byte(`{"t":"\u0041KIAIOSFODNN7EXAMPLE"}`)
	if out, _, _ := r.JSON(escaped); strings.Contains(string(out), "IOSFODNN7") {
		t.Fatalf("escaped key slipped through: %s", out)
	}
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
	b, _ := json.Marshal(map[string]string{"text": "key:\n" + pem})
	if out, counts, _ := r.JSON(b); strings.Contains(string(out), "b3Blbn") || counts["private-key"] != 1 {
		t.Fatalf("PEM block: %s", out)
	}
}

// Every built-in pattern must be found through its hints, at the start, in
// the middle and at the end of a frame.
func TestBuiltinHintsCoverTheirPatterns(t *testing.T) {
	r, _ := NewRedactor(true, nil)
	samples := map[string]string{
		"private-key":       "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----",
		"aws-access-key-id": "ASIAIOSFODNN7EXAMPLE",
		"github-token":      "github_pat_" + strings.Repeat("a1", 31),
		"anthropic-api-key": "sk-ant-api03-" + strings.Repeat("Ab3", 10),
		"openai-api-key":    "sk-proj-" + strings.Repeat("Zx9", 12),
		"slack-token":       "xoxb-1234567890-abcdef",
		"stripe-secret-key": "sk_live_" + strings.Repeat("4eC3", 6),
		"google-api-key":    "AIza" + strings.Repeat("S", 35),
		"jwt":               "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
	}
	for name, secret := range samples {
		for _, frame := range []string{secret + ` tail`, `{"a":"x ` + secret + ` y"}`, `head ` + secret} {
			b, _ := json.Marshal(map[string]string{"text": frame})
			if !r.candidate(b) {
				t.Errorf("%s: no hint found in %s", name, b)
				continue
			}
			_, counts, _ := r.JSON(b)
			if counts[name] == 0 {
				t.Errorf("%s: not redacted in %s (counts %v)", name, b, counts)
			}
		}
	}
}

func TestCustomPatternHints(t *testing.T) {
	p := mustParse(t, `
[redact]
builtin = false
[[redact.pattern]]
name = "ticket"
regex = 'TKT-[0-9]{6}'
hints = ["TKT-"]
`)
	out, counts, _ := p.Redactor.JSON([]byte(`{"t":"see TKT-123456"}`))
	if counts["ticket"] != 1 || strings.Contains(string(out), "123456") {
		t.Fatalf("%s %v", out, counts)
	}
	if p.Redactor.candidate([]byte(`{"t":"nothing here at all"}`)) {
		t.Fatal("hinted custom pattern should skip clean frames without a regex run")
	}
}

// The bug from the devlog: in raw JSON, the n of a \n escape sits right
// before the key and defeats the pattern's \b.
func TestKeyAfterNewlineEscape(t *testing.T) {
	r, _ := NewRedactor(true, nil)
	b, _ := json.Marshal(map[string]string{"text": "AWS=x\nAKIAIOSFODNN7EXAMPLE\n"})
	out, counts, _ := r.JSON(b)
	if counts["aws-access-key-id"] != 1 || strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("%s %v", out, counts)
	}
}
