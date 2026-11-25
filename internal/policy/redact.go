package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// builtinPatterns catch credentials with a recognisable shape. Generic
// "password=..." matching is left out on purpose: it fires on documentation
// and code samples far more often than on real secrets.
//
// Each has hints: literal substrings every match contains. Checking for a
// hint with a plain substring search is far cheaper than running the
// regex, and most tool results contain none of them.
var builtinPatterns = []PatternCfg{
	{"private-key", `-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`, []string{"PRIVATE KEY-----"}},
	{"aws-access-key-id", `\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`, []string{"AKIA", "ASIA", "ABIA", "ACCA"}},
	{"github-token", `\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b`, []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}},
	{"anthropic-api-key", `\bsk-ant-[A-Za-z0-9_-]{20,}`, []string{"sk-ant-"}},
	{"openai-api-key", `\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}`, []string{"sk-"}},
	{"slack-token", `\bxox[abposr]-[A-Za-z0-9-]{10,}`, []string{"xox"}},
	{"stripe-secret-key", `\b[rs]k_live_[A-Za-z0-9]{20,}`, []string{"k_live_"}},
	{"google-api-key", `\bAIza[0-9A-Za-z_-]{35}\b`, []string{"AIza"}},
	{"jwt", `\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, []string{"eyJ"}},
}

type pattern struct {
	name  string
	re    *regexp.Regexp
	hints []string
}

// Redactor replaces secrets in strings with [redacted:name].
type Redactor struct {
	pats    []pattern
	anchors []anchor // every hint, grouped by its rarest byte
}

// anchor is a byte that some hints contain, and those hints.
type anchor struct {
	b    byte
	refs []hintRef
}

type hintRef struct {
	hint []byte
	off  int // where the anchor byte sits in hint
}

// rarity lists bytes from rarest to commonest in what tools return (code,
// prose, JSON). A hint is looked for by its rarest byte: one vectorised
// IndexByte pass per distinct anchor, with few false starts.
const rarity = "JQZXVjqzxKYWUBGPHFMNDLCROSITEA_-0123456789kvbgpywfmculdhrsnioate"

func anchorOf(h string) (byte, int) {
	best, at := -1, 0
	for i := 0; i < len(h); i++ {
		r := strings.IndexByte(rarity, h[i])
		if r < 0 {
			r = len(rarity)
		}
		if best < 0 || r < best {
			best, at = r, i
		}
	}
	return h[at], at
}

// NewRedactor compiles the built-in patterns (if builtin) and the custom
// ones. Go's regexp is RE2: matching is linear in the input, so a policy
// pattern cannot be turned into a denial of service by a big tool result.
func NewRedactor(builtin bool, custom []PatternCfg) (*Redactor, error) {
	var all []PatternCfg
	if builtin {
		all = append(all, builtinPatterns...)
	}
	all = append(all, custom...)
	r := &Redactor{}
	for _, p := range all {
		if p.Name == "" || p.Regex == "" {
			return nil, errors.New("redact.pattern needs both name and regex")
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("redact.pattern %s: %w", p.Name, err)
		}
		for _, h := range p.Hints {
			if h == "" {
				return nil, fmt.Errorf("redact.pattern %s: empty hint", p.Name)
			}
		}
		pat := pattern{name: p.Name, re: re, hints: p.Hints}
		r.pats = append(r.pats, pat)
	}
	for _, p := range r.pats {
		for _, h := range p.hints {
			b, off := anchorOf(h)
			i := slices.IndexFunc(r.anchors, func(a anchor) bool { return a.b == b })
			if i < 0 {
				r.anchors = append(r.anchors, anchor{b: b})
				i = len(r.anchors) - 1
			}
			r.anchors[i].refs = append(r.anchors[i].refs, hintRef{[]byte(h), off})
		}
	}
	return r, nil
}

// Empty reports whether there is nothing to redact.
func (r *Redactor) Empty() bool { return r == nil || len(r.pats) == 0 }

// hinted reports whether s could hold a match of p: true when p has no
// hints, or when one of them occurs in s.
func (p *pattern) hinted(s string) bool {
	if p.hints == nil {
		return true
	}
	for _, h := range p.hints {
		if strings.Contains(s, h) {
			return true
		}
	}
	return false
}

// String redacts one string and counts what it replaced by pattern name.
func (r *Redactor) String(s string, counts map[string]int) string {
	if r.Empty() {
		return s
	}
	for i := range r.pats {
		p := &r.pats[i]
		if !p.hinted(s) {
			continue
		}
		s = p.re.ReplaceAllStringFunc(s, func(string) string {
			counts[p.name]++
			return "[redacted:" + p.name + "]"
		})
	}
	return s
}

// candidate is the cheap test on raw JSON bytes: could anything in here
// need redacting? Hints are literals that JSON escaping only hides when
// written as \u escapes, so those always get the full walk. A pattern
// without hints is matched against the raw bytes, which escapes such as
// \n can fool, so any backslash sends those to the full walk too.
func (r *Redactor) candidate(raw []byte) bool {
	if bytes.Contains(raw, []byte(`\u`)) {
		return true
	}
	if r.anyHint(raw) {
		return true
	}
	escaped := bytes.IndexByte(raw, '\\') >= 0
	for i := range r.pats {
		p := &r.pats[i]
		if p.hints == nil && (escaped || p.re.Match(raw)) {
			return true
		}
	}
	return false
}

// anyHint reports whether any pattern's hint occurs in raw.
func (r *Redactor) anyHint(raw []byte) bool {
	for _, a := range r.anchors {
		for i := 0; i < len(raw); {
			j := bytes.IndexByte(raw[i:], a.b)
			if j < 0 {
				break
			}
			j += i
			for _, h := range a.refs {
				if s := j - h.off; s >= 0 && s+len(h.hint) <= len(raw) && bytes.Equal(raw[s:s+len(h.hint)], h.hint) {
					return true
				}
			}
			i = j + 1
		}
	}
	return false
}

// JSON redacts every string inside a JSON value. It returns the original
// bytes untouched (and a nil map) when nothing matched, which is the common
// case and costs a few substring searches over the raw bytes.
func (r *Redactor) JSON(raw json.RawMessage) (json.RawMessage, map[string]int, error) {
	if r.Empty() || !r.candidate(raw) {
		return raw, nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw, nil, err
	}
	counts := map[string]int{}
	v = r.walk(v, counts)
	if len(counts) == 0 {
		return raw, nil, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return raw, nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), counts, nil
}

func (r *Redactor) walk(v any, counts map[string]int) any {
	switch x := v.(type) {
	case string:
		return r.String(x, counts)
	case map[string]any:
		for k, e := range x {
			x[k] = r.walk(e, counts)
		}
	case []any:
		for i, e := range x {
			x[i] = r.walk(e, counts)
		}
	}
	return v
}
