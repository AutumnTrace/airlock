package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// builtinPatterns catch credentials with a recognisable shape. Generic
// "password=..." matching is left out on purpose: it fires on documentation
// and code samples far more often than on real secrets.
var builtinPatterns = []PatternCfg{
	{"private-key", `-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`},
	{"aws-access-key-id", `\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`},
	{"github-token", `\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b`},
	{"anthropic-api-key", `\bsk-ant-[A-Za-z0-9_-]{20,}`},
	{"openai-api-key", `\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}`},
	{"slack-token", `\bxox[abposr]-[A-Za-z0-9-]{10,}`},
	{"stripe-secret-key", `\b[rs]k_live_[A-Za-z0-9]{20,}`},
	{"google-api-key", `\bAIza[0-9A-Za-z_-]{35}\b`},
	{"jwt", `\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`},
}

// Redactor replaces secrets in strings with [redacted:name].
type Redactor struct {
	names []string
	res   []*regexp.Regexp
	any   *regexp.Regexp // all patterns at once, for the fast path
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
	var alts []string
	for _, p := range all {
		if p.Name == "" || p.Regex == "" {
			return nil, fmt.Errorf("redact.pattern needs both name and regex")
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("redact.pattern %s: %w", p.Name, err)
		}
		r.names = append(r.names, p.Name)
		r.res = append(r.res, re)
		alts = append(alts, "(?:"+p.Regex+")")
	}
	if len(alts) > 0 {
		r.any = regexp.MustCompile(strings.Join(alts, "|"))
	}
	return r, nil
}

// Empty reports whether there is nothing to redact.
func (r *Redactor) Empty() bool { return r == nil || r.any == nil }

// String redacts one string and counts what it replaced by pattern name.
func (r *Redactor) String(s string, counts map[string]int) string {
	if r.Empty() || !r.any.MatchString(s) {
		return s
	}
	for i, re := range r.res {
		name := r.names[i]
		s = re.ReplaceAllStringFunc(s, func(string) string {
			counts[name]++
			return "[redacted:" + name + "]"
		})
	}
	return s
}

// JSON redacts every string inside a JSON value. It returns the original
// bytes untouched (and a nil map) when nothing matched, which is the common
// case and costs one regex scan of the raw bytes.
func (r *Redactor) JSON(raw json.RawMessage) (json.RawMessage, map[string]int, error) {
	if r.Empty() {
		return raw, nil, nil
	}
	// Escapes can hide a match from the raw scan: \u0041 is an A, and in
	// "x\nAKIA..." the n of the escape defeats \b. So the raw scan is only
	// trusted when the bytes have no escapes other than \" and \\.
	if !r.any.Match(raw) && !hasUnusualEscapes(raw) {
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

func hasUnusualEscapes(raw []byte) bool {
	for i := 0; i < len(raw)-1; i++ {
		if raw[i] == '\\' {
			switch raw[i+1] {
			case '"', '\\':
				i++
			default:
				return true
			}
		}
	}
	return false
}
