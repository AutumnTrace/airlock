// Package policy reads airlock's TOML policy files and answers one
// question: may this tool be called with these arguments?
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// File is a policy file as written.
type File struct {
	Default   string    `toml:"default"`   // "allow" (default) or "deny"
	Malformed string    `toml:"malformed"` // "pass" or "drop"; default depends on Default
	Pinning   Pinning   `toml:"pinning"`
	Schema    SchemaCfg `toml:"schema"`
	Rules     []RuleCfg `toml:"rule"`
	Redact    RedactCfg `toml:"redact"`
}

// Pinning configures tool pinning.
type Pinning struct {
	Lockfile     string `toml:"lockfile"`      // relative to the policy file
	OnDrift      string `toml:"on_drift"`      // "warn" or "block"
	OnNewTool    string `toml:"on_new_tool"`   // "allow", "warn" or "block"
	OnSuspicious string `toml:"on_suspicious"` // "warn" or "block"
}

// SchemaCfg configures argument validation.
type SchemaCfg struct {
	Validate     *bool  `toml:"validate"`      // default true
	UnknownTools string `toml:"unknown_tools"` // "allow" or "deny" calls to tools never listed
}

// RuleCfg is one [[rule]] table.
type RuleCfg struct {
	Tools  []string           `toml:"tools"`
	Action string             `toml:"action"`
	Reason string             `toml:"reason"`
	Rate   string             `toml:"rate"`
	Args   map[string]ArgRule `toml:"args"`
}

// ArgRule constrains one argument. When the argument is an array, every
// element must pass.
type ArgRule struct {
	Prefix    []string `toml:"prefix"`
	Regex     string   `toml:"regex"`
	NotRegex  string   `toml:"not_regex"`
	MaxLength int      `toml:"max_length"`
}

// RedactCfg configures secret redaction.
type RedactCfg struct {
	Builtin  *bool        `toml:"builtin"` // default true
	Patterns []PatternCfg `toml:"pattern"`
}

// PatternCfg is one custom redaction pattern.
type PatternCfg struct {
	Name  string `toml:"name"`
	Regex string `toml:"regex"`
}

// Policy is a parsed, checked policy.
type Policy struct {
	Path string
	Hash string // SHA-256 of the file's bytes

	DefaultAllow   bool
	DropMalformed  bool
	ValidateSchema bool
	UnknownAllow   bool
	Pinning        Pinning
	Redactor       *Redactor

	rules []rule
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type rule struct {
	n      int // 1-based, as people count
	tools  []string
	allow  bool
	reason string
	rate   *rate
	args   []argRule
}

type argRule struct {
	name     string
	prefix   []string
	regex    *regexp.Regexp
	notRegex *regexp.Regexp
	maxLen   int
}

// Load reads and checks a policy file. Unknown keys are an error: a typo
// in a security policy should not silently mean "no rule".
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Path = path
	if p.Pinning.Lockfile != "" && !filepath.IsAbs(p.Pinning.Lockfile) {
		p.Pinning.Lockfile = filepath.Join(filepath.Dir(path), p.Pinning.Lockfile)
	}
	return p, nil
}

// Parse checks policy source.
func Parse(src []byte) (*Policy, error) {
	var f File
	md, err := toml.Decode(string(src), &f)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown setting(s): %s", strings.Join(keys, ", "))
	}
	sum := sha256.Sum256(src)
	p := &Policy{Hash: hex.EncodeToString(sum[:]), now: time.Now, buckets: map[string]*bucket{}}

	switch f.Default {
	case "", "allow":
		p.DefaultAllow = true
	case "deny":
	default:
		return nil, fmt.Errorf(`default must be "allow" or "deny", not %q`, f.Default)
	}
	switch f.Malformed {
	case "":
		p.DropMalformed = !p.DefaultAllow
	case "pass":
	case "drop":
		p.DropMalformed = true
	default:
		return nil, fmt.Errorf(`malformed must be "pass" or "drop", not %q`, f.Malformed)
	}

	p.Pinning = f.Pinning
	if err := oneOf("pinning.on_drift", &p.Pinning.OnDrift, "warn", "warn", "block"); err != nil {
		return nil, err
	}
	if err := oneOf("pinning.on_new_tool", &p.Pinning.OnNewTool, "warn", "allow", "warn", "block"); err != nil {
		return nil, err
	}
	if err := oneOf("pinning.on_suspicious", &p.Pinning.OnSuspicious, "warn", "warn", "block"); err != nil {
		return nil, err
	}

	p.ValidateSchema = f.Schema.Validate == nil || *f.Schema.Validate
	unknown := f.Schema.UnknownTools
	if unknown == "" {
		unknown = "allow"
		if !p.DefaultAllow {
			unknown = "deny"
		}
	}
	if err := oneOf("schema.unknown_tools", &unknown, unknown, "allow", "deny"); err != nil {
		return nil, err
	}
	p.UnknownAllow = unknown == "allow"

	for i, rc := range f.Rules {
		r, err := compileRule(i+1, rc)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		p.rules = append(p.rules, r)
	}

	builtin := f.Redact.Builtin == nil || *f.Redact.Builtin
	if p.Redactor, err = NewRedactor(builtin, f.Redact.Patterns); err != nil {
		return nil, err
	}
	return p, nil
}

func oneOf(name string, v *string, def string, allowed ...string) error {
	if *v == "" {
		*v = def
	}
	for _, a := range allowed {
		if *v == a {
			return nil
		}
	}
	return fmt.Errorf("%s must be one of %s, not %q", name, strings.Join(allowed, ", "), *v)
}

func compileRule(n int, rc RuleCfg) (rule, error) {
	r := rule{n: n, tools: rc.Tools, reason: rc.Reason}
	if len(rc.Tools) == 0 {
		return r, errors.New(`no tools: use tools = ["*"] for every tool`)
	}
	switch rc.Action {
	case "allow":
		r.allow = true
	case "deny":
		if len(rc.Args) > 0 || rc.Rate != "" {
			return r, errors.New("args and rate only make sense on allow rules")
		}
	default:
		return r, fmt.Errorf(`action must be "allow" or "deny", not %q`, rc.Action)
	}
	if rc.Rate != "" {
		rt, err := parseRate(rc.Rate)
		if err != nil {
			return r, err
		}
		r.rate = &rt
	}
	names := make([]string, 0, len(rc.Args))
	for name := range rc.Args {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ac := rc.Args[name]
		ar := argRule{name: name, maxLen: ac.MaxLength}
		for _, p := range ac.Prefix {
			np, ok := normPath(p)
			if !ok {
				return r, fmt.Errorf("args.%s.prefix %q must be an absolute path", name, p)
			}
			ar.prefix = append(ar.prefix, np)
		}
		var err error
		if ac.Regex != "" {
			if ar.regex, err = regexp.Compile(ac.Regex); err != nil {
				return r, fmt.Errorf("args.%s.regex: %w", name, err)
			}
		}
		if ac.NotRegex != "" {
			if ar.notRegex, err = regexp.Compile(ac.NotRegex); err != nil {
				return r, fmt.Errorf("args.%s.not_regex: %w", name, err)
			}
		}
		if ar.prefix == nil && ar.regex == nil && ar.notRegex == nil && ar.maxLen == 0 {
			return r, fmt.Errorf("args.%s has no constraint", name)
		}
		r.args = append(r.args, ar)
	}
	return r, nil
}

// Decision is the policy's answer for one call.
type Decision struct {
	Allow  bool
	By     string // "rule", "args", "default"
	Rule   int    // 1-based; 0 when no rule matched
	Reason string
	rule   *rule
	tool   string
}

// Evaluate finds the first rule whose tools match and applies it. Rules are
// read top to bottom like a firewall: the first match decides, and a later
// rule never rescues a call an earlier rule denied.
func (p *Policy) Evaluate(tool string, args map[string]any) Decision {
	for i := range p.rules {
		r := &p.rules[i]
		if !matchAny(r.tools, tool) {
			continue
		}
		d := Decision{Allow: r.allow, By: "rule", Rule: r.n, rule: r, tool: tool}
		if !r.allow {
			d.Reason = fmt.Sprintf("rule %d denies %s", r.n, tool)
			if r.reason != "" {
				d.Reason += ": " + r.reason
			}
			return d
		}
		for _, ar := range r.args {
			if msg := ar.check(args); msg != "" {
				return Decision{By: "args", Rule: r.n, Reason: fmt.Sprintf("rule %d: %s", r.n, msg), tool: tool}
			}
		}
		return d
	}
	if p.DefaultAllow {
		return Decision{Allow: true, By: "default", tool: tool}
	}
	return Decision{By: "default", Reason: fmt.Sprintf("no rule allows %s and the default is deny", tool), tool: tool}
}

// Take spends one unit of the matched rule's rate limit. It returns a reason
// when the limit is exhausted.
func (p *Policy) Take(d Decision) string {
	if d.rule == nil || d.rule.rate == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := strconv.Itoa(d.rule.n) + "\x00" + d.tool
	b := p.buckets[key]
	now := p.now()
	if b == nil {
		b = &bucket{tokens: float64(d.rule.rate.n), last: now}
		p.buckets[key] = b
	}
	if !b.take(*d.rule.rate, now) {
		return fmt.Sprintf("rule %d: rate limit of %s for %s reached; try again in %s", d.rule.n, d.rule.rate, d.tool, b.wait(*d.rule.rate).Round(time.Second))
	}
	return ""
}

// SetClock replaces the clock, for tests.
func (p *Policy) SetClock(now func() time.Time) { p.now = now }

// RuleCount is the number of rules.
func (p *Policy) RuleCount() int { return len(p.rules) }

func (ar argRule) check(args map[string]any) string {
	v, ok := args[ar.name]
	if !ok {
		return "" // absent; the schema decides whether that is allowed
	}
	var vals []string
	switch x := v.(type) {
	case string:
		vals = []string{x}
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return fmt.Sprintf("argument %s must hold strings", ar.name)
			}
			vals = append(vals, s)
		}
	default:
		return fmt.Sprintf("argument %s must be a string", ar.name)
	}
	for _, s := range vals {
		if ar.maxLen > 0 && len(s) > ar.maxLen {
			return fmt.Sprintf("argument %s is %d bytes, more than %d", ar.name, len(s), ar.maxLen)
		}
		if ar.prefix != nil {
			np, ok := normPath(s)
			if !ok {
				return fmt.Sprintf("argument %s must be an absolute path inside %s, got %q", ar.name, strings.Join(ar.prefix, " or "), s)
			}
			if !underAny(np, ar.prefix) {
				return fmt.Sprintf("argument %s = %q is outside %s", ar.name, s, strings.Join(ar.prefix, " or "))
			}
		}
		if ar.regex != nil && !ar.regex.MatchString(s) {
			return fmt.Sprintf("argument %s = %q does not match %s", ar.name, s, ar.regex)
		}
		if ar.notRegex != nil && ar.notRegex.MatchString(s) {
			return fmt.Sprintf("argument %s = %q matches the forbidden pattern %s", ar.name, s, ar.notRegex)
		}
	}
	return ""
}
