package policy

import (
	"fmt"
	"math"
	"path"
	"strconv"
	"strings"
	"time"
)

// matchAny reports whether name matches any of the globs. A glob is a tool
// name where * matches any run of characters and ? matches one; nothing else
// is special, so tool names with dots, slashes or brackets need no escaping.
func matchAny(globs []string, name string) bool {
	for _, g := range globs {
		if glob(g, name) {
			return true
		}
	}
	return false
}

func glob(pattern, name string) bool {
	// Iterative matcher with single-star backtracking: linear in practice,
	// no recursion, no regex compilation per call.
	p, n := 0, 0
	starP, starN := -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == name[n]):
			p++
			n++
		case p < len(pattern) && pattern[p] == '*':
			starP, starN = p, n
			p++
		case starP >= 0:
			p = starP + 1
			starN++
			n = starN
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// normPath turns a path argument into a clean, slash-separated absolute
// path, so "/work/../etc/passwd" is seen as "/etc/passwd". It returns false
// for relative paths and for "~": airlock cannot know what the server will
// resolve those against, so a prefix rule refuses them.
//
// What it cannot see is the filesystem: a symlink inside an allowed
// directory that points outside it passes. The server is the only party
// that can check that.
func normPath(p string) (string, bool) {
	if p == "" || strings.ContainsRune(p, 0) {
		return "", false
	}
	s := strings.ReplaceAll(p, `\`, "/")
	drive := ""
	if len(s) >= 2 && s[1] == ':' && isLetter(s[0]) {
		drive, s = strings.ToUpper(s[:1])+":", s[2:]
	}
	if strings.HasPrefix(s, "//") && drive == "" {
		return "", false // UNC paths and the like
	}
	if !strings.HasPrefix(s, "/") {
		return "", false
	}
	return drive + path.Clean(s), true
}

func isLetter(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }

// underAny reports whether p is one of the prefixes or inside one. Matching
// is by path segment, so /work does not cover /workshop. Windows-style paths
// (with a drive letter) compare case-insensitively.
func underAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		a, b := p, pre
		if len(b) >= 2 && b[1] == ':' {
			a, b = strings.ToLower(a), strings.ToLower(b)
		}
		if a == b || b == "/" || strings.HasPrefix(a, strings.TrimSuffix(b, "/")+"/") {
			return true
		}
	}
	return false
}

// rate is "n calls per period".
type rate struct {
	n      int
	period time.Duration
	text   string
}

func (r rate) String() string { return r.text }

func parseRate(s string) (rate, error) {
	num, unit, ok := strings.Cut(strings.ReplaceAll(s, " ", ""), "/")
	n, err := strconv.Atoi(num)
	if !ok || err != nil || n <= 0 {
		return rate{}, fmt.Errorf("rate %q must look like 10/min", s)
	}
	var d time.Duration
	switch unit {
	case "s", "sec", "second":
		d = time.Second
	case "m", "min", "minute":
		d = time.Minute
	case "h", "hour":
		d = time.Hour
	case "d", "day":
		d = 24 * time.Hour
	default:
		return rate{}, fmt.Errorf("rate %q: unit must be s, min, h or day", s)
	}
	return rate{n: n, period: d, text: s}, nil
}

// bucket is a token bucket that holds up to n tokens and refills at n per
// period: a burst of n is allowed, then calls are spaced out.
type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) refill(r rate, now time.Time) {
	if el := now.Sub(b.last); el > 0 {
		b.tokens = math.Min(float64(r.n), b.tokens+el.Seconds()*float64(r.n)/r.period.Seconds())
		b.last = now
	}
}

func (b *bucket) take(r rate, now time.Time) bool {
	b.refill(r, now)
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (b *bucket) wait(r rate) time.Duration {
	need := 1 - b.tokens
	return time.Duration(need * r.period.Seconds() / float64(r.n) * float64(time.Second))
}
