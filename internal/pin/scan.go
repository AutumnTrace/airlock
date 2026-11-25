package pin

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Flag is something in a tool definition that looks like an attempt to steer
// the model. These are heuristics: they catch the published tool-poisoning
// examples and the obvious variations, and they will miss a careful
// attacker and occasionally flag an honest description.
type Flag struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"` // "high" or "low"
	Where    string `json:"where"`    // JSON path inside the definition
	Detail   string `json:"detail"`
}

var (
	reInstructionTag = regexp.MustCompile(`(?i)<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\b[^>]*>`)
	reOverride       = regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|other)\s+(instructions|rules|directions)|\b(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show|notify)\s+(this\s+to\s+|it\s+to\s+)?(the\s+)?user|\bwithout\s+(telling|informing|notifying|asking)\s+(the\s+)?user|\bthe\s+user\s+(must|should)\s+not\s+(know|see|be\s+told)`)
	reSensitivePath  = regexp.MustCompile(`(?i)(~|\$home|%userprofile%)?[/\\]?\.ssh\b|\bid_(rsa|ed25519|ecdsa)\b|\.aws[/\\]credentials|(^|[\s'"/\\])\.env\b|\bmcp\.json\b|claude_desktop_config|\.cursor[/\\]|/etc/(passwd|shadow)|\.netrc\b|\.npmrc\b|\.git-credentials|\.pgpass\b|\.docker[/\\]config\.json`)
)

// longDescription is the length above which a description is noted.
const longDescription = 4000

// Scan looks through every string in a canonical definition. others are the
// names of the server's other tools, for the cross-reference check.
func Scan(t Tool, others []string) []Flag {
	var v any
	if err := json.Unmarshal(t.Def, &v); err != nil {
		return nil
	}
	var flags []Flag
	walkStrings(v, "", func(where, s string) {
		flags = append(flags, scanString(where, s)...)
		if where == "description" {
			if n := utf8.RuneCountInString(s); n > longDescription {
				flags = append(flags, Flag{"long-description", "low", where, fmt.Sprintf("%d characters", n)})
			}
			for _, o := range others {
				if o != t.Name && isIdentifierLike(o) && mentions(s, o) {
					flags = append(flags, Flag{"mentions-other-tool", "low", where, "refers to " + o})
				}
			}
		}
	})
	sort.SliceStable(flags, func(i, j int) bool { return flags[i].Severity == "high" && flags[j].Severity != "high" })
	return flags
}

// HasHigh reports whether any flag is high severity.
func HasHigh(flags []Flag) bool {
	for _, f := range flags {
		if f.Severity == "high" {
			return true
		}
	}
	return false
}

func scanString(where, s string) []Flag {
	var flags []Flag
	var hidden strings.Builder
	tagCount, invisible := 0, map[rune]int{}
	for _, r := range s {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			// Unicode tag characters render as nothing but map one-to-one
			// onto ASCII, which makes them a way to smuggle text past a
			// human reviewer.
			tagCount++
			if r >= 0xE0020 && r <= 0xE007E {
				hidden.WriteRune(r - 0xE0000)
			}
		case isInvisible(r):
			invisible[r]++
		}
	}
	if tagCount > 0 {
		detail := fmt.Sprintf("%d Unicode tag characters", tagCount)
		if hidden.Len() > 0 {
			detail += fmt.Sprintf(", hidden text: %q", hidden.String())
		}
		flags = append(flags, Flag{"hidden-tag-characters", "high", where, detail})
	}
	if len(invisible) > 0 {
		var parts []string
		for r, n := range invisible {
			parts = append(parts, fmt.Sprintf("U+%04X x%d", r, n))
		}
		sort.Strings(parts)
		flags = append(flags, Flag{"invisible-characters", "high", where, strings.Join(parts, ", ")})
	}
	visible := strings.Map(func(r rune) rune {
		if (r >= 0xE0000 && r <= 0xE007F) || isInvisible(r) {
			return -1
		}
		return r
	}, s)
	if m := reInstructionTag.FindString(visible); m != "" {
		flags = append(flags, Flag{"instruction-tag", "high", where, m})
	}
	if m := reOverride.FindString(visible); m != "" {
		flags = append(flags, Flag{"conceal-or-override", "high", where, m})
	}
	if m := reSensitivePath.FindString(visible); m != "" {
		flags = append(flags, Flag{"sensitive-path", "low", where, strings.TrimSpace(m)})
	}
	if hidden.Len() > 0 {
		h := hidden.String()
		if m := reOverride.FindString(h); m != "" {
			flags = append(flags, Flag{"conceal-or-override", "high", where + " (hidden)", m})
		}
		if m := reSensitivePath.FindString(h); m != "" {
			flags = append(flags, Flag{"sensitive-path", "high", where + " (hidden)", strings.TrimSpace(m)})
		}
	}
	return flags
}

func isInvisible(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, // zero-width space/joiners, LRM, RLM
		r >= 0x202A && r <= 0x202E, // bidi embeddings and overrides
		r >= 0x2060 && r <= 0x2064, // word joiner, invisible operators
		r >= 0x2066 && r <= 0x2069, // bidi isolates
		r == 0xFEFF, r == 0x00AD, r == 0x180E:
		return true
	}
	return false
}

func isIdentifierLike(name string) bool {
	return len(name) >= 4 && strings.ContainsAny(name, "_-.")
}

func mentions(s, name string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], name)
		if j < 0 {
			return false
		}
		j += i
		before, after := j == 0 || !isWordByte(s[j-1]), j+len(name) == len(s) || !isWordByte(s[j+len(name)])
		if before && after {
			return true
		}
		i = j + 1
	}
}

func isWordByte(b byte) bool {
	return b == '_' || b == '-' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// walkStrings calls fn for every string value, with a dotted path.
func walkStrings(v any, path string, fn func(where, s string)) {
	switch x := v.(type) {
	case string:
		fn(path, x)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := k
			if path != "" {
				p = path + "." + k
			}
			walkStrings(x[k], p, fn)
		}
	case []any:
		for i, e := range x {
			walkStrings(e, fmt.Sprintf("%s[%d]", path, i), fn)
		}
	}
}
