package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/AutumnTrace/airlock/internal/pin"
	"github.com/AutumnTrace/airlock/internal/textdiff"
)

// cmdDiff compares two lockfiles tool by tool, for reviewing a server
// upgrade before accepting it with --repin. Exit codes follow diff(1): 0 the
// pins are the same, 1 they differ, 2 a lockfile could not be read.
func cmdDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: airlock diff <old.lock.json> <new.lock.json>

Compare two lockfiles: tools added, removed and changed, a word diff of
changed descriptions, a line diff of the rest of each changed definition,
and the description heuristics run on every added or changed tool.
Exit 0 if the pins are the same, 1 if they differ, 2 if a file can't be read.

To make the new lockfile, run the upgraded server under airlock with --lock
naming a file that does not exist yet. With no pins to compare against,
airlock pins every tool the server lists (trust on first use).`)
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return 2
	}
	oldPins, err := readPins(fs.Arg(0), stderr)
	if err != nil {
		fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 2
	}
	newPins, err := readPins(fs.Arg(1), stderr)
	if err != nil {
		fmt.Fprintf(stderr, "airlock: %v\n", err)
		return 2
	}
	d := diffPins(oldPins, newPins)
	d.write(stdout)
	if d.same() {
		return 0
	}
	return 1
}

// readPins loads every tool of a lockfile in canonical form. Unlike a
// session, a diff has no use for a lockfile that does not exist.
func readPins(path string, stderr io.Writer) (map[string]pin.Tool, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: no such lockfile", path)
	}
	set, err := pin.Load(path)
	if err != nil {
		return nil, err
	}
	tools := map[string]pin.Tool{}
	for _, name := range set.Names() {
		e, _ := set.Get(name)
		t, err := pin.Canonical(e.Definition)
		if err != nil {
			return nil, fmt.Errorf("%s: pin for %q: %w", path, name, err)
		}
		if t.Name != name {
			return nil, fmt.Errorf("%s: pin %q holds the definition of %q", path, name, t.Name)
		}
		if e.SHA256 != t.Hash {
			// A hand-edited lockfile. Compare what the definitions say,
			// which is what a session would check against.
			fmt.Fprintf(stderr, "airlock: warning: %s: pin for %q: sha256 does not match its definition\n", path, name)
		}
		tools[name] = t
	}
	return tools, nil
}

type toolChange struct {
	name     string
	old, new pin.Tool // old is zero for an added tool
	flags    []pin.Flag
	known    map[string]bool // flags the old definition already had, by rule and place
}

type pinDiff struct {
	added, removed []string
	changed        []toolChange
	addedTools     []toolChange
	unchanged      int
}

func (d pinDiff) same() bool {
	return len(d.added) == 0 && len(d.removed) == 0 && len(d.changed) == 0
}

func diffPins(oldPins, newPins map[string]pin.Tool) pinDiff {
	var d pinDiff
	newNames := make([]string, 0, len(newPins))
	for n := range newPins {
		newNames = append(newNames, n)
	}
	sort.Strings(newNames)
	oldNames := make([]string, 0, len(oldPins))
	for n := range oldPins {
		oldNames = append(oldNames, n)
	}
	sort.Strings(oldNames)

	for _, n := range newNames {
		nt := newPins[n]
		ot, existed := oldPins[n]
		switch {
		case !existed:
			d.added = append(d.added, n)
			d.addedTools = append(d.addedTools, toolChange{name: n, new: nt, flags: pin.Scan(nt, newNames)})
		case ot.Hash != nt.Hash:
			known := map[string]bool{}
			for _, f := range pin.Scan(ot, oldNames) {
				known[f.Rule+"\x00"+f.Where] = true
			}
			d.changed = append(d.changed, toolChange{name: n, old: ot, new: nt, flags: pin.Scan(nt, newNames), known: known})
		default:
			d.unchanged++
		}
	}
	for _, n := range oldNames {
		if _, ok := newPins[n]; !ok {
			d.removed = append(d.removed, n)
		}
	}
	return d
}

func (d pinDiff) write(w io.Writer) {
	for _, c := range d.changed {
		fmt.Fprintf(w, "changed  %s  sha256 %s -> %s\n", c.name, c.old.Hash[:16], c.new.Hash[:16])
		oldDesc, newDesc := description(c.old), description(c.new)
		if oldDesc != newDesc {
			fmt.Fprintln(w, "  description:")
			fmt.Fprintf(w, "    %s\n", wordDiff(oldDesc, newDesc))
		}
		if lines := lineDiff(withoutDescription(c.old.Def), withoutDescription(c.new.Def)); len(lines) > 0 {
			if oldDesc != newDesc {
				fmt.Fprintln(w, "  rest of the definition:")
			} else {
				fmt.Fprintln(w, "  definition:")
			}
			for _, l := range lines {
				fmt.Fprintf(w, "    %s\n", l)
			}
		}
		writeFlags(w, c)
	}
	for _, c := range d.addedTools {
		fmt.Fprintf(w, "added    %s  sha256 %s\n", c.name, c.new.Hash[:16])
		writeFlags(w, c)
	}
	for _, n := range d.removed {
		fmt.Fprintf(w, "removed  %s\n", n)
	}
	if !d.same() {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%d changed, %d added, %d removed, %d unchanged\n", len(d.changed), len(d.added), len(d.removed), d.unchanged)
}

func writeFlags(w io.Writer, c toolChange) {
	if len(c.flags) == 0 {
		return
	}
	fmt.Fprintln(w, "  heuristic flags:")
	for _, f := range c.flags {
		note := ""
		if c.known[f.Rule+"\x00"+f.Where] {
			note = "  (already in the old definition)"
		}
		fmt.Fprintf(w, "    %-4s  %s  %s: %s%s\n", f.Severity, f.Rule, f.Where, pin.Visible(f.Detail), note)
	}
}

func description(t pin.Tool) string {
	var v struct {
		Description string `json:"description"`
	}
	_ = json.Unmarshal(t.Def, &v)
	return v.Description
}

// wordDiff renders a word diff the way git diff --word-diff=plain does:
// [-removed-] and {+added+}. Long unchanged stretches are shortened.
func wordDiff(a, b string) string {
	var out strings.Builder
	for _, p := range textdiff.Merge(textdiff.Diff(textdiff.Words(a), textdiff.Words(b))) {
		text := pin.Visible(p.Text)
		switch p.Op {
		case textdiff.Del:
			out.WriteString("[-" + text + "-]")
		case textdiff.Ins:
			out.WriteString("{+" + text + "+}")
		default:
			out.WriteString(elide(text, 40))
		}
	}
	return out.String()
}

// elide keeps keep runes at each end of a long unchanged stretch.
func elide(s string, keep int) string {
	if utf8.RuneCountInString(s) <= 2*keep+5 {
		return s
	}
	r := []rune(s)
	return string(r[:keep]) + " … " + string(r[len(r)-keep:])
}

// withoutDescription drops the top-level description, which wordDiff shows,
// from a canonical definition.
func withoutDescription(def json.RawMessage) json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(def))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return def
	}
	delete(v, "description")
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return def
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// lineDiff is a line diff of two indented definitions with two lines of
// context around each change, or nil when they are equal.
func lineDiff(a, b json.RawMessage) []string {
	if bytes.Equal(a, b) {
		return nil
	}
	parts := textdiff.Diff(strings.Split(string(a), "\n"), strings.Split(string(b), "\n"))
	const context = 2
	show := make([]bool, len(parts))
	for i, p := range parts {
		if p.Op == textdiff.Eq {
			continue
		}
		for j := max(0, i-context); j <= min(len(parts)-1, i+context); j++ {
			show[j] = true
		}
	}
	var out []string
	gap := false
	for i, p := range parts {
		if !show[i] {
			gap = true
			continue
		}
		if gap && len(out) > 0 {
			out = append(out, "  ...")
		}
		gap = false
		sign := "  "
		switch p.Op {
		case textdiff.Del:
			sign = "- "
		case textdiff.Ins:
			sign = "+ "
		}
		out = append(out, sign+pin.Visible(p.Text))
	}
	return out
}
