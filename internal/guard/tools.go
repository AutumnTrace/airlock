package guard

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/AutumnTrace/airlock/internal/jsonrpc"
	"github.com/AutumnTrace/airlock/internal/pin"
)

// Event is what airlock writes to the log about its own decisions. Fields
// that do not apply to a type are left out.
type Event struct {
	Type    string          `json:"type"`
	ID      json.RawMessage `json:"id,omitempty"` // the JSON-RPC id it concerns
	Tool    string          `json:"tool,omitempty"`
	Tools   []string        `json:"tools,omitempty"`
	By      string          `json:"by,omitempty"` // which check: pinning, policy, schema, rate, ...
	Rule    *int            `json:"rule,omitempty"`
	Action  string          `json:"action,omitempty"`
	Reason  string          `json:"reason,omitempty"`
	Version string          `json:"version,omitempty"`
	Via     string          `json:"via,omitempty"`

	OldHash string          `json:"old_sha256,omitempty"`
	NewHash string          `json:"new_sha256,omitempty"`
	Old     json.RawMessage `json:"old,omitempty"`
	New     json.RawMessage `json:"new,omitempty"`
	Flags   []pin.Flag      `json:"flags,omitempty"`

	Redactions map[string]int `json:"redactions,omitempty"`
}

// toolsList checks each listed tool against its pin and, when the policy
// says block, takes changed tools out of the list before the client sees it.
func (g *Guard) toolsList(m *jsonrpc.Message, req pending) verdict {
	var res map[string]json.RawMessage
	if err := json.Unmarshal(m.Result, &res); err != nil {
		return verdict{}
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(res["tools"], &raws); err != nil {
		return verdict{}
	}
	parsed := make([]pin.Tool, len(raws))
	names := make([]string, 0, len(raws))
	for i, r := range raws {
		if t, err := pin.Canonical(r); err == nil {
			parsed[i] = t
			names = append(names, t.Name)
		}
	}

	now := g.opt.Now()
	var events []any
	var firstPins, repinned []string
	keep := make([]json.RawMessage, 0, len(raws))
	filtered := false
	seen := map[string]bool{}

	for i, raw := range raws {
		t := parsed[i]
		if t.Name == "" {
			keep = append(keep, raw) // not a tool we can parse; the client will judge
			continue
		}
		seen[t.Name] = true
		flags := pin.Scan(t, names)
		status, old := g.pins.Check(t)

		switch {
		case status == pin.Same:
			g.accept(t)
		case g.opt.Repin && status != pin.Same:
			g.pins.Pin(t, now)
			g.accept(t)
			repinned = append(repinned, t.Name)
		case status == pin.New:
			g.pins.Pin(t, now)
			g.accept(t)
			if g.pins.FromLockfile() {
				events = append(events, Event{Type: "new_tool", Tool: t.Name, NewHash: t.Hash, New: t.Def, Action: Warn})
				g.opt.Warn(fmt.Sprintf("new tool %q is not in the lockfile; pinned it", t.Name))
			} else {
				firstPins = append(firstPins, t.Name)
			}
		case status == pin.Changed:
			ev := Event{Type: "drift", Tool: t.Name, Action: g.opt.OnDrift, OldHash: old.SHA256, NewHash: t.Hash, Old: old.Definition, New: t.Def, Flags: flags}
			events = append(events, ev)
			if g.opt.OnDrift == Block {
				g.block(t.Name, "the tool's definition changed since it was pinned (hash "+short(old.SHA256)+" -> "+short(t.Hash)+")")
				filtered = true
				g.opt.Warn(fmt.Sprintf("tool %q changed since it was pinned; hidden from the client and blocked (review, then run with --repin to accept)", t.Name))
				continue
			}
			g.accept(t)
			g.opt.Warn(fmt.Sprintf("tool %q changed since it was pinned (on_drift = warn)", t.Name))
		}
		if len(flags) > 0 && status != pin.Changed {
			events = append(events, Event{Type: "suspicious", Tool: t.Name, Flags: flags, Action: Warn})
			if pin.HasHigh(flags) {
				g.opt.Warn(fmt.Sprintf("tool %q: %s (%s)", t.Name, flags[0].Rule, flags[0].Detail))
			}
		}
		keep = append(keep, raw)
	}

	if len(firstPins) > 0 {
		sort.Strings(firstPins)
		events = append([]any{Event{Type: "pin", Tools: firstPins}}, events...)
	}
	if len(repinned) > 0 {
		events = append(events, Event{Type: "repin", Tools: repinned})
	}
	if _, more := res["nextCursor"]; !more && !req.cursor {
		if gone := g.missing(seen); len(gone) > 0 {
			events = append(events, Event{Type: "removed", Tools: gone})
		}
	}
	if err := g.pins.Save(); err != nil {
		g.opt.Warn("cannot save the lockfile: " + err.Error())
	}

	v := verdict{events: events}
	if filtered {
		b, _ := jsonrpc.Marshal(keep)
		res["tools"] = b
		nr, _ := jsonrpc.Marshal(res)
		if frame, err := jsonrpc.WithResult(m, nr); err == nil {
			v.frame = frame
		}
	}
	return v
}

func (g *Guard) accept(t pin.Tool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tools[t.Name] = t
	delete(g.blocked, t.Name)
}

func (g *Guard) block(name, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.tools, name)
	g.blocked[name] = reason
}

// missing lists tools the client was shown before that a complete listing
// no longer has.
func (g *Guard) missing(seen map[string]bool) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var gone []string
	for n := range g.tools {
		if !seen[n] {
			gone = append(gone, n)
			delete(g.tools, n)
		}
	}
	sort.Strings(gone)
	return gone
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
