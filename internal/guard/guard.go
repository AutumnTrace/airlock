// Package guard is the MCP-aware part of airlock: it looks at each frame,
// records it, and decides what reaches the other side.
package guard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/AutumnTrace/airlock/internal/audit"
	"github.com/AutumnTrace/airlock/internal/jsonrpc"
	"github.com/AutumnTrace/airlock/internal/pin"
	"github.com/AutumnTrace/airlock/internal/proxy"
)

// Recorder is the part of an audit.Writer the guard uses.
type Recorder interface {
	Msg(dir string, frame []byte, isJSON bool)
	Event(ev any)
	Stderr(line []byte)
}

type nopRecorder struct{}

func (nopRecorder) Msg(string, []byte, bool) {}
func (nopRecorder) Event(any)                {}
func (nopRecorder) Stderr([]byte)            {}

// What to do about a tool whose definition changed.
const (
	Warn  = "warn"
	Block = "block"
)

// Options configure a Guard.
type Options struct {
	// Pins holds approved tool definitions. Nil means a fresh in-memory set.
	Pins *pin.Set
	// OnDrift is Warn (the default) or Block.
	OnDrift string
	// Repin accepts every definition the server lists as the new pin.
	Repin bool
	// Warn receives one-line human-readable warnings. Nil discards them.
	Warn func(msg string)
	// Now is the clock, for tests.
	Now func() time.Time
}

type pending struct {
	method string
	tool   string
	cursor bool // a tools/list request for a page after the first
}

// Guard implements proxy.Handler.
type Guard struct {
	rec  Recorder
	opt  Options
	pins *pin.Set

	mu      sync.Mutex
	pending map[string]pending
	proto   string
	tools   map[string]pin.Tool // what the client was last shown
	blocked map[string]string   // tool name -> reason
}

var _ proxy.Handler = (*Guard)(nil)

// New returns a guard that records to rec (nil records nothing).
func New(rec Recorder, opt Options) *Guard {
	if rec == nil {
		rec = nopRecorder{}
	}
	if opt.Pins == nil {
		opt.Pins, _ = pin.Load("")
	}
	if opt.OnDrift == "" {
		opt.OnDrift = Warn
	}
	if opt.Warn == nil {
		opt.Warn = func(string) {}
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Guard{
		rec: rec, opt: opt, pins: opt.Pins,
		pending: map[string]pending{},
		tools:   map[string]pin.Tool{},
		blocked: map[string]string{},
	}
}

// verdict is the outcome for one message.
type verdict struct {
	drop   bool   // do not forward
	frame  []byte // forward this instead of the original (nil: original)
	reply  []byte // answer the sender with this
	events []any
}

// FromClient handles a frame the client sent.
func (g *Guard) FromClient(frame []byte) proxy.Action {
	m := jsonrpc.Parse(frame)
	if m.Kind == jsonrpc.Batch {
		return g.batch(frame, m)
	}
	v := g.client(m)
	return g.finish(frame, m.JSON, v, audit.ClientToServer, audit.ClientToAirlock)
}

// FromServer handles a frame the server sent.
func (g *Guard) FromServer(frame []byte) proxy.Action {
	m := jsonrpc.Parse(frame)
	var v verdict
	if m.Kind == jsonrpc.Response {
		v = g.response(m)
	}
	return g.finish(frame, m.JSON, v, audit.ServerToClient, audit.ServerToAirlock)
}

// Stderr records a line of server stderr.
func (g *Guard) Stderr(line []byte) { g.rec.Stderr(line) }

// finish records a message and its events and turns the verdict into an
// action. Order in the log: what arrived (or what was forwarded in its
// place), then airlock's events, then airlock's reply.
func (g *Guard) finish(frame []byte, isJSON bool, v verdict, fwdDir, stopDir string) proxy.Action {
	var act proxy.Action
	switch {
	case v.drop:
		g.rec.Msg(stopDir, frame, isJSON)
	case v.frame != nil:
		g.rec.Msg(fwdDir, v.frame, true)
		act.Forward = [][]byte{v.frame}
	default:
		g.rec.Msg(fwdDir, frame, isJSON)
		act.Forward = [][]byte{frame}
	}
	for _, e := range v.events {
		g.rec.Event(e)
	}
	if v.reply != nil {
		g.rec.Msg(audit.AirlockToClient, v.reply, true)
		act.Reply = [][]byte{v.reply}
	}
	return act
}

// batch handles a JSON-RPC batch member by member, so nothing inside a batch
// gets past a check that the same message would fail on its own.
func (g *Guard) batch(frame []byte, m *jsonrpc.Message) proxy.Action {
	var fwd, replies [][]byte
	var events []any
	touched := false
	for _, e := range m.Elems {
		v := g.client(e)
		events = append(events, v.events...)
		switch {
		case v.drop:
			touched = true
		case v.frame != nil:
			touched = true
			fwd = append(fwd, v.frame)
		default:
			fwd = append(fwd, bytes.TrimSpace(e.Raw))
		}
		if v.reply != nil {
			replies = append(replies, v.reply)
		}
	}
	if !touched {
		return g.finish(frame, true, verdict{events: events}, audit.ClientToServer, audit.ClientToAirlock)
	}
	g.rec.Msg(audit.ClientToAirlock, frame, true)
	var act proxy.Action
	if len(fwd) > 0 {
		b := joinBatch(fwd)
		g.rec.Msg(audit.ClientToServer, b, true)
		act.Forward = [][]byte{b}
	}
	for _, e := range events {
		g.rec.Event(e)
	}
	if len(replies) > 0 {
		b := joinBatch(replies)
		g.rec.Msg(audit.AirlockToClient, b, true)
		act.Reply = [][]byte{b}
	}
	return act
}

func joinBatch(parts [][]byte) []byte {
	return append(append([]byte{'['}, bytes.Join(parts, []byte{','})...), ']')
}

// client looks at one client message.
func (g *Guard) client(m *jsonrpc.Message) verdict {
	if m.Kind != jsonrpc.Request {
		return verdict{}
	}
	var events []any
	if ev := g.noteRequest(m); ev != nil {
		events = append(events, ev)
	}
	if m.Method == "tools/call" {
		v := g.checkCall(m)
		v.events = append(events, v.events...)
		return v
	}
	return verdict{events: events}
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Meta      json.RawMessage `json:"_meta"`
}

// checkCall decides whether a tools/call may reach the server.
func (g *Guard) checkCall(m *jsonrpc.Message) verdict {
	var p callParams
	_ = json.Unmarshal(m.Params, &p)
	g.mu.Lock()
	reason, blocked := g.blocked[p.Name]
	g.mu.Unlock()
	if blocked {
		return g.deny(m, p.Name, "pinning", reason)
	}
	return verdict{}
}

// deny answers a tools/call without forwarding it. The answer is a tool
// result with isError set rather than a JSON-RPC error: the spec routes
// tool-level failures through the result so the model sees the reason and
// can change course.
func (g *Guard) deny(m *jsonrpc.Message, tool, by, reason string) verdict {
	g.forget(m.ID)
	result := map[string]any{
		"content": []map[string]any{{"type": "text", "text": "airlock blocked this call: " + reason}},
		"isError": true,
	}
	if g.statelessProtocol() {
		result["resultType"] = "complete"
	}
	g.opt.Warn(fmt.Sprintf("blocked %s: %s", tool, reason))
	return verdict{
		drop:   true,
		reply:  jsonrpc.ResultResponse(m.ID, result),
		events: []any{Event{Type: "deny", ID: m.ID, Tool: tool, By: by, Reason: reason}},
	}
}

const metaProtocolVersion = "io.modelcontextprotocol/protocolVersion"

// noteRequest remembers a request so its response can be matched, and
// picks up the protocol version from initialize or from _meta (2026-07-28
// and later carry it on every request).
func (g *Guard) noteRequest(m *jsonrpc.Message) any {
	var p struct {
		Name            string                     `json:"name"`
		Cursor          string                     `json:"cursor"`
		ProtocolVersion string                     `json:"protocolVersion"`
		Meta            map[string]json.RawMessage `json:"_meta"`
	}
	_ = json.Unmarshal(m.Params, &p)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pending[jsonrpc.IDKey(m.ID)] = pending{method: m.Method, tool: p.Name, cursor: p.Cursor != ""}
	var v string
	if raw, ok := p.Meta[metaProtocolVersion]; ok {
		_ = json.Unmarshal(raw, &v)
	}
	if v != "" && v != g.proto {
		g.proto = v
		return Event{Type: "protocol", Version: v, Via: "_meta"}
	}
	return nil
}

func (g *Guard) forget(id json.RawMessage) {
	g.mu.Lock()
	delete(g.pending, jsonrpc.IDKey(id))
	g.mu.Unlock()
}

func (g *Guard) take(id json.RawMessage) (pending, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := jsonrpc.IDKey(id)
	p, ok := g.pending[k]
	delete(g.pending, k)
	return p, ok
}

// statelessProtocol reports whether the session speaks 2026-07-28 or later,
// where every result carries resultType.
func (g *Guard) statelessProtocol() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.proto >= "2026-07-28"
}

// response looks at a server response to a client request.
func (g *Guard) response(m *jsonrpc.Message) verdict {
	p, ok := g.take(m.ID)
	if !ok || m.Result == nil {
		return verdict{}
	}
	switch p.method {
	case "initialize":
		var r struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(m.Result, &r) == nil && r.ProtocolVersion != "" {
			g.mu.Lock()
			g.proto = r.ProtocolVersion
			g.mu.Unlock()
			return verdict{events: []any{Event{Type: "protocol", Version: r.ProtocolVersion, Via: "initialize"}}}
		}
	case "tools/list":
		return g.toolsList(m, p)
	}
	return verdict{}
}
