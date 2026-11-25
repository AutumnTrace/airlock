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
	"github.com/AutumnTrace/airlock/internal/policy"
	"github.com/AutumnTrace/airlock/internal/proxy"
	"github.com/AutumnTrace/airlock/internal/schema"
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
	// OnNewTool applies to a tool that a lockfile with pins does not know:
	// "allow" or Warn (pin it and go on), or Block.
	OnNewTool string
	// OnSuspicious applies to a tool whose definition trips a high-severity
	// heuristic: Warn or Block.
	OnSuspicious string
	// Policy decides tools/call. Nil allows every call that pinning allows
	// and turns off redaction, argument checks and malformed-frame handling.
	Policy *policy.Policy
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
	schemas map[string]compiled // by definition hash
}

type compiled struct {
	v   *schema.Validator
	err error
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
	if opt.OnNewTool == "" {
		opt.OnNewTool = Warn
	}
	if opt.OnSuspicious == "" {
		opt.OnSuspicious = Warn
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
		schemas: map[string]compiled{},
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
	pol := g.opt.Policy
	if pol != nil {
		if v, bad := g.malformed(m, pol); bad {
			return v
		}
	}
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

// malformed handles client frames that a policy should not let through
// unexamined: frames that are not JSON-RPC at all (dropped when the policy
// says so), and messages with a repeated member, which parsers disagree on.
func (g *Guard) malformed(m *jsonrpc.Message, pol *policy.Policy) (verdict, bool) {
	if m.Kind == jsonrpc.Invalid {
		if !pol.DropMalformed {
			return verdict{}, false
		}
		g.opt.Warn("dropped a malformed frame from the client: " + m.Err.Error())
		return verdict{drop: true, events: []any{&Event{Type: "malformed", Action: "drop", Reason: m.Err.Error()}}}, true
	}
	if m.Kind != jsonrpc.Request && m.Kind != jsonrpc.Notification {
		return verdict{}, false
	}
	k, dup := jsonrpc.DuplicateKey(m.Raw)
	if !dup {
		return verdict{}, false
	}
	reason := fmt.Sprintf("member %q appears twice (names compared without regard to case)", k)
	v := verdict{drop: true, events: []any{&Event{Type: "malformed", ID: m.ID, Action: "drop", Reason: reason}}}
	if m.Kind == jsonrpc.Request {
		v.reply = jsonrpc.ErrorResponse(m.ID, jsonrpc.CodeInvalidRequest, "airlock: "+reason)
	}
	g.opt.Warn("rejected a client message: " + reason)
	return v, true
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// checkCall decides whether a tools/call may reach the server. The checks
// run cheapest and most specific first: pinning, then the policy's rules
// and argument constraints, then the tool's own schema, and the rate limit
// last so that a call refused for another reason does not use up a token.
func (g *Guard) checkCall(m *jsonrpc.Message) verdict {
	var p callParams
	perr := json.Unmarshal(m.Params, &p)

	g.mu.Lock()
	reason, blocked := g.blocked[p.Name]
	def, known := g.tools[p.Name]
	g.mu.Unlock()
	if blocked {
		return g.deny(m, p.Name, "pinning", reason)
	}
	pol := g.opt.Policy
	if pol == nil {
		return verdict{}
	}
	if perr != nil || p.Name == "" {
		return g.deny(m, p.Name, "malformed", "the call has no tool name airlock can read")
	}
	if !known {
		// The client may be using a tool list it cached in an earlier
		// session; a lockfile pin is as good as a listing.
		if e, ok := g.pins.Get(p.Name); ok {
			if t, err := pin.Canonical(e.Definition); err == nil {
				def, known = t, true
			}
		}
	}
	if !known && !pol.UnknownAllow {
		return g.deny(m, p.Name, "unknown-tool", "airlock has not seen a definition for "+p.Name+" in this session or the lockfile; list the tools first")
	}

	args, aerr := decodeArgs(p.Arguments)
	d := pol.Evaluate(p.Name, args)
	if !d.Allow {
		v := g.deny(m, p.Name, d.By, d.Reason)
		v.events[0].(*Event).Rule = ruleRef(d.Rule)
		return v
	}
	if pol.ValidateSchema && known {
		c := g.compile(def)
		if c.err != nil {
			return g.deny(m, p.Name, "schema", "the tool's inputSchema cannot be used for validation: "+c.err.Error())
		}
		if err := c.v.Validate(p.Arguments); err != nil {
			return g.deny(m, p.Name, "schema", err.Error())
		}
	} else if aerr != nil {
		return g.deny(m, p.Name, "malformed", "arguments must be a JSON object")
	}
	if r := pol.Take(d); r != "" {
		v := g.deny(m, p.Name, "rate", r)
		v.events[0].(*Event).Rule = ruleRef(d.Rule)
		return v
	}
	return verdict{events: []any{&Event{Type: "allow", ID: m.ID, Tool: p.Name, By: d.By, Rule: ruleRef(d.Rule)}}}
}

func ruleRef(n int) *int {
	if n == 0 {
		return nil
	}
	return &n
}

func decodeArgs(raw json.RawMessage) (map[string]any, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return map[string]any{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var args map[string]any
	if err := dec.Decode(&args); err != nil {
		return nil, err
	}
	return args, nil
}

func (g *Guard) compile(t pin.Tool) compiled {
	g.mu.Lock()
	c, ok := g.schemas[t.Hash]
	g.mu.Unlock()
	if ok {
		return c
	}
	if len(t.Schema) == 0 {
		c = compiled{err: fmt.Errorf("the tool declares no inputSchema")}
	} else {
		v, err := schema.Compile(t.Schema)
		c = compiled{v: v, err: err}
	}
	g.mu.Lock()
	g.schemas[t.Hash] = c
	g.mu.Unlock()
	return c
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
		events: []any{&Event{Type: "deny", ID: m.ID, Tool: tool, By: by, Reason: reason}},
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
		return &Event{Type: "protocol", Version: v, Via: "_meta"}
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
			return verdict{events: []any{&Event{Type: "protocol", Version: r.ProtocolVersion, Via: "initialize"}}}
		}
	case "tools/list":
		return g.toolsList(m, p)
	case "tools/call", "resources/read", "prompts/get":
		return g.redact(m, p)
	}
	return verdict{}
}

// redact replaces secrets in a result before the client, and so the model,
// sees them. The log records the redacted version too.
func (g *Guard) redact(m *jsonrpc.Message, p pending) verdict {
	if g.opt.Policy == nil || g.opt.Policy.Redactor.Empty() {
		return verdict{}
	}
	out, counts, err := g.opt.Policy.Redactor.JSON(m.Result)
	if err != nil || counts == nil {
		return verdict{}
	}
	frame, err := jsonrpc.WithResult(m, out)
	if err != nil {
		return verdict{}
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	what := p.method
	if p.tool != "" {
		what = p.tool
	}
	g.opt.Warn(fmt.Sprintf("redacted %d secret(s) from the result of %s", total, what))
	return verdict{frame: frame, events: []any{&Event{Type: "redact", ID: m.ID, Tool: p.tool, Redactions: counts}}}
}
