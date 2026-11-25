// Package guard is the MCP-aware part of airlock: it looks at each frame,
// records it, and decides what reaches the other side.
package guard

import (
	"github.com/AutumnTrace/airlock/internal/audit"
	"github.com/AutumnTrace/airlock/internal/jsonrpc"
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

// Guard implements proxy.Handler.
type Guard struct {
	rec Recorder
}

// New returns a guard that records to rec (nil records nothing).
func New(rec Recorder) *Guard {
	if rec == nil {
		rec = nopRecorder{}
	}
	return &Guard{rec: rec}
}

var _ proxy.Handler = (*Guard)(nil)

// FromClient handles a frame the client sent.
func (g *Guard) FromClient(frame []byte) proxy.Action {
	m := jsonrpc.Parse(frame)
	g.rec.Msg(audit.ClientToServer, frame, m.JSON)
	return proxy.Pass(frame)
}

// FromServer handles a frame the server sent.
func (g *Guard) FromServer(frame []byte) proxy.Action {
	m := jsonrpc.Parse(frame)
	g.rec.Msg(audit.ServerToClient, frame, m.JSON)
	return proxy.Pass(frame)
}

// Stderr records a line of server stderr.
func (g *Guard) Stderr(line []byte) { g.rec.Stderr(line) }
