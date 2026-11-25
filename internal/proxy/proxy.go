// Package proxy moves frames between an MCP client and a server process and
// lets a Handler decide what happens to each one.
package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"sync"

	"github.com/AutumnTrace/airlock/internal/jsonrpc"
)

// Action is a handler's verdict on one frame.
type Action struct {
	// Forward goes on to the other side: client frames to the server,
	// server frames to the client.
	Forward [][]byte
	// Reply goes back to whoever sent the frame. This is how a blocked
	// request gets its answer without the server ever seeing it.
	Reply [][]byte
}

// Pass forwards a frame unchanged.
func Pass(frame []byte) Action { return Action{Forward: [][]byte{frame}} }

// Handler sees every frame in both directions. FromClient and FromServer are
// called from different goroutines and may run at the same time.
type Handler interface {
	FromClient(frame []byte) Action
	FromServer(frame []byte) Action
	// Stderr receives each line the server writes to stderr. The line has
	// already been copied to airlock's own stderr.
	Stderr(line []byte)
}

// Passthrough forwards everything and looks at nothing.
type Passthrough struct{}

func (Passthrough) FromClient(f []byte) Action { return Pass(f) }
func (Passthrough) FromServer(f []byte) Action { return Pass(f) }
func (Passthrough) Stderr([]byte)              {}

// Pipes are the four ends a proxy connects.
type Pipes struct {
	ClientIn  io.Reader      // what the MCP client writes (our stdin)
	ClientOut io.Writer      // what the MCP client reads (our stdout)
	ServerIn  io.WriteCloser // the server's stdin
	ServerOut io.Reader      // the server's stdout
	ServerErr io.Reader      // the server's stderr, may be nil
	ErrOut    io.Writer      // where server stderr is copied, may be nil
}

// syncWriter serialises whole frames onto one stream, so a reply written by
// one pump can never interleave with a forward written by the other.
type syncWriter struct {
	mu  sync.Mutex
	w   io.Writer
	buf []byte
	err error
}

func (s *syncWriter) writeFrame(frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.buf = append(append(s.buf[:0], frame...), '\n')
	_, s.err = s.w.Write(s.buf)
	return s.err
}

// Run pumps frames until the server's stdout closes. When the client closes
// its side, the server's stdin is closed too, which is how an MCP stdio
// client asks a server to shut down. Run returns after both server output
// streams are drained, which is the point where exec.Cmd.Wait may be called.
func Run(p Pipes, h Handler) error {
	toClient := &syncWriter{w: p.ClientOut}
	toServer := &syncWriter{w: p.ServerIn}

	var wg sync.WaitGroup

	go func() {
		// Client -> server. This goroutine is not waited for: the client may
		// keep its stdin open after the server has gone away.
		_ = pump(p.ClientIn, h.FromClient, toServer, toClient)
		_ = p.ServerIn.Close()
	}()

	if p.ServerErr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			copyStderr(p.ServerErr, p.ErrOut, h.Stderr)
		}()
	}

	serverErr := pump(p.ServerOut, h.FromServer, toClient, toServer)
	wg.Wait()
	if !errors.Is(serverErr, io.EOF) {
		return serverErr
	}
	return nil
}

// pump reads frames from src, asks decide, and writes the results. Write
// errors on the forward side end the pump; write errors on the reply side are
// ignored, because the peer that would read them is already gone.
func pump(src io.Reader, decide func([]byte) Action, forward, reply *syncWriter) error {
	fr := jsonrpc.NewFrameReader(src)
	for {
		frame, err := fr.Next()
		if frame != nil {
			act := decide(frame)
			for _, f := range act.Reply {
				_ = reply.writeFrame(f)
			}
			for _, f := range act.Forward {
				if werr := forward.writeFrame(f); werr != nil {
					drain(fr)
					return werr
				}
			}
		}
		if err != nil {
			return err
		}
	}
}

// drain keeps reading after the far side has gone so the writer is never
// blocked on a full pipe.
func drain(fr *jsonrpc.FrameReader) {
	for {
		if _, err := fr.Next(); err != nil {
			return
		}
	}
}

func copyStderr(r io.Reader, out io.Writer, sink func([]byte)) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if out != nil {
				_, _ = out.Write(line)
			}
			if trimmed := bytes.TrimRight(line, "\r\n"); len(trimmed) > 0 {
				sink(trimmed)
			}
		}
		if err != nil {
			return
		}
	}
}
