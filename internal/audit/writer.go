package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Options tune a Writer.
type Options struct {
	// Key signs checkpoints and the closing record. Nil means unsigned.
	Key ed25519.PrivateKey
	// CheckpointEvery is the number of records between signed checkpoints.
	// Zero means 256. Ignored without Key.
	CheckpointEvery int
	// Now is the clock, for tests.
	Now func() time.Time
}

// Writer appends records to a session log. It is safe for concurrent use;
// records are chained in the order their calls take the lock.
type Writer struct {
	mu     sync.Mutex
	w      io.Writer
	c      io.Closer
	buf    []byte
	seq    uint64
	prev   string
	key    ed25519.PrivateKey
	every  int
	since  int
	now    func() time.Time
	err    error
	closed bool
	Path   string
}

// Create makes the log file (and its directory) and writes the header.
func Create(path string, h Header, opts Options) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	w, err := NewWriter(f, h, opts)
	if err != nil {
		f.Close()
		return nil, err
	}
	w.c, w.Path = f, path
	return w, nil
}

// NewWriter writes the header to w and returns a Writer for the rest.
func NewWriter(w io.Writer, h Header, opts Options) (*Writer, error) {
	lw := &Writer{w: w, prev: ZeroHash, key: opts.Key, every: opts.CheckpointEvery, now: opts.Now}
	if lw.every <= 0 {
		lw.every = 256
	}
	if lw.now == nil {
		lw.now = time.Now
	}
	if lw.key != nil {
		h.Key = PublicKeyString(lw.key.Public().(ed25519.PublicKey))
	}
	hb, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	lw.mu.Lock()
	defer lw.mu.Unlock()
	lw.append(KindOpen, func(b []byte) []byte { return append(append(b, `,"session":`...), hb...) })
	return lw, lw.err
}

func (w *Writer) append(kind string, fields func([]byte) []byte) {
	if w.err != nil || w.closed {
		return
	}
	var h string
	w.buf, h = appendRecord(w.buf[:0], w.seq, w.now(), kind, w.prev, fields)
	if _, err := w.w.Write(w.buf); err != nil {
		w.err = err
		return
	}
	w.seq++
	w.prev = h
	if w.key != nil && kind != KindCheckpoint && kind != KindOpen && kind != KindClose {
		w.since++
		if w.since >= w.every {
			w.checkpoint()
		}
	}
}

func (w *Writer) checkpoint() {
	sig := ed25519.Sign(w.key, signedBytes(KindCheckpoint, w.seq, w.prev))
	w.since = 0
	w.append(KindCheckpoint, func(b []byte) []byte {
		return appendString(b, "sig", base64.StdEncoding.EncodeToString(sig))
	})
}

// signedBytes is what a checkpoint or closing record signs: its kind, its
// own sequence number and the hash of the record before it.
func signedBytes(kind string, seq uint64, prev string) []byte {
	return []byte("airlock " + kind + " v1\n" + strconv.FormatUint(seq, 10) + "\n" + prev)
}

// Msg records a frame. isJSON says whether the frame parsed as JSON; frames
// that did not are stored as text.
func (w *Writer) Msg(dir string, frame []byte, isJSON bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.append(KindMsg, func(b []byte) []byte {
		b = appendString(b, "dir", dir)
		return appendJSONField(b, "msg", frame, isJSON)
	})
}

// Event records something airlock decided or noticed. ev must marshal to a
// JSON object with at least a "type" member.
func (w *Writer) Event(ev any) {
	eb, err := json.Marshal(ev)
	if err != nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.append(KindEvent, func(b []byte) []byte { return append(append(b, `,"event":`...), eb...) })
}

// Stderr records one line the server wrote to stderr.
func (w *Writer) Stderr(line []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.append(KindStderr, func(b []byte) []byte { return appendJSONField(b, "line", line, false) })
}

// Close writes the closing record (signed, with a key), closes the file and
// returns the final chain head: the hash to keep somewhere else if you want
// to detect truncation without a key.
func (w *Writer) Close(exitCode int) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.prev, w.err
	}
	records := w.seq
	w.append(KindClose, func(b []byte) []byte {
		b = append(b, `,"exit":`...)
		b = strconv.AppendInt(b, int64(exitCode), 10)
		b = append(b, `,"records":`...)
		b = strconv.AppendUint(b, records, 10)
		if w.key != nil {
			sig := ed25519.Sign(w.key, signedBytes(KindClose, w.seq, w.prev))
			b = appendString(b, "sig", base64.StdEncoding.EncodeToString(sig))
		}
		return b
	})
	w.closed = true
	if w.c != nil {
		if err := w.c.Close(); err != nil && w.err == nil {
			w.err = err
		}
	}
	return w.prev, w.err
}

// Err reports the first write error, if any. After a write error the
// Writer stops recording; the proxy keeps running.
func (w *Writer) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}
