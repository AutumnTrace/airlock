// Package pin fingerprints MCP tool definitions and remembers them, so a
// server cannot change what a tool says it does after the user agreed to it.
package pin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Tool is one definition from a tools/list result, in canonical form.
type Tool struct {
	Name   string
	Hash   string          // hex SHA-256 of Def
	Def    json.RawMessage // canonical JSON, _meta removed
	Schema json.RawMessage // the inputSchema member of Def, if any
}

// Canonical parses a tool definition and returns it in a stable form: keys
// sorted at every level, numbers kept as written, no HTML escaping, and the
// top-level _meta member dropped (it is for out-of-band data that may change
// on every listing). Everything else counts: name, title, description,
// inputSchema, outputSchema, annotations, icons and any field a later spec
// revision adds.
func Canonical(raw json.RawMessage) (Tool, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return Tool{}, err
	}
	name, _ := v["name"].(string)
	if name == "" {
		return Tool{}, errors.New("tool has no name")
	}
	delete(v, "_meta")
	def, err := encode(v)
	if err != nil {
		return Tool{}, err
	}
	sum := sha256.Sum256(def)
	t := Tool{Name: name, Hash: hex.EncodeToString(sum[:]), Def: def}
	if s, ok := v["inputSchema"]; ok {
		t.Schema, _ = encode(s)
	}
	return t, nil
}

func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Status is how a definition compares with its pin.
type Status int

const (
	Same    Status = iota
	New            // never pinned
	Changed        // pinned with a different hash
)

// Entry is a pinned definition.
type Entry struct {
	SHA256     string          `json:"sha256"`
	PinnedAt   time.Time       `json:"pinned_at"`
	Definition json.RawMessage `json:"definition"`
}

type lockfile struct {
	Comment string           `json:"//"`
	Version int              `json:"version"`
	Tools   map[string]Entry `json:"tools"`
}

const lockComment = "airlock tool pins: the definitions this server's tools had when they were approved. Review changes before running with --repin."

// Set is the collection of pins for one server. With a path it is backed by
// a lockfile; without one it lives for the session only, which still
// catches a definition that changes mid-session.
type Set struct {
	mu     sync.Mutex
	path   string
	pins   map[string]Entry
	loaded bool // a lockfile with pins existed when the session started
	dirty  bool
}

// Load reads the lockfile at path. A missing file is an empty set. An empty
// path makes an in-memory set.
func Load(path string) (*Set, error) {
	s := &Set{path: path, pins: map[string]Entry{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var lf lockfile
	if err := json.Unmarshal(b, &lf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if lf.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported lockfile version %d", path, lf.Version)
	}
	for k, e := range lf.Tools {
		s.pins[k] = e
	}
	s.loaded = len(s.pins) > 0
	return s, nil
}

// Path is the lockfile path, or "" for an in-memory set.
func (s *Set) Path() string { return s.path }

// FromLockfile reports whether pins were loaded from disk, which is what
// makes a tool that has never been seen "new" rather than just "first".
func (s *Set) FromLockfile() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loaded
}

// Check compares t with its pin.
func (s *Set) Check(t Tool) (Status, Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.pins[t.Name]
	switch {
	case !ok:
		return New, Entry{}
	case e.SHA256 != t.Hash:
		return Changed, e
	}
	return Same, e
}

// Get returns the pin for a tool name.
func (s *Set) Get(name string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.pins[name]
	return e, ok
}

// Pin records t as the approved definition.
func (s *Set) Pin(t Tool, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins[t.Name] = Entry{SHA256: t.Hash, PinnedAt: now.UTC(), Definition: t.Def}
	s.dirty = true
}

// Names lists pinned tools in order.
func (s *Set) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.pins))
	for n := range s.pins {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Save writes the lockfile if anything changed. It writes a temporary file
// and renames it over the old one, so a crash never leaves half a lockfile.
func (s *Set) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" || !s.dirty {
		return nil
	}
	b, err := json.MarshalIndent(lockfile{Comment: lockComment, Version: 1, Tools: s.pins}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".airlock-lock-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	s.dirty = false
	return nil
}
