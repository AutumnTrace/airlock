// Package viewer serves the session-log viewer: a static page that parses
// and verifies logs in the browser, plus a tiny API that hands it the files
// named on the command line.
package viewer

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed static
var static embed.FS

// Static is the viewer's files, the same ones the GitHub Pages build
// publishes.
func Static() fs.FS {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}
	return sub
}

// Session is one log the viewer can open.
type Session struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	path     string
}

// Find expands the command-line arguments: files are taken as they are,
// directories contribute their *.jsonl files, newest first.
func Find(args []string) ([]Session, error) {
	var out []Session
	add := func(path string) error {
		st, err := os.Stat(path)
		if err != nil {
			return err
		}
		out = append(out, Session{Name: filepath.Base(path), Size: st.Size(), Modified: st.ModTime().UTC(), path: path})
		return nil
	}
	for _, a := range args {
		st, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			if err := add(a); err != nil {
				return nil, err
			}
			continue
		}
		matches, err := filepath.Glob(filepath.Join(a, "*.jsonl"))
		if err != nil {
			return nil, err
		}
		var dir []Session
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil {
				dir = append(dir, Session{Name: filepath.Base(m), Size: st.Size(), Modified: st.ModTime().UTC(), path: m})
			}
		}
		sort.Slice(dir, func(i, j int) bool { return dir[i].Modified.After(dir[j].Modified) })
		out = append(out, dir...)
	}
	return out, nil
}

// Server is a running viewer.
type Server struct {
	URL string
	srv *http.Server
	ln  net.Listener
}

// Start listens on addr (use 127.0.0.1:0 for a free port) and serves the
// viewer for sessions. Every path sits under a random token, and requests
// whose Host is not the address it listens on are refused, so neither
// another local user who guesses the port nor a web page using DNS
// rebinding can read the logs.
func Start(addr string, sessions []Session) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		return nil, err
	}
	prefix := "/" + hex.EncodeToString(tok) + "/"
	host := ln.Addr().String()

	mux := http.NewServeMux()
	mux.Handle(prefix, http.StripPrefix(strings.TrimSuffix(prefix, "/"), handler(sessions)))
	s := &Server{
		URL: "http://" + host + prefix,
		ln:  ln,
		srv: &http.Server{
			Handler:           hostCheck(host, mux),
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

// Close stops the server.
func (s *Server) Close() error { return s.srv.Close() }

func hostCheck(host string, next http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(host)
	ok := map[string]bool{host: true, "localhost:" + port: true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ok[r.Host] {
			http.Error(w, "wrong host", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func handler(sessions []Session) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/sessions", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		list := make([]map[string]any, len(sessions))
		for i, s := range sessions {
			list[i] = map[string]any{"name": s.Name, "size": s.Size, "modified": s.Modified, "url": "api/log/" + strconv.Itoa(i)}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"source": "local", "sessions": list})
	})
	mux.HandleFunc("GET /api/log/{i}", func(w http.ResponseWriter, r *http.Request) {
		i, err := strconv.Atoi(r.PathValue("i"))
		if err != nil || i < 0 || i >= len(sessions) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, sessions[i].path)
	})
	mux.HandleFunc("GET /config.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{"source":"local"}`))
	})
	files := http.FileServerFS(Static())
	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/samples/") {
			http.NotFound(w, r) // samples exist only on the published site
			return
		}
		files.ServeHTTP(w, r)
	}))
	return mux
}

// Describe is a one-line summary for the terminal.
func Describe(sessions []Session) string {
	if len(sessions) == 1 {
		return sessions[0].Name
	}
	return fmt.Sprintf("%d sessions", len(sessions))
}
