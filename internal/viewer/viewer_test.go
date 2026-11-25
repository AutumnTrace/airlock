package viewer

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func get(t *testing.T, url, host string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestServer(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.jsonl"), []byte(`{"seq":0}`+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)
	sessions, err := Find([]string{dir})
	if err != nil || len(sessions) != 1 {
		t.Fatalf("%v %v", sessions, err)
	}
	s, err := Start("127.0.0.1:0", sessions)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if code, body := get(t, s.URL, ""); code != 200 || !strings.Contains(body, "airlock session viewer") {
		t.Fatalf("index: %d", code)
	}
	if code, body := get(t, s.URL+"api/sessions", ""); code != 200 || !strings.Contains(body, `"a.jsonl"`) {
		t.Fatalf("sessions: %d %s", code, body)
	}
	if code, body := get(t, s.URL+"api/log/0", ""); code != 200 || body != `{"seq":0}`+"\n" {
		t.Fatalf("log: %d %q", code, body)
	}
	if code, _ := get(t, s.URL+"api/log/1", ""); code != 404 {
		t.Fatalf("out of range: %d", code)
	}
	if code, body := get(t, s.URL+"config.json", ""); code != 200 || !strings.Contains(body, `"local"`) {
		t.Fatalf("config: %d %s", code, body)
	}
	if code, _ := get(t, s.URL+"app.js", ""); code != 200 {
		t.Fatalf("app.js: %d", code)
	}
	// Without the token there is nothing.
	root := s.URL[:strings.Index(s.URL[7:], "/")+8]
	if code, _ := get(t, root+"api/sessions", ""); code != 404 {
		t.Fatalf("no token: %d", code)
	}
	// DNS rebinding: right address, wrong Host header.
	if code, _ := get(t, s.URL+"api/sessions", "evil.example:80"); code != 403 {
		t.Fatalf("wrong host: %d", code)
	}
}

func TestStaticHasNoTestFiles(t *testing.T) {
	entries, _ := os.ReadDir("static")
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".test.mjs") {
			t.Fatalf("test file %s would be embedded", e.Name())
		}
	}
}
