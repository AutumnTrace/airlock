package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	return func() time.Time { t = t.Add(time.Millisecond); return t }
}

// session writes a small log and returns its lines.
func session(t *testing.T, key ed25519.PrivateKey, every int) []string {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, Header{Airlock: "test", Command: []string{"srv"}}, Options{Key: key, CheckpointEvery: every, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	w.Msg(ClientToServer, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), true)
	w.Msg(ServerToClient, []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`), true)
	w.Msg(ClientToServer, []byte("not json \xff"), false)
	w.Event(map[string]any{"type": "deny", "tool": "write_file"})
	w.Stderr([]byte("server says hi"))
	if _, err := w.Close(0); err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
}

func verify(t *testing.T, lines []string, trusted ed25519.PublicKey) *Report {
	t.Helper()
	rep, err := Verify(strings.NewReader(strings.Join(lines, "\n")+"\n"), trusted)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestRecordsAreValidJSON(t *testing.T) {
	for i, l := range session(t, nil, 0) {
		var rec Record
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("line %d is not JSON: %v\n%s", i+1, err, l)
		}
		if rec.Seq != uint64(i) {
			t.Fatalf("line %d has seq %d", i+1, rec.Seq)
		}
	}
}

func TestIntactLogVerifies(t *testing.T) {
	lines := session(t, nil, 0)
	rep := verify(t, lines, nil)
	if !rep.OK() || rep.Records != len(lines) || !rep.Closed || rep.ExitCode == nil || *rep.ExitCode != 0 {
		t.Fatalf("%+v", rep)
	}
	if rep.Session == nil || rep.Session.Command[0] != "srv" {
		t.Fatalf("header: %+v", rep.Session)
	}
}

func TestNonJSONFrameIsKeptAsText(t *testing.T) {
	lines := session(t, nil, 0)
	var rec Record
	_ = json.Unmarshal([]byte(lines[3]), &rec)
	if rec.MsgText == nil || !strings.HasPrefix(*rec.MsgText, "not json") {
		t.Fatalf("%s", lines[3])
	}
}

func TestTamperingIsDetected(t *testing.T) {
	cases := map[string]func([]string) []string{
		"edit": func(l []string) []string {
			l[2] = strings.Replace(l[2], `"tools":[]`, `"tools":[1]`, 1)
			return l
		},
		"delete": func(l []string) []string { return append(l[:2:2], l[3:]...) },
		"swap": func(l []string) []string {
			l[1], l[2] = l[2], l[1]
			return l
		},
		"insert": func(l []string) []string {
			return append(l[:3:3], append([]string{l[1]}, l[3:]...)...)
		},
		"drop the header": func(l []string) []string { return l[1:] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rep := verify(t, mutate(session(t, nil, 0)), nil)
			if rep.OK() {
				t.Fatalf("tampering went unnoticed: %+v", rep)
			}
		})
	}
}

func TestTruncationIsOnlyANote(t *testing.T) {
	lines := session(t, nil, 0)
	rep := verify(t, lines[:4], nil)
	if !rep.OK() || rep.Closed {
		t.Fatalf("%+v", rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "no closing record") {
		t.Fatalf("notes: %q", rep.Notes)
	}
}

func TestSignedLog(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	lines := session(t, priv, 2)
	checkpoints := 0
	for _, l := range lines {
		if strings.Contains(l, `"kind":"checkpoint"`) {
			checkpoints++
		}
	}
	if checkpoints != 2 {
		t.Fatalf("%d checkpoints, want 2 (5 records every 2)", checkpoints)
	}
	rep := verify(t, lines, pub)
	if !rep.OK() || rep.Checkpoints != 3 || rep.SignedUpTo != len(lines) {
		t.Fatalf("%+v", rep)
	}

	t.Run("wrong trusted key", func(t *testing.T) {
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		if verify(t, lines, other).OK() {
			t.Fatal("accepted a log signed with another key")
		}
	})
	t.Run("unsigned log with a trusted key", func(t *testing.T) {
		if verify(t, session(t, nil, 0), pub).OK() {
			t.Fatal("accepted an unsigned log")
		}
	})
	t.Run("rewritten chain", func(t *testing.T) {
		// An attacker who rewrites a record and recomputes every hash after
		// it keeps the chain intact, but cannot re-sign.
		forged := rechain(t, lines, 2, `"tools":[]`, `"tools":["evil"]`)
		if !chainOK(verify(t, forged, nil)) {
			t.Fatal("rechain helper is broken")
		}
		if verify(t, forged, pub).OK() {
			t.Fatal("a rewritten, re-hashed log passed signature checks")
		}
	})
}

func TestUnsignedRewriteIsUndetectable(t *testing.T) {
	// Documented limitation: without a key or an anchored head, a full
	// rewrite verifies. Kept as a test so the README stays honest.
	forged := rechain(t, session(t, nil, 0), 2, `"tools":[]`, `"tools":["evil"]`)
	if !verify(t, forged, nil).OK() {
		t.Fatal("expected the rewritten unsigned log to verify")
	}
}

func chainOK(r *Report) bool {
	for _, p := range r.Problems {
		if !strings.Contains(p.Msg, "signature") {
			return false
		}
	}
	return true
}

// rechain edits line i and recomputes every hash from there on.
func rechain(t *testing.T, lines []string, i int, old, new string) []string {
	t.Helper()
	out := append([]string(nil), lines...)
	out[i] = strings.Replace(out[i], old, new, 1)
	prev := ""
	for j := range out {
		l := out[j]
		if j >= i {
			body, _, err := splitHash([]byte(l))
			if err != nil {
				t.Fatal(err)
			}
			if prev != "" {
				var rec Record
				_ = json.Unmarshal([]byte(l), &rec)
				body = bytes.Replace(body, []byte(`"prev":"`+rec.Prev+`"`), []byte(`"prev":"`+prev+`"`), 1)
			}
			h := hashOf(body)
			l = string(body[:len(body)-1]) + `,"hash":"` + h + `"}`
			out[j] = l
		}
		var rec Record
		_ = json.Unmarshal([]byte(out[j]), &rec)
		prev = rec.Hash
	}
	return out
}

func TestKeyRoundTrip(t *testing.T) {
	privPEM, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := dir + "/k.pem"
	if err := writeFile(path, privPEM); err != nil {
		t.Fatal(err)
	}
	sk, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ParsePublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !pk.Equal(sk.Public()) {
		t.Fatal("public key does not match")
	}
	if _, err := ParsePublicKey("ed25519:AAAA"); err == nil {
		t.Fatal("accepted a short key")
	}
}
