package jsonrpc

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestParseKinds(t *testing.T) {
	cases := []struct {
		in   string
		kind Kind
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, Request},
		{`{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"x"}}`, Request},
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, Notification},
		{`{"jsonrpc":"2.0","id":null,"method":"x"}`, Notification},
		{`{"jsonrpc":"2.0","id":1,"result":{}}`, Response},
		{`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"no"}}`, Response},
		{`[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","method":"b"}]`, Batch},
		{`{"id":1,"method":"x"}`, Invalid},
		{`{"jsonrpc":"2.0","id":1}`, Invalid},
		{`not json`, Invalid},
		{`"a string"`, Invalid},
		{``, Invalid},
	}
	for _, c := range cases {
		m := Parse([]byte(c.in))
		if m.Kind != c.kind {
			t.Errorf("Parse(%s) = %v (%v), want %v", c.in, m.Kind, m.Err, c.kind)
		}
		if m.Kind == Invalid && m.Err == nil {
			t.Errorf("Parse(%s): Invalid without Err", c.in)
		}
	}
}

func TestParseKeepsRawAndFields(t *testing.T) {
	in := `{"jsonrpc":"2.0", "id": 7, "method":"tools/call","params":{"name":"read_file"}}`
	m := Parse([]byte(in))
	if string(m.Raw) != in || m.Method != "tools/call" || IDKey(m.ID) != "7" || string(m.Params) != `{"name":"read_file"}` {
		t.Fatalf("%+v", m)
	}
	b := Parse([]byte(`[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","method":"b"}]`))
	if len(b.Elems) != 2 || b.Elems[0].Kind != Request || b.Elems[1].Kind != Notification {
		t.Fatalf("batch: %+v", b.Elems)
	}
}

func TestIDKeyKeepsTypes(t *testing.T) {
	if IDKey([]byte(`1`)) == IDKey([]byte(`"1"`)) {
		t.Fatal("number and string ids collided")
	}
}

func TestResponses(t *testing.T) {
	got := string(ErrorResponse([]byte(`"x"`), CodeInvalidParams, "bad <args>"))
	want := `{"jsonrpc":"2.0","id":"x","error":{"code":-32602,"message":"bad <args>"}}`
	if got != want {
		t.Fatalf("got %s", got)
	}
	got = string(ResultResponse([]byte(`3`), map[string]bool{"ok": true}))
	if got != `{"jsonrpc":"2.0","id":3,"result":{"ok":true}}` {
		t.Fatalf("got %s", got)
	}
	m := Parse([]byte(`{"jsonrpc":"2.0","id":3,"result":{"a":1},"x":true}`))
	b, err := WithResult(m, []byte(`{"a":2}`))
	if err != nil || !strings.Contains(string(b), `"result":{"a":2}`) || !strings.Contains(string(b), `"x":true`) {
		t.Fatalf("WithResult: %s %v", b, err)
	}
}

func TestFrameReader(t *testing.T) {
	r := NewFrameReader(strings.NewReader("a\r\n\n  \nb\n" + strings.Repeat("c", 200000)))
	var got []string
	for {
		f, err := r.Next()
		if f != nil {
			got = append(got, string(f))
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || len(got[2]) != 200000 {
		t.Fatalf("frames: %d %q", len(got), got[:2])
	}
}

func TestDuplicateKey(t *testing.T) {
	for in, want := range map[string]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}`:                "name",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","NAME":"b"}}`:                "NAME",
		`{"method":"tools/list","method":"tools/call"}`:                                                  "method",
		`{"a":[{"x":1},{"x":2}],"b":{"c":{"d":1,"d":2}}}`:                                                "d",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","arguments":{"path":"/x"}}}`: "",
		`{"a":{"x":1},"b":{"x":1}}`:                                                                      "",
		`[{"a":1},{"a":1}]`:                                                                              "",
		`not json`:                                                                                       "",
	} {
		got, dup := DuplicateKey([]byte(in))
		if got != want || dup != (want != "") {
			t.Errorf("DuplicateKey(%s) = %q, %v; want %q", in, got, dup, want)
		}
	}
}
