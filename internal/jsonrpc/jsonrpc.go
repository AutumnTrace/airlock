// Package jsonrpc parses the newline-delimited JSON-RPC 2.0 frames used by the
// MCP stdio transport. It never re-encodes a message it does not have to: the
// original bytes travel with the parsed fields, so a proxy can forward
// untouched traffic byte for byte.
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Kind says what a frame is.
type Kind int

const (
	// Invalid is anything that is not a JSON-RPC 2.0 object: bad JSON, a bare
	// string, an object with neither method nor result nor error.
	Invalid Kind = iota
	Request
	Notification
	Response
	Batch
)

func (k Kind) String() string {
	switch k {
	case Request:
		return "request"
	case Notification:
		return "notification"
	case Response:
		return "response"
	case Batch:
		return "batch"
	}
	return "invalid"
}

// Message is one parsed frame. Raw is the frame exactly as it arrived, minus
// the line terminator.
type Message struct {
	Raw    []byte
	Kind   Kind
	ID     json.RawMessage // nil for notifications
	Method string
	Params json.RawMessage
	Result json.RawMessage
	Error  json.RawMessage

	// Elems holds the members of a batch. Batches were removed from MCP in
	// 2025-06-18 but older peers may still send them.
	Elems []*Message

	// Err is set for Invalid frames and says why.
	Err error
}

type wire struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  *string         `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

var (
	errNotObject = errors.New("frame is not a JSON object")
	errShape     = errors.New("object has no method, result or error")
	errVersion   = errors.New(`missing "jsonrpc": "2.0"`)
)

// Parse classifies one frame. It always returns a Message; for frames that
// cannot be understood, Kind is Invalid and Err explains.
func Parse(raw []byte) *Message {
	m := &Message{Raw: raw}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		m.Err = errNotObject
		return m
	}
	if trimmed[0] == '[' {
		var elems []json.RawMessage
		if err := json.Unmarshal(trimmed, &elems); err != nil {
			m.Err = err
			return m
		}
		m.Kind = Batch
		for _, e := range elems {
			m.Elems = append(m.Elems, Parse(e))
		}
		return m
	}
	if trimmed[0] != '{' {
		m.Err = errNotObject
		return m
	}
	var w wire
	if err := json.Unmarshal(trimmed, &w); err != nil {
		m.Err = err
		return m
	}
	if w.JSONRPC != "2.0" {
		m.Err = errVersion
		return m
	}
	m.Params, m.Result, m.Error = nullToNil(w.Params), nullToNil(w.Result), nullToNil(w.Error)
	m.ID = nullToNil(w.ID)
	switch {
	case w.Method != nil:
		m.Method = *w.Method
		if m.ID == nil {
			m.Kind = Notification
		} else {
			m.Kind = Request
		}
	case w.Result != nil || w.Error != nil:
		m.Kind = Response
	default:
		m.Err = errShape
	}
	return m
}

func nullToNil(r json.RawMessage) json.RawMessage {
	if r == nil || bytes.Equal(bytes.TrimSpace(r), []byte("null")) {
		return nil
	}
	return r
}

// IDKey turns a request id into a map key. Ids keep their JSON spelling, so
// the number 1 and the string "1" stay distinct, as JSON-RPC requires.
func IDKey(id json.RawMessage) string {
	return string(bytes.TrimSpace(id))
}

// ErrorResponse builds a JSON-RPC error response for id.
func ErrorResponse(id json.RawMessage, code int, message string) []byte {
	type errObj struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	b, _ := marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   errObj          `json:"error"`
	}{"2.0", idOrNull(id), errObj{code, message}})
	return b
}

// ResultResponse builds a JSON-RPC success response for id.
func ResultResponse(id json.RawMessage, result any) []byte {
	b, _ := marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  any             `json:"result"`
	}{"2.0", idOrNull(id), result})
	return b
}

// WithResult returns the frame of a response with its result replaced,
// keeping the id and any other members intact.
func WithResult(m *Message, result json.RawMessage) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(m.Raw, &obj); err != nil {
		return nil, err
	}
	obj["result"] = result
	return marshal(obj)
}

func idOrNull(id json.RawMessage) json.RawMessage {
	if id == nil {
		return json.RawMessage("null")
	}
	return id
}

// marshal encodes without HTML escaping, so "<" in a tool description stays
// "<" instead of becoming "<" on its way to the client.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Marshal is marshal for other packages.
func Marshal(v any) ([]byte, error) { return marshal(v) }

// Standard JSON-RPC error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
)
