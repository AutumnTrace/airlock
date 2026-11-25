// Package audit writes and verifies airlock's session logs.
//
// A log is JSON Lines. Every record carries a sequence number, the hash of
// the record before it ("prev") and its own hash ("hash"), which is the
// SHA-256 of the record's line with the hash member removed. Changing,
// dropping or reordering any record breaks the chain from that point on.
//
// A chain alone does not stop someone who can rewrite the whole file: they
// can recompute every hash. That is what signed checkpoints are for. With a
// signing key, airlock periodically writes a checkpoint record carrying an
// Ed25519 signature over the chain head, and signs the closing record. A
// rewrite then needs the private key, which should live somewhere the agent
// cannot read.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"
	"unicode/utf8"
)

// Record kinds.
const (
	KindOpen       = "open"
	KindMsg        = "msg"
	KindEvent      = "event"
	KindStderr     = "stderr"
	KindCheckpoint = "checkpoint"
	KindClose      = "close"
)

// Message directions.
const (
	ClientToServer  = "c2s" // forwarded to the server
	ServerToClient  = "s2c" // forwarded to the client
	ClientToAirlock = "c2a" // sent by the client, stopped by airlock
	AirlockToClient = "a2c" // written by airlock in reply
	ServerToAirlock = "s2a" // sent by the server, stopped by airlock
)

// ZeroHash is the "prev" of the first record.
var ZeroHash = hexString(make([]byte, sha256.Size))

// hashSuffixLen is len(`,"hash":"` + 64 hex digits + `"}`).
const hashSuffixLen = 9 + 64 + 2

// Header is the content of the opening record.
type Header struct {
	Airlock    string   `json:"airlock"`
	Command    []string `json:"cmd"`
	Dir        string   `json:"cwd,omitempty"`
	PID        int      `json:"pid,omitempty"`
	Policy     string   `json:"policy,omitempty"`
	PolicyHash string   `json:"policy_sha256,omitempty"`
	Lockfile   string   `json:"lockfile,omitempty"`
	Key        string   `json:"key,omitempty"` // signing public key, "ed25519:<base64>"
}

// appendRecord assembles a record's line. fields appends the kind-specific
// members, each starting with a comma. The result is the full line including
// the trailing newline, and the record's hash.
func appendRecord(dst []byte, seq uint64, ts time.Time, kind, prev string, fields func([]byte) []byte) ([]byte, string) {
	start := len(dst)
	dst = append(dst, `{"seq":`...)
	dst = strconv.AppendUint(dst, seq, 10)
	dst = append(dst, `,"ts":"`...)
	dst = ts.UTC().AppendFormat(dst, time.RFC3339Nano)
	dst = append(dst, `","kind":"`...)
	dst = append(dst, kind...)
	dst = append(dst, '"')
	if fields != nil {
		dst = fields(dst)
	}
	dst = append(dst, `,"prev":"`...)
	dst = append(dst, prev...)
	dst = append(dst, `"}`...)
	sum := sha256.Sum256(dst[start:])
	h := hexString(sum[:])
	dst = append(dst[:len(dst)-1], `,"hash":"`...)
	dst = append(dst, h...)
	dst = append(dst, "\"}\n"...)
	return dst, h
}

// appendJSONField appends ,"name":<raw> if raw is valid UTF-8 JSON, and
// ,"name_text":"<raw as a string>" otherwise. Frames that are not JSON are
// still recorded, as text.
func appendJSONField(dst []byte, name string, raw []byte, isJSON bool) []byte {
	if isJSON && utf8.Valid(raw) {
		dst = append(dst, `,"`...)
		dst = append(dst, name...)
		dst = append(dst, `":`...)
		return append(dst, raw...)
	}
	s, _ := json.Marshal(string(raw))
	dst = append(dst, `,"`...)
	dst = append(dst, name...)
	dst = append(dst, `_text":`...)
	return append(dst, s...)
}

func appendString(dst []byte, name, value string) []byte {
	s, _ := json.Marshal(value)
	dst = append(dst, `,"`...)
	dst = append(dst, name...)
	dst = append(dst, `":`...)
	return append(dst, s...)
}

// splitHash takes a line (without newline) apart into the bytes that were
// hashed and the hash it claims.
func splitHash(line []byte) (body []byte, claimed string, err error) {
	if len(line) < hashSuffixLen+2 || string(line[len(line)-hashSuffixLen:len(line)-hashSuffixLen+9]) != `,"hash":"` ||
		string(line[len(line)-2:]) != `"}` {
		return nil, "", errors.New("record does not end with a hash member")
	}
	claimed = string(line[len(line)-hashSuffixLen+9 : len(line)-2])
	body = make([]byte, 0, len(line)-hashSuffixLen+1)
	body = append(body, line[:len(line)-hashSuffixLen]...)
	body = append(body, '}')
	return body, claimed, nil
}

func hashOf(body []byte) string {
	sum := sha256.Sum256(body)
	return hexString(sum[:])
}

func hexString(b []byte) string { return hex.EncodeToString(b) }
