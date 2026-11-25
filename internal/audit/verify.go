package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Record is one parsed log line.
type Record struct {
	Seq      uint64          `json:"seq"`
	TS       time.Time       `json:"ts"`
	Kind     string          `json:"kind"`
	Session  *Header         `json:"session,omitempty"`
	Dir      string          `json:"dir,omitempty"`
	Msg      json.RawMessage `json:"msg,omitempty"`
	MsgText  *string         `json:"msg_text,omitempty"`
	Event    json.RawMessage `json:"event,omitempty"`
	LineText *string         `json:"line_text,omitempty"`
	Exit     *int            `json:"exit,omitempty"`
	Records  *uint64         `json:"records,omitempty"`
	Sig      string          `json:"sig,omitempty"`
	Prev     string          `json:"prev"`
	Hash     string          `json:"hash"`
}

// Problem is one thing wrong with a log.
type Problem struct {
	Line int    `json:"line"` // 1-based
	Msg  string `json:"msg"`
}

func (p Problem) String() string { return fmt.Sprintf("line %d: %s", p.Line, p.Msg) }

// Report is the outcome of Verify.
type Report struct {
	Records     int
	Head        string // hash of the last record
	Session     *Header
	Closed      bool
	ExitCode    *int
	Key         string // signing key named in the header, if any
	Checkpoints int    // valid signatures, the closing one included
	SignedUpTo  int    // records covered by the last valid signature
	Problems    []Problem
	Notes       []string
}

// OK is true when the chain is unbroken and every signature checks out.
func (r *Report) OK() bool { return len(r.Problems) == 0 }

// Verify reads a whole log and checks the chain and, if the log is signed or
// trusted is given, the signatures. Passing trusted pins the key: a log
// signed with any other key, or not signed at all, is a problem.
func Verify(r io.Reader, trusted ed25519.PublicKey) (*Report, error) {
	rep := &Report{}
	br := bufio.NewReaderSize(r, 1<<20)
	var key ed25519.PublicKey
	prevHash := ZeroHash
	line := 0
	for {
		raw, err := br.ReadBytes('\n')
		raw = bytes.TrimRight(raw, "\r\n")
		if len(raw) > 0 {
			line++
			rep.Records++
			problem := func(format string, a ...any) {
				rep.Problems = append(rep.Problems, Problem{line, fmt.Sprintf(format, a...)})
			}
			body, claimed, serr := splitHash(raw)
			var rec Record
			if serr != nil {
				problem("%v", serr)
			} else if jerr := json.Unmarshal(raw, &rec); jerr != nil {
				problem("not valid JSON: %v", jerr)
			} else {
				if got := hashOf(body); got != claimed {
					problem("hash mismatch: the record was changed after it was written")
				}
				if rec.Prev != prevHash {
					problem("chain broken: prev does not match the record before it (a record was removed, inserted or moved)")
				}
				if rec.Seq != uint64(line-1) {
					problem("sequence number %d, expected %d", rec.Seq, line-1)
				}
				switch rec.Kind {
				case KindOpen:
					if line != 1 {
						problem("open record in the middle of the log")
					}
					rep.Session = rec.Session
					if rec.Session != nil && rec.Session.Key != "" {
						rep.Key = rec.Session.Key
						k, kerr := ParsePublicKey(rec.Session.Key)
						if kerr != nil {
							problem("header key: %v", kerr)
						}
						key = k
					}
					if trusted != nil {
						if key == nil {
							problem("the log is not signed, but a trusted key was given")
						} else if !key.Equal(trusted) {
							problem("the log is signed with %s, not with the trusted key", rep.Key)
						}
						key = trusted
					}
				case KindCheckpoint, KindClose:
					if rec.Kind == KindClose {
						rep.Closed = true
						rep.ExitCode = rec.Exit
					}
					if key != nil {
						sig, derr := base64.StdEncoding.DecodeString(rec.Sig)
						switch {
						case rec.Sig == "":
							problem("%s record has no signature", rec.Kind)
						case derr != nil || !ed25519.Verify(key, signedBytes(rec.Kind, rec.Seq, rec.Prev), sig):
							problem("bad signature on %s record", rec.Kind)
						default:
							rep.Checkpoints++
							rep.SignedUpTo = line
						}
					}
				}
				if line == 1 && rec.Kind != KindOpen {
					problem("the first record is %q, not an open record", rec.Kind)
				}
			}
			prevHash = claimed
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	rep.Head = prevHash
	if rep.Records == 0 {
		rep.Problems = append(rep.Problems, Problem{0, "empty log"})
	}
	if !rep.Closed {
		rep.Notes = append(rep.Notes, "no closing record: the session was cut short (airlock killed, machine crash), or the end of the log was removed. The chain cannot tell these apart.")
	}
	if key != nil && rep.SignedUpTo < rep.Records {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d record(s) after the last signature are covered by the hash chain only", rep.Records-rep.SignedUpTo))
	}
	if key == nil {
		rep.Notes = append(rep.Notes, "unsigned log: the chain catches edits to a part of the file, not a rewrite of the whole thing")
	}
	return rep, nil
}

// ReadAll parses every record of a log without verifying it.
func ReadAll(r io.Reader) ([]Record, error) {
	var out []Record
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		raw, err := br.ReadBytes('\n')
		raw = bytes.TrimSpace(raw)
		if len(raw) > 0 {
			var rec Record
			if jerr := json.Unmarshal(raw, &rec); jerr != nil {
				return out, fmt.Errorf("record %d: %w", len(out)+1, jerr)
			}
			out = append(out, rec)
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}
