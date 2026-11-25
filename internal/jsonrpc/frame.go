package jsonrpc

import (
	"bufio"
	"bytes"
	"io"
)

// FrameReader splits a stream into newline-delimited frames. MCP's stdio
// transport forbids embedded newlines, so a frame is exactly one line.
// There is no length limit: a tool result of several megabytes is still one
// frame.
type FrameReader struct {
	r *bufio.Reader
}

// NewFrameReader wraps r.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: bufio.NewReaderSize(r, 64<<10)}
}

// Next returns the next non-blank frame without its terminator ("\n" or
// "\r\n"). The slice is owned by the caller. A final frame with no trailing
// newline is returned before io.EOF.
func (f *FrameReader) Next() ([]byte, error) {
	for {
		line, err := f.r.ReadBytes('\n')
		line = bytes.TrimRight(line, "\r\n")
		if len(bytes.TrimSpace(line)) > 0 {
			return line, nil
		}
		if err != nil {
			return nil, err
		}
	}
}
