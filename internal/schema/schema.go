// Package schema validates tools/call arguments against the inputSchema a
// server declared, following the MCP 2026-07-28 rules for schema use: JSON
// Schema 2020-12 unless $schema says otherwise, no fetching of $ref targets,
// and bounds on how much schema a server can make airlock chew through.
package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Bounds on a declared schema. A tool server is untrusted input; a schema
// with ten thousand nested anyOfs is a way to burn the proxy's CPU.
const (
	MaxBytes      = 256 << 10
	MaxDepth      = 32
	MaxSubschemas = 2000
)

// Validator checks arguments against one compiled schema.
type Validator struct {
	sch *jsonschema.Schema
}

// refusingLoader is used for every $ref that does not point inside the
// schema itself. The spec says implementations MUST NOT dereference network
// URIs by default; airlock goes further and never reads files either, so a
// tool cannot use "$ref": "file:///..." to make airlock open local files.
type refusingLoader struct{}

func (refusingLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external $ref %q is not followed", url)
}

// Compile prepares a validator for a tool's inputSchema.
func Compile(raw json.RawMessage) (*Validator, error) {
	if len(raw) > MaxBytes {
		return nil, fmt.Errorf("schema is %d bytes, more than the %d airlock accepts", len(raw), MaxBytes)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if err := checkBounds(doc); err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(refusingLoader{})
	const loc = "airlock:///tool-input-schema.json"
	if err := c.AddResource(loc, doc); err != nil {
		return nil, err
	}
	sch, err := c.Compile(loc)
	if err != nil {
		return nil, err
	}
	return &Validator{sch: sch}, nil
}

func checkBounds(doc any) error {
	nodes := 0
	var walk func(v any, depth int) error
	walk = func(v any, depth int) error {
		if depth > MaxDepth {
			return fmt.Errorf("schema nests deeper than %d levels", MaxDepth)
		}
		switch x := v.(type) {
		case map[string]any:
			nodes++
			if nodes > MaxSubschemas {
				return fmt.Errorf("schema has more than %d objects", MaxSubschemas)
			}
			for _, e := range x {
				if err := walk(e, depth+1); err != nil {
					return err
				}
			}
		case []any:
			for _, e := range x {
				if err := walk(e, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(doc, 0)
}

// Validate checks the arguments of a call (nil or absent counts as an empty
// object, as clients send for tools with no parameters). The error message
// is written for the model that made the call: short, with JSON pointers.
func (v *Validator) Validate(args json.RawMessage) error {
	if len(bytes.TrimSpace(args)) == 0 || string(bytes.TrimSpace(args)) == "null" {
		args = json.RawMessage(`{}`)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(args))
	if err != nil {
		return fmt.Errorf("arguments are not valid JSON: %w", err)
	}
	err = v.sch.Validate(inst)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return err
	}
	return errors.New(summarize(ve.BasicOutput()))
}

func summarize(out *jsonschema.OutputUnit) string {
	seen := map[string]bool{}
	var msgs []string
	for _, e := range out.Errors {
		if e.Error == nil {
			continue
		}
		loc := e.InstanceLocation
		if loc == "" {
			loc = "/"
		}
		m := loc + ": " + e.Error.String()
		// The root unit repeats its children's errors in a generic form.
		if strings.HasPrefix(e.Error.String(), "validation failed") || seen[m] {
			continue
		}
		seen[m] = true
		msgs = append(msgs, m)
	}
	if len(msgs) == 0 && out.Error != nil {
		msgs = append(msgs, out.Error.String())
	}
	sort.Strings(msgs)
	if len(msgs) > 5 {
		msgs = append(msgs[:5], fmt.Sprintf("and %d more", len(msgs)-5))
	}
	return "arguments do not match the tool's inputSchema: " + strings.Join(msgs, "; ")
}
