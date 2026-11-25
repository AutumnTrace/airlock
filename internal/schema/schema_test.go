package schema

import (
	"fmt"
	"strings"
	"testing"
)

const writeFile = `{
  "type": "object",
  "properties": {
    "path": {"type": "string"},
    "content": {"type": "string"},
    "mode": {"enum": ["overwrite", "append"]}
  },
  "required": ["path", "content"],
  "additionalProperties": false
}`

func TestValidate(t *testing.T) {
	v, err := Compile([]byte(writeFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Validate([]byte(`{"path":"/a","content":"x"}`)); err != nil {
		t.Fatalf("valid call rejected: %v", err)
	}
	for args, want := range map[string]string{
		`{"path":"/a"}`:                                 "content",
		`{"path":5,"content":"x"}`:                      "/path",
		`{"path":"/a","content":"x","exfil":"key"}`:     "exfil",
		`{"path":"/a","content":"x","mode":"truncate"}`: "/mode",
		`null`:  "path",
		`[1,2]`: "object",
	} {
		err := v.Validate([]byte(args))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Validate(%s) = %v, want a message mentioning %q", args, err, want)
		}
	}
}

func TestEmptyArgumentsForParameterlessTool(t *testing.T) {
	v, err := Compile([]byte(`{"type":"object","additionalProperties":false}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(nil); err != nil {
		t.Fatal(err)
	}
}

func TestOlderDraftsStillWork(t *testing.T) {
	v, err := Compile([]byte(`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"number"}},"required":["a"]}`))
	if err != nil {
		t.Fatalf("draft-07 schema: %v", err)
	}
	if v.Validate([]byte(`{"a":"x"}`)) == nil {
		t.Fatal("draft-07 schema did not validate")
	}
}

func TestLocalRefsResolveExternalRefsDoNot(t *testing.T) {
	if _, err := Compile([]byte(`{"$defs":{"p":{"type":"string"}},"type":"object","properties":{"path":{"$ref":"#/$defs/p"}}}`)); err != nil {
		t.Fatalf("local $ref: %v", err)
	}
	for _, ref := range []string{"https://example.com/schema.json", "file:///etc/passwd", "http://169.254.169.254/latest/meta-data"} {
		_, err := Compile([]byte(fmt.Sprintf(`{"type":"object","properties":{"x":{"$ref":%q}}}`, ref)))
		if err == nil {
			t.Errorf("external $ref %s was accepted", ref)
		}
	}
}

func TestBounds(t *testing.T) {
	deep := strings.Repeat(`{"anyOf":[`, 40) + `{}` + strings.Repeat(`]}`, 40)
	if _, err := Compile([]byte(deep)); err == nil || !strings.Contains(err.Error(), "deeper") {
		t.Fatalf("deep schema: %v", err)
	}
	wide := `{"anyOf":[` + strings.Repeat(`{"type":"string"},`, 2500) + `{}]}`
	if _, err := Compile([]byte(wide)); err == nil || !strings.Contains(err.Error(), "objects") {
		t.Fatalf("wide schema: %v", err)
	}
}
