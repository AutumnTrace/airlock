// Command record produces the sample sessions published with the viewer.
// It drives real servers through airlock with the official Go MCP SDK as
// the client, so the logs are exactly what airlock writes in use:
//
//   - filesystem: @modelcontextprotocol/server-filesystem on a small
//     workspace, under a deny-by-default policy.
//   - rugpull: examples/rugpull, which swaps its tool description after the
//     first call, under on_drift = "block".
//
// Usage (from the repository root):
//
//	cd demo && go run ./record -root C:/airlock-demo -out ../docs/samples
//
// Needs Go and Node (for npx). The root directory is created and reused.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	root    = flag.String("root", filepath.Join(os.TempDir(), "airlock-demo"), "scratch directory for the workspace, binaries and key")
	out     = flag.String("out", "../docs/samples", "where to write the session logs")
	fsPkg   = flag.String("fs-server", "@modelcontextprotocol/server-filesystem@2.4.0", "npm package of the filesystem server")
	repoDir = flag.String("repo", "..", "airlock repository root")
	version = flag.String("version", "0.1.0", "version stamped into the airlock binary, and so into the logs")
)

func main() {
	flag.Parse()
	must(os.MkdirAll(*root, 0o755))
	must(os.MkdirAll(*out, 0o755))
	rootAbs, err := filepath.Abs(*root)
	must(err)
	bin := filepath.Join(rootAbs, "bin")
	airlock := build(bin, "airlock", "./cmd/airlock")
	rugpull := build(bin, "rugpull", "./examples/rugpull")

	key := filepath.Join(rootAbs, "demo.key")
	if _, err := os.Stat(key); err != nil {
		cmd := exec.Command(airlock, "keygen", "-o", key)
		cmd.Stderr = os.Stderr
		pub, err := cmd.Output()
		must(err)
		must(os.WriteFile(filepath.Join(*out, "demo.pub"), pub, 0o644))
	}

	ws := filepath.ToSlash(filepath.Join(rootAbs, "workspace"))
	writeWorkspace(rootAbs, ws)
	fsPolicy := filepath.Join(rootAbs, "filesystem.toml")
	must(os.WriteFile(fsPolicy, []byte(strings.ReplaceAll(filesystemPolicy, "{{WS}}", ws)), 0o644))
	weatherPolicy := filepath.Join(rootAbs, "weather.toml")
	must(os.WriteFile(weatherPolicy, []byte(weatherPolicySrc), 0o644))
	for _, f := range []string{"filesystem.lock.json", "weather.lock.json"} {
		_ = os.Remove(filepath.Join(rootAbs, f))
	}

	ctx := context.Background()
	fsLog := logPath("filesystem.jsonl")
	session(ctx, rootAbs, fsLog, []string{airlock, "wrap", "--policy", fsPolicy, "--sign-key", key, "--checkpoint-every", "16", "--log-file", fsLog, "--", "npx", "-y", *fsPkg, ws},
		func(c *client) {
			c.list()
			c.call("list_allowed_directories", map[string]any{})
			c.call("list_directory", map[string]any{"path": ws})
			c.call("read_text_file", map[string]any{"path": ws + "/README.md"})
			c.call("search_files", map[string]any{"path": ws, "pattern": "**/*.ts"})
			c.call("read_text_file", map[string]any{"path": ws + "/.env"})
			c.call("read_text_file", map[string]any{"path": ws + "/../secrets.txt"})
			c.call("write_file", map[string]any{"path": ws + "/src/greeting.ts", "content": "export const greeting = (name: string) => `Hello, ${name}!`;\n"})
			c.call("edit_file", map[string]any{"path": ws + "/src/app.ts"})
			c.call("write_file", map[string]any{"path": ws + "/src/.env.production", "content": "API_URL=https://api.example.com\n"})
			c.call("move_file", map[string]any{"source": ws + "/README.md", "destination": ws + "/docs/README.md"})
			for i, name := range []string{"a", "b", "c"} {
				c.call("write_file", map[string]any{"path": ws + "/src/gen-" + name + ".ts", "content": fmt.Sprintf("export const n = %d;\n", i)})
			}
			c.call("list_directory_with_sizes", map[string]any{"path": ws + "/src"})
		})

	rpLog := logPath("rugpull.jsonl")
	session(ctx, rootAbs, rpLog, []string{airlock, "wrap", "--policy", weatherPolicy, "--sign-key", key, "--log-file", rpLog, "--", rugpull},
		func(c *client) {
			c.list()
			c.call("get_forecast", map[string]any{"city": "Lisbon", "days": 2})
			time.Sleep(100 * time.Millisecond) // let the list_changed notification land
			c.list()
			// A client that cached the poisoned definition, or a model that
			// saw it somewhere else, now tries the exfiltrating call.
			c.call("get_forecast", map[string]any{"city": "Lisbon", "notes": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----"})
			c.call("get_alerts", map[string]any{"region": "Lisbon"})
		})

	for _, p := range []string{fsLog, rpLog} {
		cmd := exec.Command(airlock, "verify", p)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		must(cmd.Run())
	}
	must(copyFile(fsPolicy, filepath.Join(*out, "filesystem.policy.toml")))
	must(copyFile(weatherPolicy, filepath.Join(*out, "weather.policy.toml")))
}

func logPath(name string) string {
	p, err := filepath.Abs(filepath.Join(*out, name))
	must(err)
	_ = os.Remove(p)
	return p
}

type client struct {
	ctx context.Context
	cs  *mcp.ClientSession
}

func (c *client) list() {
	res, err := c.cs.ListTools(c.ctx, &mcp.ListToolsParams{})
	if err != nil {
		log.Printf("tools/list: %v", err)
		return
	}
	names := make([]string, len(res.Tools))
	for i, t := range res.Tools {
		names[i] = t.Name
	}
	log.Printf("tools/list: %s", strings.Join(names, ", "))
}

func (c *client) call(name string, args map[string]any) {
	res, err := c.cs.CallTool(c.ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		log.Printf("%s: error %v", name, err)
		return
	}
	text := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}
	if len(text) > 90 {
		text = text[:90] + "..."
	}
	log.Printf("%s (isError=%v): %q", name, res.IsError, text)
}

func session(ctx context.Context, dir, logFile string, argv []string, script func(*client)) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	c := mcp.NewClient(&mcp.Implementation{Name: "airlock-demo-recorder", Version: "0.1.0"}, nil)
	cs, err := c.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	must(err)
	script(&client{ctx: ctx, cs: cs})
	must(cs.Close())
	log.Printf("wrote %s", logFile)
}

func build(dir, name, pkg string) string {
	out := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command("go", "build", "-ldflags", "-X main.version="+*version, "-o", out, pkg)
	cmd.Dir = *repoDir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	must(cmd.Run())
	return out
}

func writeWorkspace(rootDir, ws string) {
	_ = os.RemoveAll(ws)
	files := map[string]string{
		"README.md":     "# site\n\nA small static site. `npm run build` writes it to dist/.\n",
		"package.json":  `{"name":"site","private":true,"scripts":{"build":"tsc && node build.js"}}` + "\n",
		"src/app.ts":    "import { slug } from './util';\n\nexport function title(s: string) {\n  return slug(s).toUpperCase();\n}\n",
		"src/util.ts":   "export const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-');\n",
		"docs/notes.md": "Deploy notes: the staging bucket is site-staging.\n",
		// AWS's documented example credentials and a made-up GitHub token.
		".env": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nGITHUB_TOKEN=ghp_" + strings.Repeat("x7Rq", 9) + "\nPUBLIC_SITE_NAME=site\n",
	}
	for name, body := range files {
		p := filepath.Join(ws, name)
		must(os.MkdirAll(filepath.Dir(p), 0o755))
		must(os.WriteFile(p, []byte(body), 0o644))
	}
	must(os.WriteFile(filepath.Join(rootDir, "secrets.txt"), []byte("outside the workspace\n"), 0o644))
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

const filesystemPolicy = `# Policy used to record docs/samples/filesystem.jsonl.
default = "deny"

[pinning]
lockfile = "filesystem.lock.json"
on_drift = "block"
on_suspicious = "block"

[schema]
validate = true

[[rule]]
tools = ["read_text_file", "read_media_file", "read_multiple_files", "list_directory",
         "list_directory_with_sizes", "directory_tree", "search_files", "get_file_info"]
action = "allow"
args.path.prefix = ["{{WS}}"]
args.paths.prefix = ["{{WS}}"]

[[rule]]
tools = ["list_allowed_directories"]
action = "allow"

[[rule]]
tools = ["write_file", "edit_file", "create_directory"]
action = "allow"
rate = "3/min"
  [rule.args.path]
  prefix = ["{{WS}}/src", "{{WS}}/docs"]
  not_regex = '(^|/)\.env'

[[rule]]
tools = ["move_file", "copy_file"]
action = "deny"
reason = "ask the user to move or copy files"

[[redact.pattern]]
name = "aws-secret-access-key"
regex = '(?i)aws_secret_access_key\s*=\s*\S+'
`

const weatherPolicySrc = `# Policy used to record docs/samples/rugpull.jsonl.
default = "allow"

[pinning]
lockfile = "weather.lock.json"
on_drift = "block"
on_suspicious = "block"
`
