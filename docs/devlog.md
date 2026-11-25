# Devlog

Notes on what went wrong or surprised me while building v0.1.0, roughly in order.

## Waiting for the server the right way

The first version of the proxy test deadlocked. The goroutine running `Run` sent its result on an unbuffered channel and only then closed the pipe standing in for the client's stdout. The test, meanwhile, sat in `io.ReadAll` on that pipe, waiting for EOF. It was my test's bug, but the same ordering problem exists for real. `exec.Cmd.Wait` closes the pipes it created, so it must not be called until both server output streams have been read to the end, or the last frames and stderr lines are lost. `Run` returns only after stdout and stderr are drained, and `wrap` calls `Wait` after that.

## Windows doesn't send signals

On Unix a supervisor stops a stdio server by closing stdin, then SIGTERM. On Windows, Node's `child.kill()` is `TerminateProcess`: airlock gets no signal and no chance to do anything. Most servers still exit, because their stdin pipe closes when airlock dies. But a server that doesn't watch for EOF would be left running. So would anything the server spawned, and with `npx` in the chain the real server is already a grandchild. A job object with kill-on-close fixes all of it without relying on the server's manners. airlock holds the only handle, so the kernel cleans up the whole tree when airlock goes.

## Hash what you wrote, not what you parsed

The obvious chain design hashes a canonical re-serialisation of each record. That brings in canonical JSON, which two implementations (Go and the browser viewer) would have to agree on byte for byte. Instead, the hash covers the line exactly as written, minus its own `,"hash":"..."` member. Since that member is always last and fixed-width, both verifiers just cut a known suffix off the line.

Writing records needed one more change. `json.Marshal` compacts a `json.RawMessage` and HTML-escapes it, so `<IMPORTANT>` in a tool description would be logged as `\u003cIMPORTANT\u003e`. That is valid JSON, but it is not what the server sent. Records are now assembled by hand around the raw frame. The same escaping would have changed frames airlock rewrites (a filtered tool list, a redacted result), so its own encoder has `SetEscapeHTML(false)` too.

## A hash chain is not tamper-proof

It is easy to write "tamper-evident log" and stop there. Someone who can edit the file can also recompute every hash after their edit. There is a test, `TestUnsignedRewriteIsUndetectable`, that does exactly that and asserts the forged log verifies, so the limitation can't quietly disappear from the docs. Signed checkpoints are the actual answer. The README says plainly which parts are proven and which are not.

## Redaction leaked through a backslash-n

The redactor has a fast path: run the patterns over the raw JSON bytes, and only decode and walk the value if something might match. My first rule was that escapes other than `\n`, `\t`, `\"` and `\\` force the slow path, since `\u0041KIA...` spells `AKIA` in disguise.

The bug was `\n`. In the raw bytes of `"AWS=x\nAKIAIOSFODNN7EXAMPLE"`, the character before `AKIA` is the `n` of the escape. The pattern starts with `\b`, a word boundary, and `nA` has none. The raw scan would have found nothing, the fast path would have returned the frame untouched, and the key would have gone to the client. I caught it rereading the fast path before any of this ran against a real server. A test now puts a key right after a `\n`, and only `\"` and `\\` count as harmless. (The current fast path no longer runs the patterns over raw bytes at all; see the next section.)

## The fast path was slow

`BenchmarkGuard` showed 25 µs of CPU per small tool call with a policy loaded. Two thirds of that was the redactor's combined regex: an alternation of nine patterns, one with `[\s\S]*?`, which RE2 can only run on its NFA.

Every built-in pattern contains a fixed literal (`AKIA`, `ghp_`, `sk-ant-`, `PRIVATE KEY-----`). So each pattern now carries those literals as hints, and the regex only runs where a hint occurs. That brought it to 9.6 µs.

Then the 64 KiB benchmark showed the hint scan costing about 160 µs per result: twenty `bytes.Contains` passes over the frame. Each hint is now found by its rarest byte (`J` in `eyJ`, `-` in `sk-`, `V` in `PRIVATE`). That means one vectorised `IndexByte` pass per distinct anchor byte, with a comparison at each hit, and it brought the 64 KiB cost down to about 40 µs.

The benchmark data itself had been misleading. The fake server's big result was 64 KiB of the letter `x`, the worst possible input for the Slack hint `xox`. It now returns ordinary prose.

## Duplicate members, and Go's case-insensitive fields

`{"name":"read_file","name":"write_file"}` means different things to different JSON parsers, which is the classic way to get one message past a proxy as one thing and into a server as another. Go adds its own twist: `encoding/json` matches struct fields case-insensitively. So with `{"name":"read_file","NAME":"write_file"}`, airlock's struct would have seen `write_file` while a JavaScript server reads `name` and runs `read_file`. That direction happens to be safe, since airlock checks the more dangerous call, but the reverse ordering isn't something I want to reason about per field. airlock now refuses any client message that repeats a member name, compared case-insensitively.

## A schema that reads files

The JSON Schema library resolves `$ref` through a loader, and its default loader opens `file://` URLs. A tool's `inputSchema` is written by the server, so `"$ref": "file:///home/me/.ssh/id_rsa"` would have had airlock opening files for an untrusted party. The spec only says not to fetch network URIs by default. airlock refuses every external ref.

## The 2026-07-28 handshake, live

The recorder uses the official Go SDK as its client, and SDK v1.8.0 opens with the new stateless `server/discover`. My first manual probe of server-filesystem 2.4.0 sent `initialize` and then `server/discover`, got "method not found", and I concluded the server only spoke 2025-11-25. Wrong: once a connection has done the legacy handshake, discover is no longer offered on it. Sent first, as the SDK does, it is answered, and both sample sessions are 2026-07-28 sessions. airlock picks the version up from the `_meta` key every request now carries, and adds the `resultType` that revision requires to its own replies.

Two smaller things from the same recording:

- A nil Go map in `CallToolParams.Arguments` goes out as `"arguments": null`, which server-filesystem's validator rejects.
- My first recording called `get_file_info`, whose timestamps include the machine's time zone name. Sample logs get published, so that call is gone.

## Heuristics are noisy

`mentions-other-tool` (a description that names a sibling tool) is one of the tricks in the tool-shadowing write-ups. It fires on three of server-filesystem's own tools, for example "DEPRECATED: Use read_text_file instead". It is a low-severity note, `on_suspicious` ignores it, and the viewer keeps notes out of the timeline.

## Windows timer resolution

I wanted p50 and p99 round-trip latencies, not just means. On this Windows machine the per-call durations came back as either 0 or 500 µs, which is the timer's granularity showing through. The benchmarks report Go's ns/op means, which time thousands of calls at once.
