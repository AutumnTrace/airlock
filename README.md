# airlock

A flight recorder and firewall for MCP servers.

airlock sits on the stdio pipe between an MCP client and an MCP server. It records the session to a hash-chained JSON Lines log, pins every tool definition the server lists, and with a TOML policy decides each `tools/call` before the server sees it: allow and deny rules by tool name, path and pattern constraints on arguments, validation against the tool's own `inputSchema`, per-tool rate limits, and redaction of secrets in results.

```sh
go install github.com/AutumnTrace/airlock/cmd/airlock@latest
airlock check examples/policies/filesystem.toml read_text_file '{"path":"/etc/passwd"}'
airlock wrap --policy examples/policies/filesystem.toml -- npx -y @modelcontextprotocol/server-filesystem /home/me/projects/site
airlock verify ~/.airlock/logs/*.jsonl
```

`examples/rugpull` is a deliberately malicious server that swaps its tool description after the first call. Try it with `examples/policies/weather.toml`.

MIT licensed.
