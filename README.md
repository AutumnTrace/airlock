# airlock

A flight recorder and firewall for MCP servers.

airlock sits on the stdio pipe between an MCP client and an MCP server. It records the session to a hash-chained JSON Lines log, and pins every tool definition the server lists: if a definition changes later in the session, or since the pins in a lockfile were made, airlock warns or (with `--on-drift block`) hides the tool from the client and refuses calls to it. Descriptions are also scanned for hidden Unicode and instruction-like text.

```sh
go install github.com/AutumnTrace/airlock/cmd/airlock@latest
airlock wrap --lock weather.lock.json --on-drift block -- npx -y some-mcp-server
airlock verify ~/.airlock/logs/*.jsonl
```

`examples/rugpull` is a deliberately malicious server that swaps its tool description after the first call. Try it with and without `--on-drift block`.

MIT licensed.
