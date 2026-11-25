# airlock

A flight recorder and firewall for MCP servers.

airlock sits on the stdio pipe between an MCP client and an MCP server. It starts the server, passes every frame through, and records the session to a hash-chained JSON Lines log that `airlock verify` can check later. With a key from `airlock keygen`, the log also carries Ed25519-signed checkpoints.

```sh
go install github.com/AutumnTrace/airlock/cmd/airlock@latest
airlock wrap -- npx -y @modelcontextprotocol/server-filesystem ~/projects
airlock verify ~/.airlock/logs/*.jsonl
```

MIT licensed.
