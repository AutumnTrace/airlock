# airlock

A flight recorder and firewall for MCP servers.

airlock sits on the stdio pipe between an MCP client and an MCP server. At this stage it is a transparent proxy: it starts the server, passes every frame through unchanged, copies the server's stderr and exits with the server's status.

```sh
go install github.com/AutumnTrace/airlock/cmd/airlock@latest
airlock wrap -- npx -y @modelcontextprotocol/server-filesystem ~/projects
```

MIT licensed.
