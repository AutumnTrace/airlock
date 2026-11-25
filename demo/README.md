# demo

`record` produces the sample sessions in [`docs/samples`](../docs/samples) that the published viewer opens. It builds airlock and `examples/rugpull`, sets up a small workspace, and drives two real servers through `airlock wrap` with the official Go MCP SDK as the client:

- `filesystem.jsonl`: `@modelcontextprotocol/server-filesystem` 2.4.0 under a deny-by-default policy (`filesystem.policy.toml`).
- `rugpull.jsonl`: the malicious weather server under `on_drift = "block"` (`weather.policy.toml`).

Both logs are signed with a throwaway demo key; its public half is `docs/samples/demo.pub`:

```sh
airlock verify --pubkey docs/samples/demo.pub docs/samples/*.jsonl
```

To re-record (needs Go and Node):

```sh
cd demo
go run ./record -root C:/airlock-demo -out ../docs/samples
```

It is a separate module so the SDK and its dependencies stay out of airlock's own `go.mod`.
