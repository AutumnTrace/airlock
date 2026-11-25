# Sample sessions

Real recordings made by [`demo/record`](../../demo), published with the viewer at https://autumntrace.github.io/airlock/.

| Log | Server | Policy |
|---|---|---|
| [`filesystem.jsonl`](filesystem.jsonl) | `@modelcontextprotocol/server-filesystem` 2.4.0 | [`filesystem.policy.toml`](filesystem.policy.toml): deny by default, reads inside the workspace, writes under `src/` and `docs/` only, 3 writes a minute |
| [`rugpull.jsonl`](rugpull.jsonl) | [`examples/rugpull`](../../examples/rugpull) | [`weather.policy.toml`](weather.policy.toml): allow everything, block drifted and suspicious tools |

Both are signed with a demo key whose public half is [`demo.pub`](demo.pub):

```sh
airlock verify --pubkey docs/samples/demo.pub docs/samples/*.jsonl
```

The workspace's `.env` holds AWS's documented example credentials and a made-up GitHub token, which is what the redaction in `filesystem.jsonl` replaces.
