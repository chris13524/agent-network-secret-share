# agent-network-secret-share

Hand a secret (e.g. an access token) to an AI agent without pasting it into the chat.

```
cargo run --release -- [--public | --bind HOST] [--expires DURATION]
```

1. You're prompted for the secret (input is hidden).
2. The app generates a fresh self-signed TLS certificate and a random one-time password, and binds to a random TCP port.
3. It prints a short prompt to paste into your AI agent, containing a `curl` command that pins the certificate's public key:

   ```
   curl -sS --insecure --pinnedpubkey 'sha256//<key hash>' -H 'Authorization: Bearer <password>' https://127.0.0.1:<port>/secret
   ```

## Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `--public` | off | Listen on all network interfaces. The printed URL uses this machine's LAN IP. |
| `--bind HOST` | `127.0.0.1` | Listen on a specific address. |
| `--expires DURATION` | `1h` | Shut down after this long even if the secret wasn't fetched. Accepts e.g. `90s`, `15m`, `2h30m`, `1d`. |

## Security properties

- **Server authentication:** HTTPS (TLS 1.2/1.3) with a certificate generated per run. `--pinnedpubkey` makes curl abort unless the server presents exactly that public key, so the agent can't be redirected to a different endpoint. `--insecure` only disables CA-chain validation, which a self-signed certificate can't pass; the pin replaces it.
- **Client authentication:** the one-time password is 256 bits from the OS CSPRNG and is compared in constant time.
- **Single use:** the first successful `GET /secret` returns the secret, then the server exits.
- **Limits:** after 5 failed authentication attempts, or when the expiry is reached, the server exits without sharing the secret.
- **Scope:** listens on loopback only unless `--public` or `--bind` is given.
