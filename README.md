# agent-network-secret-share

Hand a secret (e.g. an access token) to an AI agent without pasting it into the chat.

```
cargo run --release
```

1. You're prompted for the secret (input is hidden).
2. The app binds to a random TCP port on `127.0.0.1` and generates a random one-time password.
3. It prints a short prompt to paste into your AI agent, containing the `curl` command to fetch the secret.

## Security properties

- The one-time password is 256 bits from the OS CSPRNG and is compared in constant time.
- The first successful `GET /secret` with `Authorization: Bearer <password>` returns the secret, and then the server exits. The password can't be used again.
- After 5 failed authentication attempts the server exits without sharing the secret.
- It listens on loopback only by default. Pass `--public` to listen on all network interfaces (the printed URL then uses this machine's LAN IP), or `--bind HOST` for a specific address. Traffic is plain HTTP, so only do this on a network you trust.
