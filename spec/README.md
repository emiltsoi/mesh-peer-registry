# Mesh Envelope Contract

This directory is the single source of truth for the `[mesh]` envelope format shared by `hermes-mesh`, `openclaw-mesh`, and `diploid-mesh`.

## Envelope format

```
[mesh][from:<sender>][to:<recipient>][id:<uuid>][action:do|info][reply:yes|no|end][ref:<uuid>]
<body>
```

- `from`, `to`, `id` are required.
- `action` and `reply` are required on send. On receive, missing `action` defaults to `info` and missing `reply` defaults to `no`.
- `ref` is optional and references the `id` of a prior message in the same thread.
- The optional `[v:<version>]` field comes immediately after `[mesh]`. It is reserved for future protocol versions.
- Token values may contain `A-Za-z0-9_.:-`, 1-128 characters.
- Body is free text. A body beginning with `[mesh-dsn]` marks a delivery-status notification.

## Reply contract

- `reply=yes` — the sender expects a response.
- `reply=no` — the sender does not expect a response.
- `reply=end` — terminal message. No reply is owed. Any subsequent message referencing this `id` via `ref` must be rejected with `THREAD_CLOSED` unless it is a DSN.

## Delivery

- Outbound POSTs must include `X-Mesh-Signature` (base64 Ed25519) and `X-Mesh-Timestamp` (Unix seconds).
- Receivers verify the signature using the sender's `public_key` from the vault or registry.
- Receivers enforce a replay window for `id` values (default 300s).
- Receivers enforce `THREAD_CLOSED` for `ref` values that are terminal anchors.

## DSN

- DSNs use `X-Mesh-DSN: 1` and a body beginning with `[mesh-dsn]`.
- DSNs are `action=info` and `reply=no`.
- DSNs are exempt from `THREAD_CLOSED` checks.
- DSN-of-DSN is forbidden.

## Identity

See `identity.schema.json`. Each agent has an `identity.yaml` under `<vault>/mesh/agents/<name>/`.
