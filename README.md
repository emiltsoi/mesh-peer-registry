# mesh-peer-registry

A small, shared, language-agnostic peer registry for the mesh network used by [`hermes-mesh`](https://github.com/emiltsoi/hermes-mesh) and [`openclaw-mesh`](https://github.com/emiltsoi/openclaw-mesh).

Peers register with an Ed25519 public key and a webhook URL, then discover each other over a simple HTTP API. The server never holds private keys.

## About

`mesh-peer-registry` provides a centralized but state-light way for mesh agents to announce themselves to one another:

- Peers register an Ed25519 **public key** and a **webhook URL** under a unique name.
- Registration, deregistration, and refresh requests are signed by the peer's private key, so the registry can trust the public key it stores.
- Other peers query the registry to find a recipient's webhook URL and public key.
- Mesh messages are signed by the sender and verified by the receiver against the sender's public key from the registry.

The signing protocol uses compact, deterministic, sorted-key JSON, making it straightforward to implement in other runtimes (e.g. the Node.js implementation in `openclaw-mesh`).

## Features

- **HTTP API** for register, list, get, refresh, and deregister operations.
- **Ed25519 signatures** on all mutating requests.
- **SQLite-backed** store by default, with the path configurable via `--store`.
- **TTL + reaper** — peers can register with a TTL in seconds; a background reaper removes expired peers and refreshes keep them alive.
- **CLI** server launcher.
- **Python client** (`RegistryClient`) with built-in signing.
- No private keys kept by the registry.

## Quick start

Install and run the server:

```bash
pip install mesh-peer-registry
mesh-peer-registry --port 8646 --store ~/.mesh/registry.sqlite
```

The server will listen on `http://127.0.0.1:8646` and store peers in `~/.mesh/registry.sqlite`.

### CLI options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `127.0.0.1` | Bind host. |
| `--port` | `8646` | Bind port. |
| `--store` | `~/.mesh/registry.sqlite` | SQLite store file path. |
| `--reaper-interval` | `60.0` | Interval in seconds between TTL reaping passes. |
| `--admin-token` | — | Token required for `/health` and `/metrics`. |
| `--ssl-cert` / `--ssl-key` | — | Optional TLS certificate and key for HTTPS. |

## API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/register` | Register or update a peer. Body must include `name`, `url`, `public_key`. Optional: `role`, `description`, `ttl` (seconds). Signed with `X-Mesh-Signature`. |
| `GET` | `/peers` | List peers. Query params: `role`, `limit`, `offset`. Returns `{peers, total, limit, offset}`. |
| `GET` | `/peers/{name}` | Get one peer. |
| `POST` | `/peers/{name}/refresh` | Refresh `last_seen` for a peer (prevents TTL expiry). Signed with `X-Mesh-Signature`. |
| `DELETE` | `/peers/{name}` | Deregister a peer. Signed with `X-Mesh-Signature`. |
| `GET` | `/health` | Health check. Requires `X-Admin-Token` if `--admin-token` is set. |
| `GET` | `/metrics` | Basic registry metrics. Requires `X-Admin-Token` if `--admin-token` is set. |

All registration, refresh, and deregistration requests must include a valid Ed25519 signature in the `X-Mesh-Signature` header over the sorted JSON body (or the action payload for refresh/deregister).

## Python client

```python
from mesh_peer_registry.crypto import generate_keypair
from mesh_peer_registry.client import RegistryClient

private, public = generate_keypair()
client = RegistryClient("http://127.0.0.1:8646", private, public)

client.register(
    "agent0",
    "http://127.0.0.1:8645/mesh/receive",
    role="operator",
    description="Hermes operator node",
    ttl=3600,
)

print(client.list_peers())

# Keep the registration alive before the TTL expires.
client.refresh("agent0")

# Later, deregister.
client.deregister("agent0")
```

## Verifying a message

Receivers fetch the sender's public key from the registry and verify the `X-Mesh-Signature` header:

```python
from mesh_peer_registry.crypto import verify_message
from mesh_peer_registry.client import RegistryClient

client = RegistryClient("http://127.0.0.1:8646", "", "")
peer = client.get_peer("agent0")

# body is the raw request body; signature is from the X-Mesh-Signature header.
ok = verify_message(peer.public_key, body, signature)
```

When `X-Mesh-Timestamp` is included in the signed payload (optional, controlled by `MESH_SIGN_TIMESTAMP` on the sender), the receiver should prepend `f"{timestamp}\n"` to the body before verification. Backward-compatible receivers try both forms.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

[MIT](LICENSE)
