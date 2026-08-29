# mesh-peer-registry

A small, shared, language-agnostic peer registry for the mesh network used by [`hermes-mesh`](https://github.com/emiltsoi/hermes-mesh), [`openclaw-mesh`](https://github.com/emiltsoi/openclaw-mesh), and [`diploid-mesh`](https://github.com/emiltsoi/diploid-mesh).

Peers register with an Ed25519 public key and a webhook URL, then discover each other over a simple HTTP API. The server never holds private keys.

## About

`mesh-peer-registry` provides a centralized but state-light way for mesh agents to announce themselves to one another:

- Peers register an Ed25519 **public key** and a **webhook URL** under a unique name.
- Registration, deregistration, and refresh requests are signed by the peer's private key, so the registry can trust the public key it stores.
- Other peers query the registry to find a recipient's webhook URL and public key.
- Mesh messages are signed by the sender and verified by the receiver against the sender's public key from the registry.

The signing protocol uses compact, deterministic, sorted-key JSON, making it straightforward to implement in other runtimes (e.g. the Node.js implementation in `openclaw-mesh`).

## Cross-harness mesh

`mesh-peer-registry` is the shared backbone that lets agents from different harnesses talk to each other:

- **Hermes** agents speak through [`hermes-mesh`](https://github.com/emiltsoi/hermes-mesh).
- **OpenClaw** agents speak through [`openclaw-mesh`](https://github.com/emiltsoi/openclaw-mesh).
- **diploid-agent** agents speak through [`diploid-mesh`](https://github.com/emiltsoi/diploid-mesh).

All three share:

- The bracketed `[mesh]` envelope format and Ed25519 wire signatures.
- The same local vault layout (`mesh/agents/<name>/identity.yaml`).
- The same optional [`mesh-peer-registry`](https://github.com/emiltsoi/mesh-peer-registry) server for multi-host discovery.

This means a Hermes fleet agent can `mesh_send` to a diploid agent, and the diploid agent can reply to an OpenClaw agent, with the same identity and envelope format everywhere.

## Features

- **HTTP API** for register, list, get, refresh, and deregister operations.
- **Ed25519 signatures** on all mutating requests.
- **SQLite-backed** store by default, with the path configurable via `--store`.
- **TTL + reaper** — peers can register with a TTL in seconds; a background reaper removes expired peers and refreshes keep them alive.
- **CLI** server launcher.
- **Python client** (`RegistryClient`) with built-in signing.
- No private keys kept by the registry.

## Quick start

Install and run the server over plain HTTP for local development:

```bash
pip install mesh-peer-registry
MESH_REGISTRY_ALLOW_INSECURE=1 mesh-peer-registry --port 8646 --store ~/.mesh/registry.sqlite
```

The server will listen on `http://127.0.0.1:8646` and store peers in `~/.mesh/registry.sqlite`.

For production, serve over HTTPS with `--ssl-cert` / `--ssl-key` and set `MESH_REGISTRY_HSTS=1` to emit `Strict-Transport-Security` headers.

### CLI options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `127.0.0.1` | Bind host. |
| `--port` | `8646` | Bind port. |
| `--store` | `~/.mesh/registry.sqlite` | SQLite store file path. |
| `--reaper-interval` | `60.0` | Interval in seconds between TTL reaping passes. |
| `--admin-token` | — | Token required for `/health` and `/metrics`. |
| `--ssl-cert` / `--ssl-key` | — | Optional TLS certificate and key for HTTPS. |
| `--behind-proxy` | `false` | Trust `X-Forwarded-Proto` and `X-Forwarded-For` from a reverse proxy. |
| `--rate-limit` | `0` | Maximum registrations per IP per minute (`0` disables). |
| `--hsts` | `false` | Emit `Strict-Transport-Security` for HTTPS responses. |

Environment variables mirror the flags and middleware settings:

- `MESH_REGISTRY_ALLOW_INSECURE` — set to `1` to allow plain HTTP requests.
- `MESH_REGISTRY_BEHIND_PROXY` — set to `1` to enable proxy header handling.
- `MESH_REGISTRY_RATE_LIMIT` — per-IP registration limit per minute (`0` disables).
- `MESH_REGISTRY_HSTS` — set to `1` to emit HSTS headers.
- `MESH_REGISTRY_PIN` — when set, the client verifies the server certificate SPKI matches this SHA-256 hex digest.

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

# For plain HTTP development, allow_insecure=True is required unless the
# server is configured with MESH_REGISTRY_ALLOW_INSECURE=1.
client = RegistryClient(
    "http://127.0.0.1:8646",
    private,
    public,
    allow_insecure=True,
    pin=None,
)

# For HTTPS production with certificate pinning:
# client = RegistryClient(
#     "https://registry.example.com",
#     private,
#     public,
#     pin="sha256-hex-of-server-certificate-spki",
# )

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

# Read-only lookup can use an empty keypair and allow_insecure for local HTTP.
client = RegistryClient(
    "http://127.0.0.1:8646",
    "",
    "",
    allow_insecure=True,
)
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
