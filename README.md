# mesh-peer-registry

A small, shared, language-agnostic peer registry for the mesh network used by [`hermes-mesh`](https://github.com/emiltsoi/hermes-mesh) and [`openclaw-mesh`](https://github.com/emiltsoi/openclaw-mesh).

Peers register with an Ed25519 public key and a webhook URL, then discover each other over a simple HTTP API. The server never holds private keys.

## About

`mesh-peer-registry` provides a centralized but state-light way for mesh agents to announce themselves to one another:

- Peers register an Ed25519 **public key** and a **webhook URL** under a unique name.
- Registration and deregistration requests are signed by the peer's private key, so the registry can trust the public key it stores.
- Other peers query the registry to find a recipient's webhook URL and public key.
- Mesh messages are signed by the sender and verified by the receiver against the sender's public key from the registry.

The signing protocol uses compact, deterministic, sorted-key JSON, making it straightforward to implement in other runtimes (e.g. the Node.js implementation in `openclaw-mesh`).

## Features

- **HTTP API** for register, list, get, and deregister operations.
- **Ed25519 signatures** on all mutating requests.
- **In-memory** store by default, or **file-backed** persistence via `--store`.
- **CLI** server launcher.
- **Python client** (`RegistryClient`) with built-in signing.
- No private keys kept by the registry.

## Quick start

Install and run the server:

```bash
pip install mesh-peer-registry
mesh-peer-registry --port 8646 --store ./registry.json
```

The server will listen on `http://127.0.0.1:8646`.

## API

- `POST /register` — register or update a peer (signed with the peer's private key).
- `GET /peers` — list all peers.
- `GET /peers/{name}` — get one peer.
- `DELETE /peers/{name}` — deregister a peer (signed with the peer's private key).

All registration/deregistration requests must include a valid Ed25519 signature in the `X-Mesh-Signature` header.

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
)

print(client.list_peers())
```

## Verifying a message

```python
from mesh_peer_registry.crypto import verify_message
from mesh_peer_registry.client import RegistryClient

client = RegistryClient("http://127.0.0.1:8646", "", "")
peer = client.get_peer("agent0")

# body is the raw request body; signature is from the X-Mesh-Signature header.
ok = verify_message(peer.public_key, body, signature)
```

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

[MIT](LICENSE)
