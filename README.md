# mesh-peer-registry

Shared, language-agnostic peer registry for `hermes-mesh` and `openclaw-mesh`.

Peers register with an Ed25519 public key and a webhook URL, then discover each other over a simple HTTP API. The server never holds private keys.

## Quick start

```bash
pip install mesh-peer-registry
mesh-peer-registry --port 8646
```

## API

- `POST /register` — register or update a peer (signed with peer's private key).
- `GET /peers` — list all peers.
- `GET /peers/{name}` — get one peer.
- `DELETE /peers/{name}` — deregister a peer (signed with peer's private key).
