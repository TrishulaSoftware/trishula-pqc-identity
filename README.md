# Trishula PQC Identity

Post-quantum cryptographic authentication for multi-agent systems.

## What It Does

Provides **ML-KEM-768 (Kyber-768)** key generation, encapsulation, and HMAC-SHA3-512 payload signing — the same lattice-based cryptography selected by NIST for post-quantum standardization.

Use it to give each agent in your system a unique, quantum-resistant identity that can:
- **Sign** outbound payloads so recipients can verify authenticity
- **Encapsulate** data so only the intended recipient can read it
- **Rotate** keys with version tracking and zero downtime

## Quick Start

```python
from pqc_identity import PqcAgent, PqcSigner

# Create two agents with auto-generated keypairs
alice = PqcAgent("alice")
bob = PqcAgent("bob")

# Alice sends a signed message to Bob
envelope = alice.encapsulate(bob.public_key, {"action": "deploy"})

# Bob verifies and decrypts
payload = bob.decapsulate(envelope)  # {"action": "deploy"}

# Key rotation (old keys preserved)
alice.rotate_keys()

# Standalone signing for any data
sig = PqcSigner.sign({"build": "v1.2.3"}, alice._sk)
valid = PqcSigner.verify({"build": "v1.2.3"}, sig, alice._sk)  # True
```

## Installation

```bash
pip install -r requirements.txt
python pqc_identity.py  # Run the demo
```

For **real hardware-accelerated PQC** (not simulation), install [liboqs-python](https://github.com/open-quantum-safe/liboqs-python):

```bash
pip install liboqs-python
```

The library auto-detects liboqs and uses it when available. Without it, a high-entropy SHA3-512 simulation is used (suitable for development and testing).

## Key Vault

Keys are stored in `./vault/keys/` by default:

```
vault/keys/
├── alice.pub       # Public key (safe to share)
├── alice.key       # Secret key (never share)
├── alice.pub.1     # Rotated version 1
├── alice.key.1
├── bob.pub
└── bob.key
```

## Envelope Format

```json
{
  "pqc_version": "ML-KEM-768",
  "ciphertext": "base64...",
  "payload": "base64...",
  "signature": "base64 HMAC-SHA3-512",
  "sender": "alice",
  "timestamp": "2026-04-22T04:00:00Z"
}
```

## License

MIT
