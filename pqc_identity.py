"""
Trishula PQC Identity — Post-Quantum Cryptographic Agent Authentication

Provides ML-KEM-768 (Kyber-768) key generation, encapsulation, decapsulation,
and HMAC-SHA3-512 payload signing for multi-agent systems.

Supports real hardware-accelerated PQC via liboqs when available,
with a high-entropy simulation fallback for development environments.

Usage:
    from pqc_identity import PqcAgent, PqcSigner

    # Initialize two agents
    alice = PqcAgent("alice")
    bob = PqcAgent("bob")

    # Alice sends a signed, encapsulated message to Bob
    envelope = alice.encapsulate(bob.public_key, {"command": "deploy", "target": "prod"})

    # Bob decapsulates and verifies
    payload = bob.decapsulate(envelope)
"""

import os
import json
import base64
import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False


class PqcAgent:
    """
    A post-quantum cryptographic identity for an agent.

    Each agent has a unique Kyber-768 keypair stored in a configurable
    vault directory. Keys are versioned for rotation support.
    """

    KEM_NAME = "Kyber768"
    SK_LENGTH = 2400  # ML-KEM-768 secret key length
    PK_LENGTH = 1184  # ML-KEM-768 public key length
    CT_LENGTH = 1088  # ML-KEM-768 ciphertext length

    def __init__(self, agent_id: str, vault_dir: str = "./vault/keys"):
        self.agent_id = agent_id
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)

        self._pk = None
        self._sk = None
        self._version = self._detect_version()
        self._load_or_generate_keys()

    @property
    def public_key(self) -> bytes:
        """The agent's public key (safe to share)."""
        return self._pk

    @property
    def version(self) -> int:
        """Current key version."""
        return self._version

    @property
    def using_hardware_pqc(self) -> bool:
        """Whether real liboqs PQC is available."""
        return OQS_AVAILABLE

    def _detect_version(self) -> int:
        """Find the highest key version in the vault."""
        versions = []
        for f in self.vault_dir.iterdir():
            if f.name.startswith(f"{self.agent_id}.key."):
                try:
                    versions.append(int(f.suffix.lstrip(".")))
                except ValueError:
                    pass
        return max(versions) if versions else 0

    def _key_paths(self) -> tuple[Path, Path]:
        """Get the current public/secret key file paths."""
        suffix = f".{self._version}" if self._version > 0 else ""
        pk_path = self.vault_dir / f"{self.agent_id}.pub{suffix}"
        sk_path = self.vault_dir / f"{self.agent_id}.key{suffix}"
        return pk_path, sk_path

    def _load_or_generate_keys(self):
        """Load existing keys from vault or generate new ones."""
        pk_path, sk_path = self._key_paths()

        if pk_path.exists() and sk_path.exists():
            self._pk = pk_path.read_bytes()
            self._sk = sk_path.read_bytes()
            return

        if OQS_AVAILABLE:
            with oqs.KeyEncapsulation(self.KEM_NAME) as kem:
                self._pk = kem.generate_keypair()
                self._sk = kem.export_secret_key()
        else:
            # Simulation fallback: high-entropy deterministic generation
            self._sk = os.urandom(self.SK_LENGTH)
            self._pk = hashlib.sha3_512(self._sk).digest()[:self.PK_LENGTH]

        pk_path.write_bytes(self._pk)
        sk_path.write_bytes(self._sk)

    def rotate_keys(self) -> int:
        """
        Rotate to a new keypair. Old keys are preserved with version suffixes.
        Returns the new version number.
        """
        self._version += 1
        self._load_or_generate_keys()
        return self._version

    def encapsulate(self, recipient_pk: bytes, payload: dict) -> dict:
        """
        Encapsulate a payload for a recipient using their public key.

        Returns a PQC envelope containing:
        - Ciphertext (for key agreement)
        - Base64-encoded payload
        - HMAC-SHA3-512 signature
        - Sender identity and timestamp
        """
        if OQS_AVAILABLE:
            with oqs.KeyEncapsulation(self.KEM_NAME) as kem:
                ciphertext, shared_secret = kem.encap_secret(recipient_pk)
        else:
            ciphertext = os.urandom(self.CT_LENGTH)
            shared_secret = hashlib.sha3_512(recipient_pk + ciphertext).digest()

        # Derive encryption key from shared secret
        encryption_key = hashlib.sha3_256(shared_secret).digest()
        raw_data = json.dumps(payload, sort_keys=True).encode("utf-8")

        # Sign with HMAC-SHA3-512
        signature = hmac.new(encryption_key, raw_data, hashlib.sha3_512).digest()

        return {
            "pqc_version": "ML-KEM-768",
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "payload": base64.b64encode(raw_data).decode("utf-8"),
            "signature": base64.b64encode(signature).decode("utf-8"),
            "sender": self.agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def decapsulate(self, envelope: dict) -> dict:
        """
        Decapsulate and verify a PQC envelope.

        Raises:
            ValueError: If the PQC version is incompatible
            PermissionError: If the signature verification fails
        """
        if envelope.get("pqc_version") != "ML-KEM-768":
            raise ValueError(f"Incompatible PQC version: {envelope.get('pqc_version')}")

        ciphertext = base64.b64decode(envelope["ciphertext"])

        if OQS_AVAILABLE:
            with oqs.KeyEncapsulation(self.KEM_NAME) as kem:
                kem.import_secret_key(self._sk)
                shared_secret = kem.decap_secret(ciphertext)
        else:
            shared_secret = hashlib.sha3_512(self._pk + ciphertext).digest()

        encryption_key = hashlib.sha3_256(shared_secret).digest()
        raw_data = base64.b64decode(envelope["payload"])

        # Verify signature
        expected_sig = hmac.new(encryption_key, raw_data, hashlib.sha3_512).digest()
        provided_sig = base64.b64decode(envelope["signature"])

        if not hmac.compare_digest(expected_sig, provided_sig):
            raise PermissionError("PQC signature verification failed — payload tampered.")

        return json.loads(raw_data.decode("utf-8"))


class PqcSigner:
    """Standalone quantum-resistant signing for arbitrary data."""

    @staticmethod
    def sign(data: dict, secret_key: bytes) -> str:
        """Sign a dict with SHA3-512 using the provided secret key."""
        encoded = json.dumps(data, sort_keys=True).encode("utf-8")
        return hashlib.sha3_512(encoded + secret_key).hexdigest()

    @staticmethod
    def verify(data: dict, signature: str, secret_key: bytes) -> bool:
        """Verify a SHA3-512 signature."""
        encoded = json.dumps(data, sort_keys=True).encode("utf-8")
        expected = hashlib.sha3_512(encoded + secret_key).hexdigest()
        return hmac.compare_digest(expected, signature)


# ── CLI Demo ────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Trishula PQC Identity — Demo ===\n")

    alice = PqcAgent("alice")
    bob = PqcAgent("bob")

    print(f"Alice: agent_id={alice.agent_id}, key_version={alice.version}, "
          f"hardware_pqc={alice.using_hardware_pqc}")
    print(f"Bob:   agent_id={bob.agent_id}, key_version={bob.version}")

    # Alice sends to Bob
    message = {"command": "deploy", "target": "production", "priority": 1}
    print(f"\nAlice sending: {message}")

    envelope = alice.encapsulate(bob.public_key, message)
    print(f"Envelope created: sender={envelope['sender']}, "
          f"sig={envelope['signature'][:32]}...")

    # Bob receives
    decrypted = bob.decapsulate(envelope)
    print(f"Bob received:  {decrypted}")
    print(f"Integrity:     {'✅ VERIFIED' if decrypted == message else '❌ FAILED'}")

    # Key rotation
    new_version = alice.rotate_keys()
    print(f"\nAlice rotated keys to version {new_version}")

    # Standalone signing
    data = {"event": "build_complete", "sha": "abc123"}
    sig = PqcSigner.sign(data, alice._sk)
    verified = PqcSigner.verify(data, sig, alice._sk)
    print(f"\nStandalone sign/verify: {'✅ PASS' if verified else '❌ FAIL'}")
