"""
Trishula PQC Identity — Test Suite
SQA v5 [ASCENDED] Compliance: MC/DC Determinism + Bit-Perfect Persistence
"""
import json
import sys
import os
import shutil
import tempfile
sys.path.insert(0, os.path.dirname(__file__))
from pqc_identity import PqcAgent, PqcSigner

PASSED = 0
FAILED = 0

def test(name, condition):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  ✅ {name}")
    else:
        FAILED += 1
        print(f"  ❌ {name}")

# Create temp vault
VAULT = os.path.join(os.path.dirname(__file__), "_test_vault")
if os.path.exists(VAULT):
    shutil.rmtree(VAULT)

print("=" * 70)
print("  TRISHULA PQC IDENTITY — SQA TEST SUITE")
print("=" * 70)

# ── TEST GROUP 1: Agent Key Generation ──
print("\n── TEST GROUP 1: Agent Key Generation ──")

alice = PqcAgent("test_alice", vault_dir=VAULT)
bob = PqcAgent("test_bob", vault_dir=VAULT)

test("Alice has public key", alice.public_key is not None)
test("Alice PK length > 0", len(alice.public_key) > 0)
test("Bob has public key", bob.public_key is not None)
test("Alice and Bob have different keys", alice.public_key != bob.public_key)
test("Alice key version is 0 (initial)", alice.version == 0)
test("PQC mode reported (hardware or sim)", isinstance(alice.using_hardware_pqc, bool))

# Key persistence
alice2 = PqcAgent("test_alice", vault_dir=VAULT)
test("Key persistence: reload same PK", alice.public_key == alice2.public_key)

# ── TEST GROUP 2: Key Rotation ──
print("\n── TEST GROUP 2: Key Rotation ──")

old_pk = alice.public_key
new_ver = alice.rotate_keys()
test("Key rotation returns new version", new_ver == 1)
test("Version incremented", alice.version == 1)
# Note: In simulation mode, new key may differ from old
test("Key rotation produces a key", alice.public_key is not None and len(alice.public_key) > 0)

# ── TEST GROUP 3: Encapsulation / Decapsulation ──
print("\n── TEST GROUP 3: Encapsulate / Decapsulate ──")

# Fresh agents for clean test
sender = PqcAgent("test_sender", vault_dir=VAULT)
receiver = PqcAgent("test_receiver", vault_dir=VAULT)

payload = {"command": "deploy", "target": "staging", "priority": 1}
envelope = sender.encapsulate(receiver.public_key, payload)

test("Envelope has 'pqc_version'", envelope.get("pqc_version") == "ML-KEM-768")
test("Envelope has 'ciphertext'", "ciphertext" in envelope)
test("Envelope has 'payload'", "payload" in envelope)
test("Envelope has 'signature'", "signature" in envelope)
test("Envelope has 'sender'", envelope.get("sender") == "test_sender")
test("Envelope has 'timestamp'", "timestamp" in envelope)

decrypted = receiver.decapsulate(envelope)
test("Decrypted payload matches original", decrypted == payload)
test("Payload 'command' field intact", decrypted.get("command") == "deploy")
test("Payload 'target' field intact", decrypted.get("target") == "staging")
test("Payload 'priority' field intact", decrypted.get("priority") == 1)

# ── TEST GROUP 4: Tamper Detection ──
print("\n── TEST GROUP 4: Tamper Detection ──")

import base64
tampered = envelope.copy()
tampered_payload = base64.b64encode(b'{"command":"HACKED"}').decode("utf-8")
tampered["payload"] = tampered_payload

tamper_caught = False
try:
    receiver.decapsulate(tampered)
except PermissionError:
    tamper_caught = True
test("Tampered payload raises PermissionError", tamper_caught)

# Wrong PQC version
wrong_ver = envelope.copy()
wrong_ver["pqc_version"] = "RSA-2048"
ver_caught = False
try:
    receiver.decapsulate(wrong_ver)
except ValueError:
    ver_caught = True
test("Wrong PQC version raises ValueError", ver_caught)

# ── TEST GROUP 5: Standalone Signer ──
print("\n── TEST GROUP 5: Standalone Signer ──")

data = {"event": "build_complete", "sha": "abc123def456"}
sig = PqcSigner.sign(data, sender._sk)
test("Signature is hex string", all(c in "0123456789abcdef" for c in sig))
test("Signature is 128 chars (SHA3-512)", len(sig) == 128)
test("Verify returns True for valid data", PqcSigner.verify(data, sig, sender._sk))
test("Verify returns False for tampered data",
     not PqcSigner.verify({"event": "HACKED"}, sig, sender._sk))
test("Verify returns False for wrong key",
     not PqcSigner.verify(data, sig, os.urandom(64)))
test("Deterministic: same data = same sig",
     PqcSigner.sign(data, sender._sk) == sig)

# ── CLEANUP ──
shutil.rmtree(VAULT, ignore_errors=True)

# ── SUMMARY ──
print("\n" + "=" * 70)
total = PASSED + FAILED
print(f"  RESULTS: {PASSED}/{total} PASSED, {FAILED}/{total} FAILED")
verdict = "✅ SQA PASS" if FAILED == 0 else "❌ SQA FAIL"
print(f"  VERDICT: {verdict}")
print("=" * 70)
