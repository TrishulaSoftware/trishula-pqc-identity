"""
Trishula PQC Identity API — Test Suite
SQA v5 [ASCENDED] Compliance: Full endpoint coverage
"""
import json
import sys
import os
import shutil
sys.path.insert(0, os.path.dirname(__file__))
from pqc_api import app

PASSED = 0
FAILED = 0
VAULT = os.path.join(os.path.dirname(__file__), "_test_api_vault")
os.environ["PQC_VAULT_DIR"] = VAULT

def test(name, condition):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  PASS: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name}")

if os.path.exists(VAULT):
    shutil.rmtree(VAULT)

print("=" * 60)
print("  TRISHULA PQC IDENTITY API — SQA TEST SUITE")
print("=" * 60)

client = app.test_client()

# -- TEST GROUP 1: Health --
print("\n-- TEST GROUP 1: Health Endpoint --")
resp = client.get("/health")
data = resp.get_json()
test("Health returns 200", resp.status_code == 200)
test("Status is OPERATIONAL", data.get("status") == "OPERATIONAL")
test("Algorithm is ML-KEM-768", data.get("pqc_algorithm") == "ML-KEM-768")
test("Version is 1.0.0", data.get("version") == "1.0.0")

# -- TEST GROUP 2: Keygen --
print("\n-- TEST GROUP 2: Key Generation --")
resp = client.post("/api/v1/keygen",
                   data=json.dumps({"agent_id": "test_alice"}),
                   content_type="application/json")
data = resp.get_json()
test("Keygen returns 200", resp.status_code == 200)
test("Returns agent_id", data.get("agent_id") == "test_alice")
test("Returns public_key", "public_key" in data)
test("Returns version", "version" in data)
test("Returns algorithm", data.get("algorithm") == "ML-KEM-768")
alice_pk = data["public_key"]

resp2 = client.post("/api/v1/keygen",
                    data=json.dumps({"agent_id": "test_bob"}),
                    content_type="application/json")
bob_data = resp2.get_json()
test("Bob keygen returns 200", resp2.status_code == 200)
test("Bob has different key", bob_data["public_key"] != alice_pk)

# Missing field
resp_err = client.post("/api/v1/keygen",
                       data=json.dumps({}),
                       content_type="application/json")
test("Missing agent_id returns 400", resp_err.status_code == 400)

# -- TEST GROUP 3: Encapsulate --
print("\n-- TEST GROUP 3: Encapsulate --")
payload = {"command": "deploy", "target": "staging"}
resp = client.post("/api/v1/encapsulate",
                   data=json.dumps({
                       "sender_id": "test_alice",
                       "recipient_public_key": bob_data["public_key"],
                       "payload": payload
                   }),
                   content_type="application/json")
envelope = resp.get_json()
test("Encapsulate returns 200", resp.status_code == 200)
test("Envelope has pqc_version", envelope.get("pqc_version") == "ML-KEM-768")
test("Envelope has ciphertext", "ciphertext" in envelope)
test("Envelope has payload", "payload" in envelope)
test("Envelope has signature", "signature" in envelope)
test("Envelope has sender", envelope.get("sender") == "test_alice")

# Missing field
resp_err = client.post("/api/v1/encapsulate",
                       data=json.dumps({"sender_id": "test_alice"}),
                       content_type="application/json")
test("Missing fields returns 400", resp_err.status_code == 400)

# -- TEST GROUP 4: Decapsulate --
print("\n-- TEST GROUP 4: Decapsulate --")
resp = client.post("/api/v1/decapsulate",
                   data=json.dumps({
                       "recipient_id": "test_bob",
                       "envelope": envelope
                   }),
                   content_type="application/json")
dec_data = resp.get_json()
test("Decapsulate returns 200", resp.status_code == 200)
test("Payload verified", dec_data.get("verified") == True)
test("Payload matches original", dec_data.get("payload") == payload)
test("Command field intact", dec_data["payload"]["command"] == "deploy")

# Tamper test
import base64
tampered_env = dict(envelope)
tampered_env["payload"] = base64.b64encode(b'{"hacked":true}').decode("utf-8")
resp_tamper = client.post("/api/v1/decapsulate",
                          data=json.dumps({
                              "recipient_id": "test_bob",
                              "envelope": tampered_env
                          }),
                          content_type="application/json")
test("Tampered payload returns 403", resp_tamper.status_code == 403)
test("Verified is False", resp_tamper.get_json().get("verified") == False)

# -- TEST GROUP 5: Sign / Verify --
print("\n-- TEST GROUP 5: Sign and Verify --")
sign_data = {"event": "build_complete", "sha": "abc123"}
resp = client.post("/api/v1/sign",
                   data=json.dumps({"agent_id": "test_alice", "data": sign_data}),
                   content_type="application/json")
sig_resp = resp.get_json()
test("Sign returns 200", resp.status_code == 200)
test("Has signature", "signature" in sig_resp)
test("Algorithm is SHA3-512", sig_resp.get("algorithm") == "SHA3-512")

# Verify valid
resp = client.post("/api/v1/verify",
                   data=json.dumps({
                       "agent_id": "test_alice",
                       "data": sign_data,
                       "signature": sig_resp["signature"]
                   }),
                   content_type="application/json")
ver_resp = resp.get_json()
test("Verify returns 200", resp.status_code == 200)
test("Valid signature verified", ver_resp.get("verified") == True)

# Verify tampered
resp = client.post("/api/v1/verify",
                   data=json.dumps({
                       "agent_id": "test_alice",
                       "data": {"event": "HACKED"},
                       "signature": sig_resp["signature"]
                   }),
                   content_type="application/json")
ver_resp = resp.get_json()
test("Tampered data fails verification", ver_resp.get("verified") == False)

# Cleanup
shutil.rmtree(VAULT, ignore_errors=True)

print("\n" + "=" * 60)
total = PASSED + FAILED
print(f"  RESULTS: {PASSED}/{total} PASSED, {FAILED}/{total} FAILED")
verdict = "SQA PASS" if FAILED == 0 else "SQA FAIL"
print(f"  VERDICT: {verdict}")
print("=" * 60)
