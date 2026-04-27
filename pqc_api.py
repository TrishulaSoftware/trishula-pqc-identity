"""
Trishula PQC Identity — Flask API Wrapper
Exposes ML-KEM-768 key generation, encapsulation, and signing via REST API.

Endpoints:
    POST /api/v1/keygen     — Generate a new PQC agent keypair
    POST /api/v1/encapsulate — Encapsulate a payload for a recipient
    POST /api/v1/decapsulate — Decapsulate and verify a PQC envelope
    POST /api/v1/sign        — Sign arbitrary data with SHA3-512
    POST /api/v1/verify      — Verify a SHA3-512 signature
    GET  /health             — Service health check
"""

import os
import json
import base64
import shutil
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from pqc_identity import PqcAgent, PqcSigner

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | PQC-API | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("pqc-api")

app = Flask(__name__)

VAULT_DIR = os.environ.get("PQC_VAULT_DIR", "./vault/keys")
_agents = {}


def _get_or_create_agent(agent_id: str) -> PqcAgent:
    """Retrieve or create a PQC agent by ID."""
    if agent_id not in _agents:
        _agents[agent_id] = PqcAgent(agent_id, vault_dir=VAULT_DIR)
    return _agents[agent_id]


@app.route("/health", methods=["GET"])
def health():
    """Service health check."""
    return jsonify({
        "status": "OPERATIONAL",
        "service": "trishula-pqc-identity-api",
        "version": "1.0.0",
        "pqc_algorithm": "ML-KEM-768",
        "agents_loaded": len(_agents),
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/v1/keygen", methods=["POST"])
def keygen():
    """
    Generate a new PQC agent keypair.

    Request: {"agent_id": "alice"}
    Response: {"agent_id": "alice", "public_key": "<base64>", "version": 0}
    """
    data = request.get_json()
    if not data or "agent_id" not in data:
        return jsonify({"error": "Missing 'agent_id' field"}), 400

    agent_id = data["agent_id"]
    agent = _get_or_create_agent(agent_id)

    logger.info(f"[KEYGEN] Agent '{agent_id}' — version {agent.version}")

    return jsonify({
        "agent_id": agent_id,
        "public_key": base64.b64encode(agent.public_key).decode("utf-8"),
        "version": agent.version,
        "hardware_pqc": agent.using_hardware_pqc,
        "algorithm": "ML-KEM-768",
        "generated_at": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/v1/encapsulate", methods=["POST"])
def encapsulate():
    """
    Encapsulate a payload for a recipient.

    Request: {
        "sender_id": "alice",
        "recipient_public_key": "<base64>",
        "payload": {"command": "deploy"}
    }
    Response: PQC envelope
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request body"}), 400

    required = ["sender_id", "recipient_public_key", "payload"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing '{field}' field"}), 400

    sender = _get_or_create_agent(data["sender_id"])
    recipient_pk = base64.b64decode(data["recipient_public_key"])

    envelope = sender.encapsulate(recipient_pk, data["payload"])
    logger.info(f"[ENCAP] {data['sender_id']} -> envelope created")

    return jsonify(envelope)


@app.route("/api/v1/decapsulate", methods=["POST"])
def decapsulate():
    """
    Decapsulate and verify a PQC envelope.

    Request: {"recipient_id": "bob", "envelope": {<PQC envelope>}}
    Response: {"payload": {<original data>}, "verified": true}
    """
    data = request.get_json()
    if not data or "recipient_id" not in data or "envelope" not in data:
        return jsonify({"error": "Missing 'recipient_id' or 'envelope'"}), 400

    recipient = _get_or_create_agent(data["recipient_id"])

    try:
        payload = recipient.decapsulate(data["envelope"])
        logger.info(f"[DECAP] {data['recipient_id']} — verified OK")
        return jsonify({
            "payload": payload,
            "verified": True,
            "recipient": data["recipient_id"],
            "sender": data["envelope"].get("sender", "unknown")
        })
    except PermissionError as e:
        logger.warning(f"[DECAP] TAMPER DETECTED — {e}")
        return jsonify({"error": "Signature verification failed — payload tampered", "verified": False}), 403
    except ValueError as e:
        return jsonify({"error": str(e), "verified": False}), 400


@app.route("/api/v1/sign", methods=["POST"])
def sign():
    """
    Sign arbitrary data with SHA3-512.

    Request: {"agent_id": "alice", "data": {"event": "build"}}
    Response: {"signature": "<hex>", "algorithm": "SHA3-512"}
    """
    data = request.get_json()
    if not data or "agent_id" not in data or "data" not in data:
        return jsonify({"error": "Missing 'agent_id' or 'data'"}), 400

    agent = _get_or_create_agent(data["agent_id"])
    signature = PqcSigner.sign(data["data"], agent._sk)

    logger.info(f"[SIGN] {data['agent_id']} — signed payload")
    return jsonify({
        "signature": signature,
        "algorithm": "SHA3-512",
        "agent_id": data["agent_id"],
        "signed_at": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/v1/verify", methods=["POST"])
def verify():
    """
    Verify a SHA3-512 signature.

    Request: {"agent_id": "alice", "data": {...}, "signature": "<hex>"}
    Response: {"verified": true}
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request body"}), 400

    required = ["agent_id", "data", "signature"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing '{field}' field"}), 400

    agent = _get_or_create_agent(data["agent_id"])
    is_valid = PqcSigner.verify(data["data"], data["signature"], agent._sk)

    logger.info(f"[VERIFY] {data['agent_id']} — {'PASS' if is_valid else 'FAIL'}")
    return jsonify({
        "verified": is_valid,
        "agent_id": data["agent_id"],
        "verified_at": datetime.now(timezone.utc).isoformat()
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8444))
    logger.info(f"PQC Identity API starting on port {port}")
    app.run(host="0.0.0.0", port=port)
