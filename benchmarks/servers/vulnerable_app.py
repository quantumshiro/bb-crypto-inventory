"""Intentionally vulnerable Flask application for benchmarking bbci.

WARNING: This application contains INTENTIONAL cryptographic vulnerabilities.
It is designed ONLY for testing/benchmarking the bbci detection tool.
DO NOT deploy this in any real environment.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from functools import wraps

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from flask import Flask, jsonify, request

app = Flask(__name__)

# ============================================================
# Shared keys and state (intentionally insecure for benchmarking)
# ============================================================

# AES key (128-bit) — shared across all AES endpoints
AES_KEY = b"\x00" * 16
# Static IV for BM-02 (intentionally insecure)
STATIC_IV = b"\x01" * 16
# HMAC secret
HMAC_SECRET = b"benchmark-hmac-secret-key-12345678"

# RSA key pair for JWT RS256
RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PUBLIC_KEY = RSA_PRIVATE_KEY.public_key()
RSA_PUBLIC_PEM = RSA_PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# LCG state for BM-05 (intentionally weak PRNG)
_lcg_state = int(time.time()) & 0xFFFFFFFF


def _lcg_next() -> int:
    """Linear Congruential Generator (java.util.Random compatible parameters)."""
    global _lcg_state
    _lcg_state = (_lcg_state * 1103515245 + 12345) & 0x7FFFFFFF
    return _lcg_state


# ============================================================
# BM-01: ECB Mode Encryption
# ============================================================

@app.route("/api/encrypt", methods=["POST"])
def encrypt_ecb():
    """AES-128-ECB encryption. Identical blocks → identical ciphertext."""
    plaintext = request.get_data()
    if not plaintext:
        return jsonify({"error": "No data provided"}), 400

    # Pad to 16-byte boundary (PKCS7)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()

    return jsonify({
        "ciphertext": base64.b64encode(ct).decode(),
        "algorithm": "AES-128",  # intentionally omits "ECB"
        "length": len(ct),
    })


# ============================================================
# BM-02: Static IV (AES-CBC with hardcoded IV)
# ============================================================

@app.route("/api/encrypt-cbc-static", methods=["POST"])
def encrypt_cbc_static():
    """AES-128-CBC with static IV. Same plaintext → same ciphertext."""
    plaintext = request.get_data()
    if not plaintext:
        return jsonify({"error": "No data provided"}), 400

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(STATIC_IV))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()

    return jsonify({
        "ciphertext": base64.b64encode(ct).decode(),
        "iv": base64.b64encode(STATIC_IV).decode(),
        "algorithm": "AES-128-CBC",
    })


# ============================================================
# Negative Control: Strong encryption (AES-256-GCM, random nonce)
# ============================================================

@app.route("/api/encrypt-strong", methods=["POST"])
def encrypt_strong():
    """AES-256-GCM with random nonce. Should NOT trigger alerts."""
    plaintext = request.get_data()
    if not plaintext:
        return jsonify({"error": "No data provided"}), 400

    key = os.urandom(32)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()

    return jsonify({
        "ciphertext": base64.b64encode(nonce + ct + enc.tag).decode(),
        "algorithm": "AES-256-GCM",
    })


# ============================================================
# BM-03: Weak Hash (MD5)
# ============================================================

@app.route("/api/hash", methods=["POST"])
def hash_md5():
    """Returns MD5 hash of input data."""
    data = request.get_data()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    digest = hashlib.md5(data).hexdigest()
    return jsonify({
        "hash": digest,
        "algorithm": "secure-hash",  # intentionally vague
    })


# ============================================================
# BM-04: Weak Hash (SHA-1)
# ============================================================

@app.route("/api/hash-sha1", methods=["POST"])
def hash_sha1():
    """Returns SHA-1 hash of input data."""
    data = request.get_data()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    digest = hashlib.sha1(data).hexdigest()
    return jsonify({
        "hash": digest,
        "integrity": "verified",
    })


# ============================================================
# Negative Control: Strong hash (SHA-256)
# ============================================================

@app.route("/api/hash-strong", methods=["POST"])
def hash_strong():
    """Returns SHA-256 hash. Should NOT trigger WeakHash."""
    data = request.get_data()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    digest = hashlib.sha256(data).hexdigest()
    return jsonify({"hash": digest})


# ============================================================
# BM-05: Insecure Random (LCG)
# ============================================================

@app.route("/api/token", methods=["GET"])
def token_lcg():
    """Generate a session token using an LCG (predictable)."""
    # Generate 16 bytes from LCG
    token_bytes = b""
    for _ in range(4):
        val = _lcg_next()
        token_bytes += struct.pack(">I", val)

    return jsonify({
        "token": token_bytes.hex(),
        "type": "session",
    })


# ============================================================
# Negative Control: Secure random tokens
# ============================================================

@app.route("/api/token-secure", methods=["GET"])
def token_secure():
    """Generate a secure session token. Should NOT trigger InsecureRandom."""
    token = os.urandom(16).hex()
    return jsonify({"token": token, "type": "session"})


# ============================================================
# BM-06: Padding Oracle
# ============================================================

@app.route("/api/decrypt", methods=["POST"])
def decrypt_padding_oracle():
    """AES-CBC decryption that leaks padding validity via error messages.

    This is the classic Padding Oracle vulnerability:
    - Valid padding → "Decryption successful" or content error
    - Invalid padding → "Padding error" (different error message!)
    """
    data = request.get_data()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        ct = base64.b64decode(data)
    except Exception:
        try:
            ct = bytes.fromhex(data.decode())
        except Exception:
            return jsonify({"error": "Invalid encoding"}), 400

    if len(ct) < 32:  # Need at least IV + 1 block
        return jsonify({"error": "Ciphertext too short"}), 400

    iv = ct[:16]
    ciphertext = ct[16:]

    try:
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
        dec = cipher.decryptor()
        padded_pt = dec.update(ciphertext) + dec.finalize()

        # Check padding manually (INTENTIONALLY leaky)
        pad_len = padded_pt[-1]
        if pad_len == 0 or pad_len > 16:
            # LEAK: Different error for bad padding value
            return jsonify({"error": "Padding error: invalid pad length"}), 400

        for i in range(1, pad_len + 1):
            if padded_pt[-i] != pad_len:
                # LEAK: Different error for inconsistent padding
                return jsonify({"error": "Padding error: inconsistent padding bytes"}), 400

        plaintext = padded_pt[:-pad_len]
        return jsonify({
            "plaintext": base64.b64encode(plaintext).decode(),
            "status": "success",
        })

    except Exception as e:
        # LEAK: Generic decryption error (different from padding errors)
        return jsonify({"error": f"Decryption failed: {type(e).__name__}"}), 500


# ============================================================
# BM-07: JWT alg=none
# ============================================================

@app.route("/api/auth", methods=["POST"])
def auth_jwt_none():
    """JWT verification that accepts alg=none."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        # Issue a token for testing
        import jwt as pyjwt
        token = pyjwt.encode(
            {"sub": "benchmark-user", "role": "user"},
            HMAC_SECRET,
            algorithm="HS256",
        )
        return jsonify({"token": token, "note": "Send back with Authorization: Bearer <token>"})

    token = auth_header[7:]

    try:
        # VULNERABILITY: Accepts alg=none
        parts = token.split(".")
        if len(parts) >= 2:
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            if header.get("alg") == "none":
                # Accept without verification!
                payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                return jsonify({"authenticated": True, "user": payload})

        # Normal verification for other algorithms
        import jwt as pyjwt
        payload = pyjwt.decode(token, HMAC_SECRET, algorithms=["HS256"])
        return jsonify({"authenticated": True, "user": payload})

    except Exception as e:
        return jsonify({"authenticated": False, "error": str(e)}), 401


# ============================================================
# BM-08: JWT RS256 → HS256 confusion
# ============================================================

@app.route("/api/auth-rsa", methods=["POST"])
def auth_jwt_rsa_confusion():
    """JWT verification vulnerable to RS256→HS256 algorithm confusion."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        # Issue an RS256 token
        import jwt as pyjwt
        token = pyjwt.encode(
            {"sub": "benchmark-user", "role": "user"},
            RSA_PRIVATE_KEY,
            algorithm="RS256",
        )
        return jsonify({
            "token": token,
            "public_key": RSA_PUBLIC_PEM.decode(),
            "note": "Verify with RS256 and the provided public key",
        })

    token = auth_header[7:]

    try:
        parts = token.split(".")
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        alg = header.get("alg", "RS256")

        import jwt as pyjwt

        # VULNERABILITY: Uses the public key as HMAC secret when alg=HS256
        if alg == "HS256":
            payload = pyjwt.decode(
                token, RSA_PUBLIC_PEM, algorithms=["HS256"]
            )
        else:
            payload = pyjwt.decode(
                token, RSA_PUBLIC_KEY, algorithms=["RS256"]
            )

        return jsonify({"authenticated": True, "user": payload})

    except Exception as e:
        return jsonify({"authenticated": False, "error": str(e)}), 401


# ============================================================
# BM-10: Timing side-channel (non-constant-time HMAC verification)
# ============================================================

@app.route("/api/verify-hmac", methods=["POST"])
def verify_hmac_timing():
    """HMAC verification using byte-by-byte comparison (non-constant-time).

    VULNERABILITY: Early termination on first mismatch leaks timing info.
    """
    data = request.json
    if not data or "message" not in data or "mac" not in data:
        return jsonify({"error": "Provide 'message' and 'mac'"}), 400

    message = data["message"].encode()
    provided_mac = data["mac"]

    # Compute expected HMAC
    expected = hmac.new(HMAC_SECRET, message, hashlib.sha256).hexdigest()

    # VULNERABILITY: Non-constant-time comparison (byte-by-byte with early exit)
    if len(provided_mac) != len(expected):
        return jsonify({"valid": False}), 401

    for i in range(len(expected)):
        if provided_mac[i] != expected[i]:
            # Early termination — timing leak!
            return jsonify({"valid": False}), 401
        # Simulate slight processing time per byte to amplify timing signal
        _ = hashlib.sha256(message + bytes([i])).digest()

    return jsonify({"valid": True}), 200


# ============================================================
# Negative Control: Constant-time HMAC verification
# ============================================================

@app.route("/api/verify-hmac-secure", methods=["POST"])
def verify_hmac_secure():
    """Constant-time HMAC verification. Should NOT trigger TimingLeak."""
    data = request.json
    if not data or "message" not in data or "mac" not in data:
        return jsonify({"error": "Provide 'message' and 'mac'"}), 400

    message = data["message"].encode()
    expected = hmac.new(HMAC_SECRET, message, hashlib.sha256).hexdigest()

    if hmac.compare_digest(provided_mac := data["mac"], expected):
        return jsonify({"valid": True}), 200
    return jsonify({"valid": False}), 401


# ============================================================
# Health check
# ============================================================

@app.route("/health")
def health():
    return jsonify({"status": "ok", "benchmarks": 10})


@app.route("/")
def index():
    return jsonify({
        "service": "bbci-benchmark-server",
        "version": "0.1.0",
        "endpoints": [
            {"path": "/api/encrypt", "benchmark": "BM-01", "vuln": "ECB Mode"},
            {"path": "/api/encrypt-cbc-static", "benchmark": "BM-02", "vuln": "Static IV"},
            {"path": "/api/hash", "benchmark": "BM-03", "vuln": "MD5"},
            {"path": "/api/hash-sha1", "benchmark": "BM-04", "vuln": "SHA-1"},
            {"path": "/api/token", "benchmark": "BM-05", "vuln": "Insecure Random (LCG)"},
            {"path": "/api/decrypt", "benchmark": "BM-06", "vuln": "Padding Oracle"},
            {"path": "/api/auth", "benchmark": "BM-07", "vuln": "JWT alg=none"},
            {"path": "/api/auth-rsa", "benchmark": "BM-08", "vuln": "JWT RS256→HS256"},
            {"path": "/api/verify-hmac", "benchmark": "BM-10", "vuln": "Timing Leak"},
        ],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000, debug=False)
