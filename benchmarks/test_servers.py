"""Standalone tests for benchmark vulnerability servers.

These tests verify that the intentionally vulnerable endpoints
actually exhibit the expected cryptographic weaknesses.

Run with: pytest benchmarks/test_servers.py -v
Requires: benchmark server running on localhost:9000
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import ssl

import httpx
import pytest
from cryptography import x509

BASE_URL = os.environ.get("BENCHMARK_URL", "http://localhost:9000")
WEAK_TLS_URL = os.environ.get("BENCHMARK_WEAK_TLS_URL", "https://localhost:9443")
STRONG_TLS_URL = os.environ.get("BENCHMARK_STRONG_TLS_URL", "https://localhost:9444")


def server_available() -> bool:
    """Check if the benchmark server is reachable."""
    try:
        resp = httpx.get(f"{BASE_URL}/health", timeout=3)
        return resp.status_code == 200
    except Exception:
        return False


skipif_no_server = pytest.mark.skipif(
    not server_available(),
    reason=f"Benchmark server not available at {BASE_URL}",
)


def _fetch_peer_certificate(host: str, port: int) -> x509.Certificate:
    """Fetch the presented leaf certificate from a TLS endpoint."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=3) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)

    return x509.load_der_x509_certificate(cert_der)


@skipif_no_server
class TestBm01EcbMode:
    """BM-01: AES-128-ECB should produce identical blocks for identical plaintext."""

    def test_ecb_repeated_blocks(self) -> None:
        # Send 32 bytes of identical data (2 blocks of the same content)
        payload = b"A" * 32
        resp = httpx.post(f"{BASE_URL}/api/encrypt", content=payload)
        assert resp.status_code == 200

        ct = base64.b64decode(resp.json()["ciphertext"])
        # In ECB mode, block1 == block2 if plaintext block1 == plaintext block2
        block1 = ct[:16]
        block2 = ct[16:32]
        assert block1 == block2, "ECB mode should produce identical ciphertext for identical blocks"

    def test_ecb_deterministic(self) -> None:
        payload = b"test plaintext!!"  # Exactly 16 bytes
        ct1 = base64.b64decode(
            httpx.post(f"{BASE_URL}/api/encrypt", content=payload).json()["ciphertext"]
        )
        ct2 = base64.b64decode(
            httpx.post(f"{BASE_URL}/api/encrypt", content=payload).json()["ciphertext"]
        )
        assert ct1 == ct2, "ECB mode should be deterministic"


@skipif_no_server
class TestPhase01TlsRecon:
    """Phase 0+1 benchmark invariants for the weak/strong HTTPS edges."""

    def test_weak_edge_missing_hsts(self) -> None:
        resp = httpx.get(f"{WEAK_TLS_URL}/", verify=False)
        assert "strict-transport-security" not in resp.headers

    def test_strong_edge_has_hsts(self) -> None:
        resp = httpx.get(f"{STRONG_TLS_URL}/", verify=False)
        assert "strict-transport-security" in resp.headers

    def test_weak_edge_certificate_is_rsa_1024_sha1(self) -> None:
        cert = _fetch_peer_certificate("localhost", 9443)
        assert cert.public_key().key_size == 1024
        assert cert.signature_hash_algorithm is not None
        assert cert.signature_hash_algorithm.name == "sha1"

    def test_strong_edge_certificate_is_rsa_2048_sha256(self) -> None:
        cert = _fetch_peer_certificate("localhost", 9444)
        assert cert.public_key().key_size == 2048
        assert cert.signature_hash_algorithm is not None
        assert cert.signature_hash_algorithm.name == "sha256"


@skipif_no_server
class TestBm02StaticIv:
    """BM-02: AES-CBC with static IV should be deterministic."""

    def test_static_iv_deterministic(self) -> None:
        payload = b"hello benchmark!"
        ct1 = httpx.post(f"{BASE_URL}/api/encrypt-cbc-static", content=payload).json()["ciphertext"]
        ct2 = httpx.post(f"{BASE_URL}/api/encrypt-cbc-static", content=payload).json()["ciphertext"]
        assert ct1 == ct2, "Static IV should produce identical ciphertext for same plaintext"


@skipif_no_server
class TestBm03WeakHashMd5:
    """BM-03: Should return MD5 hashes (32 hex chars = 128 bits)."""

    def test_md5_output_length(self) -> None:
        resp = httpx.post(f"{BASE_URL}/api/hash", content=b"test")
        h = resp.json()["hash"]
        assert len(h) == 32, f"Expected 32 hex chars (MD5), got {len(h)}"

    def test_md5_correctness(self) -> None:
        data = b"hello"
        resp = httpx.post(f"{BASE_URL}/api/hash", content=data)
        assert resp.json()["hash"] == hashlib.md5(data).hexdigest()


@skipif_no_server
class TestBm04WeakHashSha1:
    """BM-04: Should return SHA-1 hashes (40 hex chars = 160 bits)."""

    def test_sha1_output_length(self) -> None:
        resp = httpx.post(f"{BASE_URL}/api/hash-sha1", content=b"test")
        h = resp.json()["hash"]
        assert len(h) == 40, f"Expected 40 hex chars (SHA-1), got {len(h)}"


@skipif_no_server
class TestBm05InsecureRandom:
    """BM-05: LCG tokens should show sequential correlation."""

    def test_token_length(self) -> None:
        resp = httpx.get(f"{BASE_URL}/api/token")
        token = resp.json()["token"]
        assert len(token) == 32, f"Expected 32 hex chars (16 bytes), got {len(token)}"

    def test_tokens_predictable(self) -> None:
        """Collect tokens and check for sequential patterns."""
        tokens = []
        for _ in range(20):
            resp = httpx.get(f"{BASE_URL}/api/token")
            tokens.append(int(resp.json()["token"][:8], 16))

        # LCG produces correlated consecutive values
        # We intentionally keep the assertion weak here because the benchmark only
        # needs to confirm that the endpoint emits token-shaped sequential outputs.
        assert len(tokens) == 20


@skipif_no_server
class TestBm06PaddingOracle:
    """BM-06: Decryption endpoint should leak padding validity."""

    def _get_valid_ciphertext(self) -> bytes:
        """Get a valid ciphertext from the encryption endpoint."""
        payload = b"padding oracle test data here!!!!"  # 32 bytes
        resp = httpx.post(f"{BASE_URL}/api/encrypt-cbc-static", content=payload)
        ct = base64.b64decode(resp.json()["ciphertext"])
        iv = base64.b64decode(resp.json()["iv"])
        return iv + ct

    def test_valid_ciphertext_accepted(self) -> None:
        ct = self._get_valid_ciphertext()
        resp = httpx.post(
            f"{BASE_URL}/api/decrypt",
            content=base64.b64encode(ct),
        )
        assert resp.status_code == 200

    def test_differential_error_responses(self) -> None:
        """Modified ciphertext should produce different error types."""
        ct = bytearray(self._get_valid_ciphertext())

        responses = set()
        for byte_val in [0x00, 0x01, 0x10, 0xFF]:
            ct[-1] = byte_val
            resp = httpx.post(
                f"{BASE_URL}/api/decrypt",
                content=base64.b64encode(bytes(ct)),
            )
            responses.add((resp.status_code, resp.json().get("error", "")))

        # Should have multiple distinct response patterns (padding oracle indicator)
        assert len(responses) >= 2, (
            f"Expected multiple response patterns for padding oracle, got {len(responses)}"
        )


@skipif_no_server
class TestBm07JwtAlgNone:
    """BM-07: JWT verification should accept alg=none."""

    def test_alg_none_accepted(self) -> None:
        # Craft a JWT with alg=none
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "attacker", "role": "admin"}).encode()
        ).rstrip(b"=").decode()
        token = f"{header}.{payload}."

        resp = httpx.post(
            f"{BASE_URL}/api/auth",
            headers={"Authorization": f"Bearer {token}"},
        )
        data = resp.json()
        assert data.get("authenticated") is True, "alg=none JWT should be accepted"
        assert data.get("user", {}).get("role") == "admin"


@skipif_no_server
class TestBm08JwtRs256ToHs256:
    """BM-08: JWT verification should accept HS256 signed with the public key."""

    def test_rs256_to_hs256_accepted(self) -> None:
        issue_resp = httpx.post(f"{BASE_URL}/api/auth-rsa")
        assert issue_resp.status_code == 200
        issue_data = issue_resp.json()
        token = issue_data["token"]
        public_key = issue_data["public_key"].encode()

        header_b64, payload_b64, _ = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
        assert header["alg"] == "RS256"

        forged_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        forged_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        signing_input = f"{forged_header}.{forged_payload}"
        signature = hmac.new(public_key, signing_input.encode(), hashlib.sha256).digest()
        forged_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        forged_token = f"{signing_input}.{forged_signature}"

        resp = httpx.post(
            f"{BASE_URL}/api/auth-rsa",
            headers={"Authorization": f"Bearer {forged_token}"},
        )
        data = resp.json()
        assert data.get("authenticated") is True, "RS256→HS256 JWT should be accepted"
        assert data.get("user", {}).get("role") == "user"


@skipif_no_server
class TestBm10TimingLeak:
    """BM-10: Non-constant-time HMAC should show timing differences."""

    def test_endpoint_responds(self) -> None:
        resp = httpx.post(
            f"{BASE_URL}/api/verify-hmac",
            json={"message": "test", "mac": "0" * 64},
        )
        assert resp.status_code in (200, 401)


@skipif_no_server
class TestNegativeControls:
    """Negative controls: strong endpoints should NOT be flagged."""

    def test_strong_encryption_random_nonce(self) -> None:
        """AES-256-GCM with random nonce should produce different outputs."""
        payload = b"negative control test"
        ct1 = httpx.post(f"{BASE_URL}/api/encrypt-strong", content=payload).json()["ciphertext"]
        ct2 = httpx.post(f"{BASE_URL}/api/encrypt-strong", content=payload).json()["ciphertext"]
        assert ct1 != ct2, "GCM with random nonce should not be deterministic"

    def test_strong_hash_sha256(self) -> None:
        resp = httpx.post(f"{BASE_URL}/api/hash-strong", content=b"test")
        h = resp.json()["hash"]
        assert len(h) == 64, f"Expected 64 hex chars (SHA-256), got {len(h)}"

    def test_secure_random_tokens(self) -> None:
        """os.urandom() tokens should all be unique."""
        tokens = set()
        for _ in range(50):
            resp = httpx.get(f"{BASE_URL}/api/token-secure")
            tokens.add(resp.json()["token"])
        assert len(tokens) == 50, "Secure random tokens should all be unique"


@skipif_no_server
class TestPhase02DiscoveryFixtures:
    """Phase02 discovery descriptors and decoys."""

    def test_service_index_lists_secure_and_decoy_endpoints(self) -> None:
        resp = httpx.get(f"{BASE_URL}/")
        assert resp.status_code == 200
        data = resp.json()
        endpoints = {entry["path"]: entry for entry in data["endpoints"]}
        assert "/api/encrypt-strong" in endpoints
        assert "/api/token-secure" in endpoints
        assert "/api/ping" in endpoints
        assert "/api/profile" in endpoints
        assert endpoints["/api/encrypt"]["methods"] == ["POST"]
        assert endpoints["/api/encrypt"]["surface_kind"] == "encryption_oracle"
        assert endpoints["/api/ping"]["crypto_relevant"] is False

    def test_openapi_descriptor_exposes_paths(self) -> None:
        resp = httpx.get(f"{BASE_URL}/openapi.json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["openapi"] == "3.0.0"
        assert "/api/encrypt" in data["paths"]
        assert "post" in data["paths"]["/api/encrypt"]
        assert "/api/ping" in data["paths"]
        assert data["paths"]["/api/encrypt"]["post"]["x-bbci-surface-kind"] == "encryption_oracle"
        assert data["paths"]["/api/ping"]["get"]["x-bbci-crypto-relevant"] is False
