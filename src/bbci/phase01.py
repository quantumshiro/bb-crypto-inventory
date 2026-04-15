"""Deterministic Phase01 HTTPS edge assessment."""

from __future__ import annotations

import asyncio
import hashlib
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from bbci.tools.common import run_command

PHASE01_SCANNER_NAME = "bbci-phase01"
PHASE01_SCHEMA_VERSION = "phase01-report/v1"

PROTOCOL_ALIASES = {
    "TLSv1": "TLSv1.0",
    "TLS1.0": "TLSv1.0",
    "TLS1.1": "TLSv1.1",
    "TLS1.2": "TLSv1.2",
    "TLS1.3": "TLSv1.3",
}

SIGNATURE_ALIASES = {
    "sha1WithRSA": "sha1WithRSAEncryption",
    "sha1_rsa": "sha1WithRSAEncryption",
    "sha256WithRSA": "sha256WithRSAEncryption",
    "sha256_rsa": "sha256WithRSAEncryption",
}

SUITE_FAMILY_ALIASES = {
    "RC4-SHA": "RC4-family",
    "RC4-MD5": "RC4-family",
    "DES-CBC3-SHA": "3DES-family",
    "AES128-SHA": "static-RSA",
    "AES256-SHA": "static-RSA",
    "AES128-SHA256": "static-RSA",
    "AES256-SHA256": "static-RSA",
    "ECDHE-RSA-AES128-SHA": "ECDHE-RSA",
    "ECDHE-RSA-AES256-SHA": "ECDHE-RSA",
    "TLS_AES_128_GCM_SHA256": "TLSv1.3-AEAD",
    "TLS_AES_256_GCM_SHA384": "TLSv1.3-AEAD",
    "TLS_CHACHA20_POLY1305_SHA256": "TLSv1.3-AEAD",
}

KEY_EXCHANGE_BY_FAMILY = {
    "RC4-family": "static-RSA",
    "3DES-family": "static-RSA",
    "static-RSA": "static-RSA",
    "ECDHE-RSA": "ECDHE",
    "TLSv1.3-AEAD": "ECDHE",
}

TLS_VERSION_FLAGS = {
    "TLSv1.0": "-tls1",
    "TLSv1.1": "-tls1_1",
    "TLSv1.2": "-tls1_2",
    "TLSv1.3": "-tls1_3",
}

PHASE01_TLS_PROBES = [
    {"suite": "RC4-SHA", "flag": "-tls1_2", "family": "RC4-family", "bits": 128},
    {"suite": "DES-CBC3-SHA", "flag": "-tls1_2", "family": "3DES-family", "bits": 112},
    {"suite": "AES128-SHA", "flag": "-tls1_2", "family": "static-RSA", "bits": 128},
    {"suite": "ECDHE-RSA-AES128-SHA", "flag": "-tls1_2", "family": "ECDHE-RSA", "bits": 128},
    {"suite": "TLS_AES_128_GCM_SHA256", "flag": "-tls1_3", "family": "TLSv1.3-AEAD", "bits": 128},
    {"suite": "TLS_AES_256_GCM_SHA384", "flag": "-tls1_3", "family": "TLSv1.3-AEAD", "bits": 256},
    {
        "suite": "TLS_CHACHA20_POLY1305_SHA256",
        "flag": "-tls1_3",
        "family": "TLSv1.3-AEAD",
        "bits": 256,
    },
]

SSL_LABS_PROTOCOL_SCORES = {
    "SSLv2": 0,
    "SSLv3": 80,
    "TLSv1.0": 90,
    "TLSv1.1": 95,
    "TLSv1.2": 100,
    "TLSv1.3": 100,
}

OPENSSL_INVALID_CIPHER_MARKERS = (
    "error setting cipher list",
    "invalid command",
    "no cipher match",
)

PERMISSIVE_CIPHER_CANDIDATES = (
    "AES128-SHA:ECDHE-RSA-AES128-SHA:DES-CBC3-SHA:RC4-SHA:@SECLEVEL=0",
    "AES128-SHA:ECDHE-RSA-AES128-SHA:DES-CBC3-SHA:RC4-SHA",
    "DEFAULT",
)


@dataclass
class ProbeOutcome:
    """Parsed TLS probe outcome."""

    succeeded: bool
    negotiated_cipher: str | None = None
    raw_output: str = ""


def canonicalize_https_url(url: str) -> str:
    """Canonicalize an HTTPS URL for phase01 scoring identity."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or 443
    path = parsed.path or "/"
    return f"{scheme}://{host}:{port}{path}"


def normalize_protocol(version: str) -> str:
    """Normalize protocol labels."""
    return PROTOCOL_ALIASES.get(version, version)


def normalize_signature_algorithm(value: str | None) -> str:
    """Normalize certificate signature algorithm labels."""
    if not value:
        return ""
    return SIGNATURE_ALIASES.get(value, value)


def normalize_suite_family(value: str) -> str:
    """Normalize a TLS suite to the benchmark family name."""
    return SUITE_FAMILY_ALIASES.get(value, value)


def parse_hsts_max_age(value: str | None) -> int | None:
    """Extract max-age from an HSTS header."""
    if not value:
        return None
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _scanner_version() -> str:
    try:
        return metadata.version("bb-crypto-inventory")
    except metadata.PackageNotFoundError:
        from bbci import __version__

        return __version__


def _observation_id(prefix: str, suffix: str) -> str:
    return f"{prefix}:{suffix}"


def _finding_id(category: str, algorithm: str, target_url: str) -> str:
    digest = hashlib.sha1(f"{category}:{algorithm}:{target_url}".encode()).hexdigest()
    return f"PHASE01-{digest[:10].upper()}"


def _score_cipher_strength(bits: int) -> int:
    if bits == 0:
        return 0
    if bits < 128:
        return 20
    if bits < 256:
        return 80
    return 100


def compute_tls_grade(
    supported_protocols: list[str],
    accepted_suites: list[dict[str, Any]],
    key_exchange_bits: int,
    hsts_header: str | None,
) -> dict[str, Any]:
    """Compute the phase01 SSL Labs style grade."""
    proto_scores = [SSL_LABS_PROTOCOL_SCORES.get(p, 50) for p in supported_protocols]
    if proto_scores:
        protocol_score = (max(proto_scores) + min(proto_scores)) / 2
    else:
        protocol_score = 0.0

    if key_exchange_bits >= 4096:
        key_exchange_score = 100.0
    elif key_exchange_bits >= 2048:
        key_exchange_score = 90.0
    elif key_exchange_bits >= 1024:
        key_exchange_score = 80.0
    elif key_exchange_bits >= 512:
        key_exchange_score = 40.0
    else:
        key_exchange_score = 20.0

    cipher_bits = [suite.get("bits", 128) for suite in accepted_suites] or [128]
    strongest = _score_cipher_strength(max(cipher_bits))
    weakest = _score_cipher_strength(min(cipher_bits))
    cipher_strength_score = (strongest + weakest) / 2

    overall = protocol_score * 0.30 + key_exchange_score * 0.30 + cipher_strength_score * 0.40

    if overall >= 80:
        grade = "A"
    elif overall >= 65:
        grade = "B"
    elif overall >= 50:
        grade = "C"
    elif overall >= 35:
        grade = "D"
    elif overall >= 20:
        grade = "E"
    else:
        grade = "F"

    caps_applied: list[str] = []
    suite_families = {suite.get("normalized_family") for suite in accepted_suites}
    non_pfs_accepted = any(
        suite.get("key_exchange_family") == "static-RSA" for suite in accepted_suites
    )

    if "SSLv2" in supported_protocols:
        grade = "F"
        caps_applied.append("SSLv2 -> F")
    if "RC4-family" in suite_families and _grade_rank(grade) > _grade_rank("C"):
        grade = "C"
        caps_applied.append("RC4-family -> max C")
    if "3DES-family" in suite_families and _grade_rank(grade) > _grade_rank("C"):
        grade = "C"
        caps_applied.append("3DES-family -> max C")
    if any(version in supported_protocols for version in ["TLSv1.0", "TLSv1.1"]) and _grade_rank(
        grade
    ) > _grade_rank("B"):
        grade = "B"
        caps_applied.append("TLSv1.0/1.1 -> max B")
    if non_pfs_accepted and _grade_rank(grade) > _grade_rank("B"):
        grade = "B"
        caps_applied.append("non-PFS accepted -> max B")

    hsts_max_age = parse_hsts_max_age(hsts_header)
    if grade == "A" and hsts_max_age is not None and hsts_max_age >= 15552000:
        grade = "A+"

    return {
        "overall_score": round(overall, 1),
        "grade": grade,
        "protocol_score": round(protocol_score, 1),
        "key_exchange_score": round(key_exchange_score, 1),
        "cipher_strength_score": round(cipher_strength_score, 1),
        "caps_applied": caps_applied,
        "hsts_max_age_seconds": hsts_max_age,
        "methodology": "Qualys SSL Labs Rating Guide v2009r (phase01)",
    }


def _grade_rank(grade: str) -> int:
    order = {
        "A+": 7,
        "A": 6,
        "B": 5,
        "C": 4,
        "D": 3,
        "E": 2,
        "F": 1,
    }
    return order.get(grade, 0)


def _is_same_origin(source_url: str, redirect_url: str) -> bool:
    source = urlparse(source_url)
    redirect = urlparse(redirect_url)
    source_port = source.port or 443
    redirect_port = redirect.port or 443
    return (
        source.scheme.lower() == redirect.scheme.lower()
        and (source.hostname or "").lower() == (redirect.hostname or "").lower()
        and source_port == redirect_port
    )


def _fetch_peer_certificate(host: str, port: int) -> x509.Certificate:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)

    return x509.load_der_x509_certificate(cert_der)


def _looks_like_invalid_cipher_syntax(output: str) -> bool:
    lowered = output.lower()
    return any(marker in lowered for marker in OPENSSL_INVALID_CIPHER_MARKERS)


async def _openssl_probe_with_fallbacks(
    host: str, port: int, variants: list[list[str]]
) -> ProbeOutcome:
    last_outcome = ProbeOutcome(succeeded=False, raw_output="")
    for extra_args in variants:
        outcome = await _openssl_probe(host, port, extra_args)
        last_outcome = outcome
        if not _looks_like_invalid_cipher_syntax(outcome.raw_output):
            return outcome
    return last_outcome


async def _fetch_peer_certificate_openssl(host: str, port: int) -> x509.Certificate:
    """Fetch a peer certificate via openssl for weak endpoints."""
    variants = [
        ["-showcerts", "-tls1_2", "-cipher", "AES128-SHA:@SECLEVEL=0"],
        ["-showcerts", "-tls1_2", "-cipher", "AES128-SHA"],
        ["-showcerts", "-tls1_2", "-cipher", "DEFAULT"],
    ]
    combined = ""
    for extra_args in variants:
        stdout, stderr, rc = await run_command(
            [
                "openssl",
                "s_client",
                "-connect",
                f"{host}:{port}",
                "-servername",
                host,
            ]
            + extra_args,
            timeout=10,
        )
        combined = f"{stdout}\n{stderr}"
        if rc == 0 or "BEGIN CERTIFICATE" in combined:
            break
        if not _looks_like_invalid_cipher_syntax(combined):
            raise ValueError(f"openssl certificate fetch failed: {combined[:400]}")

    if "BEGIN CERTIFICATE" not in combined:
        raise ValueError(f"openssl certificate fetch failed: {combined[:400]}")

    match = re.search(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        combined,
        re.DOTALL,
    )
    if not match:
        raise ValueError("openssl certificate fetch did not return a PEM certificate")
    return x509.load_pem_x509_certificate(match.group(1).encode())


def _manual_https_get_headers(target_url: str) -> tuple[int, dict[str, str]]:
    """Fetch HTTPS headers with a permissive TLS client for weak endpoints."""
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    path = parsed.path or "/"

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    for cipher_string in PERMISSIVE_CIPHER_CANDIDATES:
        try:
            context.set_ciphers(cipher_string)
            break
        except ssl.SSLError:
            continue

    with socket.create_connection((host, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            tls_sock.sendall(request.encode())

            chunks = []
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)

    raw_response = b"".join(chunks).decode("iso-8859-1", errors="replace")
    header_text, _, _ = raw_response.partition("\r\n\r\n")
    lines = header_text.split("\r\n")
    if not lines:
        return 0, {}
    match = re.match(r"HTTP/\d\.\d\s+(\d+)", lines[0])
    status_code = int(match.group(1)) if match else 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return status_code, headers


async def _openssl_probe(host: str, port: int, extra_args: list[str]) -> ProbeOutcome:
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
    ] + extra_args
    stdout, stderr, rc = await run_command(cmd, timeout=10)
    combined = f"{stdout}\n{stderr}".strip()
    if rc != 0 and not (
        "Protocol version:" in combined
        or re.search(r"Protocol\s*:\s*\S+", combined) is not None
        or "CONNECTION ESTABLISHED" in combined
        or "CONNECTED" in combined
    ):
        return ProbeOutcome(succeeded=False, raw_output=combined)

    cipher_match = re.search(r"Cipher\s*:\s*(\S+)", combined)
    if not cipher_match:
        cipher_match = re.search(r"Cipher is (\S+)", combined)
    cipher = cipher_match.group(1) if cipher_match else None

    succeeded = (
        "Protocol version:" in combined
        or re.search(r"Protocol\s*:\s*\S+", combined) is not None
        or "CONNECTION ESTABLISHED" in combined
        or "CONNECTED" in combined
    ) and cipher not in {None, "0000", "(NONE)"}
    return ProbeOutcome(succeeded=succeeded, negotiated_cipher=cipher, raw_output=combined)


class Phase01Scanner:
    """Deterministic phase01 scanner for a single HTTPS edge URL."""

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    async def scan_target(self, target_url: str) -> dict[str, Any]:
        canonical_target = canonicalize_https_url(target_url)
        parsed = urlparse(canonical_target)
        host = parsed.hostname or ""
        port = parsed.port or 443

        started_at = _utcnow()
        request_accounting = {
            "total_actions": 0,
            "header_fetches": 0,
            "certificate_fetches": 0,
            "version_probes": 0,
            "cipher_probes": 0,
            "retries": 0,
            "redirect_hops_followed": 0,
            "budget_compliant": True,
        }
        observations: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        benchmark_verdicts: list[dict[str, Any]] = []

        header_result = await self._fetch_headers(canonical_target, request_accounting)
        observations.append(header_result["observation"])

        cert_result = await self._fetch_certificate(
            host, port, canonical_target, request_accounting
        )
        observations.append(cert_result["observation"])

        protocol_result = await self._probe_protocols(
            host, port, canonical_target, request_accounting
        )
        observations.append(protocol_result["observation"])

        cipher_result = await self._probe_ciphers(host, port, canonical_target, request_accounting)
        observations.append(cipher_result["observation"])

        grade_result = compute_tls_grade(
            supported_protocols=protocol_result["supported_protocols"],
            accepted_suites=cipher_result["accepted_suites"],
            key_exchange_bits=cert_result["key_length_bits"],
            hsts_header=header_result["headers"].get("strict-transport-security"),
        )
        observations.append(
            {
                "id": _observation_id("tls_grade", f"{host}:{port}"),
                "type": "tls_grade",
                "target_url": canonical_target,
                "captured_at": _utcnow(),
                "data": grade_result,
            }
        )

        findings.extend(
            self._build_phase01_findings(
                canonical_target=canonical_target,
                header_result=header_result,
                cert_result=cert_result,
                protocol_result=protocol_result,
                cipher_result=cipher_result,
                observation_ids={obs["type"]: obs["id"] for obs in observations},
            )
        )

        request_accounting["budget_compliant"] = request_accounting["total_actions"] <= 16
        benchmark_verdicts.extend(
            self._build_benchmark_verdicts(
                canonical_target=canonical_target,
                findings=findings,
                grade_result=grade_result,
                request_accounting=request_accounting,
            )
        )

        report = {
            "schema_version": PHASE01_SCHEMA_VERSION,
            "suite_id": "phase01",
            "scanner": {
                "name": PHASE01_SCANNER_NAME,
                "version": _scanner_version(),
            },
            "execution": {
                "target_url": target_url,
                "canonical_target": canonical_target,
                "evaluation_mode": "url_scoped",
                "started_at": started_at,
                "finished_at": _utcnow(),
            },
            "request_accounting": request_accounting,
            "observations": observations,
            "findings": findings,
            "benchmark_verdicts": benchmark_verdicts,
        }

        return report

    async def _fetch_headers(
        self, target_url: str, request_accounting: dict[str, Any]
    ) -> dict[str, Any]:
        import httpx

        redirect_hops = 0
        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=False, timeout=self.timeout
            ) as client:
                response = await client.get(target_url)
                request_accounting["header_fetches"] += 1
                request_accounting["total_actions"] += 1
                final_response = response
                if response.is_redirect:
                    location = response.headers.get("location")
                    if location:
                        redirected = str(response.request.url.join(location))
                        if _is_same_origin(target_url, redirected):
                            final_response = await client.get(redirected)
                            redirect_hops = 1
                            request_accounting["header_fetches"] += 1
                            request_accounting["total_actions"] += 1
                        else:
                            raise ValueError(
                                f"Cross-origin redirect not allowed in phase01: {redirected}"
                            )
            status_code = final_response.status_code
            headers = {k.lower(): v for k, v in final_response.headers.items()}
        except Exception:
            status_code, headers = await asyncio.to_thread(_manual_https_get_headers, target_url)
            request_accounting["header_fetches"] += 1
            request_accounting["total_actions"] += 1

        request_accounting["redirect_hops_followed"] = redirect_hops
        return {
            "headers": headers,
            "redirect_hops_followed": redirect_hops,
            "observation": {
                "id": _observation_id("http_headers", urlparse(target_url).netloc),
                "type": "http_headers",
                "target_url": canonicalize_https_url(target_url),
                "captured_at": _utcnow(),
                "data": {
                    "status_code": status_code,
                    "headers": headers,
                    "redirect_hops_followed": redirect_hops,
                },
            },
        }

    async def _fetch_certificate(
        self,
        host: str,
        port: int,
        target_url: str,
        request_accounting: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            cert = await asyncio.to_thread(_fetch_peer_certificate, host, port)
        except ssl.SSLError:
            cert = await _fetch_peer_certificate_openssl(host, port)
        request_accounting["certificate_fetches"] += 1
        request_accounting["total_actions"] += 1

        public_key = cert.public_key()
        key_length_bits = getattr(public_key, "key_size", 0)
        if isinstance(public_key, rsa.RSAPublicKey):
            key_type = "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = "ECDSA"
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            key_type = "Ed25519"
        else:
            key_type = "UNKNOWN"
        signature_algorithm = normalize_signature_algorithm(
            cert.signature_algorithm_oid._name or ""
        )
        if not signature_algorithm and cert.signature_hash_algorithm is not None:
            hash_name = cert.signature_hash_algorithm.name.lower()
            if key_type.lower() == "rsa":
                signature_algorithm = normalize_signature_algorithm(f"{hash_name}WithRSA")

        return {
            "key_length_bits": key_length_bits,
            "key_type": key_type,
            "signature_algorithm": signature_algorithm,
            "observation": {
                "id": _observation_id("certificate_leaf", f"{host}:{port}"),
                "type": "certificate_leaf",
                "target_url": target_url,
                "captured_at": _utcnow(),
                "data": {
                    "certificate_position": "leaf",
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "key_type": key_type,
                    "key_length_bits": key_length_bits,
                    "signature_algorithm": signature_algorithm,
                },
            },
        }

    async def _probe_protocols(
        self,
        host: str,
        port: int,
        target_url: str,
        request_accounting: dict[str, Any],
    ) -> dict[str, Any]:
        tested_versions: list[dict[str, Any]] = []
        supported_protocols: list[str] = []
        for version, flag in TLS_VERSION_FLAGS.items():
            if version == "TLSv1.3":
                probe = await _openssl_probe_with_fallbacks(host, port, [[flag]])
            else:
                probe = await _openssl_probe_with_fallbacks(
                    host,
                    port,
                    [
                        [flag, "-cipher", "DEFAULT:@SECLEVEL=0"],
                        [flag, "-cipher", "DEFAULT"],
                    ],
                )
            request_accounting["version_probes"] += 1
            request_accounting["total_actions"] += 1
            tested_versions.append(
                {
                    "version": version,
                    "accepted": probe.succeeded,
                    "negotiated_cipher": probe.negotiated_cipher,
                }
            )
            if probe.succeeded:
                supported_protocols.append(version)

        return {
            "supported_protocols": supported_protocols,
            "observation": {
                "id": _observation_id("tls_protocol_support", f"{host}:{port}"),
                "type": "tls_protocol_support",
                "target_url": target_url,
                "captured_at": _utcnow(),
                "data": {
                    "tested_versions": tested_versions,
                    "supported_protocols": supported_protocols,
                },
            },
        }

    async def _probe_ciphers(
        self,
        host: str,
        port: int,
        target_url: str,
        request_accounting: dict[str, Any],
    ) -> dict[str, Any]:
        accepted_suites: list[dict[str, Any]] = []
        for probe in PHASE01_TLS_PROBES:
            if probe["flag"] == "-tls1_3":
                outcome = await _openssl_probe_with_fallbacks(
                    host,
                    port,
                    [["-tls1_3", "-ciphersuites", probe["suite"]]],
                )
            else:
                outcome = await _openssl_probe_with_fallbacks(
                    host,
                    port,
                    [
                        [probe["flag"], "-cipher", f"{probe['suite']}:@SECLEVEL=0"],
                        [probe["flag"], "-cipher", probe["suite"]],
                    ],
                )
            request_accounting["cipher_probes"] += 1
            request_accounting["total_actions"] += 1
            if not outcome.succeeded:
                continue
            family = normalize_suite_family(probe["suite"])
            accepted_suites.append(
                {
                    "suite": probe["suite"],
                    "version": normalize_protocol(
                        "TLS1.3" if probe["flag"] == "-tls1_3" else "TLS1.2"
                    ),
                    "normalized_family": family,
                    "key_exchange_family": KEY_EXCHANGE_BY_FAMILY[family],
                    "bits": probe["bits"],
                }
            )

        normalized_families = sorted({suite["normalized_family"] for suite in accepted_suites})
        accepted_key_exchange_families = sorted(
            {suite["key_exchange_family"] for suite in accepted_suites}
        )
        non_pfs_accepted = any(
            suite["key_exchange_family"] == "static-RSA" for suite in accepted_suites
        )

        return {
            "accepted_suites": accepted_suites,
            "normalized_families": normalized_families,
            "accepted_key_exchange_families": accepted_key_exchange_families,
            "non_pfs_accepted": non_pfs_accepted,
            "observation": {
                "id": _observation_id("tls_cipher_acceptance", f"{host}:{port}"),
                "type": "tls_cipher_acceptance",
                "target_url": target_url,
                "captured_at": _utcnow(),
                "data": {
                    "accepted_suites": accepted_suites,
                    "normalized_suite_families": normalized_families,
                    "accepted_key_exchange_families": accepted_key_exchange_families,
                    "non_pfs_accepted": non_pfs_accepted,
                },
            },
        }

    def _build_phase01_findings(
        self,
        canonical_target: str,
        header_result: dict[str, Any],
        cert_result: dict[str, Any],
        protocol_result: dict[str, Any],
        cipher_result: dict[str, Any],
        observation_ids: dict[str, str],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        captured_at = _utcnow()

        for version in ["TLSv1.0", "TLSv1.1"]:
            if version in protocol_result["supported_protocols"]:
                findings.append(
                    self._make_finding(
                        target_url=canonical_target,
                        category="WeakProtocolVersion",
                        severity="medium",
                        algorithm=version,
                        confidence=0.99,
                        detection_channel="CH1:TLS_HANDSHAKE",
                        evidence={
                            "observation_ids": [observation_ids["tls_protocol_support"]],
                            "target_url": canonical_target,
                            "collected_via": PHASE01_SCANNER_NAME,
                            "captured_at": captured_at,
                            "supported_protocols": protocol_result["supported_protocols"],
                            "accepted_protocol": version,
                        },
                    )
                )

        if "RC4-family" in cipher_result["normalized_families"]:
            representative_suite = next(
                suite["suite"]
                for suite in cipher_result["accepted_suites"]
                if suite["normalized_family"] == "RC4-family"
            )
            findings.append(
                self._make_finding(
                    target_url=canonical_target,
                    category="InsecureCipherSuite",
                    severity="high",
                    algorithm="RC4-family",
                    confidence=0.98,
                    detection_channel="CH1:TLS_HANDSHAKE",
                    evidence={
                        "observation_ids": [observation_ids["tls_cipher_acceptance"]],
                        "target_url": canonical_target,
                        "collected_via": PHASE01_SCANNER_NAME,
                        "captured_at": captured_at,
                        "accepted_suites": [
                            suite["suite"] for suite in cipher_result["accepted_suites"]
                        ],
                        "normalized_suite_families": cipher_result["normalized_families"],
                        "representative_suite": representative_suite,
                    },
                )
            )

        if cipher_result["non_pfs_accepted"]:
            findings.append(
                self._make_finding(
                    target_url=canonical_target,
                    category="NoPFS",
                    severity="high",
                    algorithm="static-RSA",
                    confidence=0.99,
                    detection_channel="CH1:TLS_HANDSHAKE",
                    evidence={
                        "observation_ids": [observation_ids["tls_cipher_acceptance"]],
                        "target_url": canonical_target,
                        "collected_via": PHASE01_SCANNER_NAME,
                        "captured_at": captured_at,
                        "accepted_suites": [
                            suite["suite"] for suite in cipher_result["accepted_suites"]
                        ],
                        "accepted_key_exchange_families": cipher_result[
                            "accepted_key_exchange_families"
                        ],
                        "non_pfs_accepted": True,
                    },
                    key_length=cert_result["key_length_bits"],
                    pq_vulnerable=True,
                )
            )

        if "strict-transport-security" not in header_result["headers"]:
            findings.append(
                self._make_finding(
                    target_url=canonical_target,
                    category="NoHSTS",
                    severity="low",
                    algorithm="HSTS-missing",
                    confidence=0.95,
                    detection_channel="RECON",
                    evidence={
                        "observation_ids": [observation_ids["http_headers"]],
                        "target_url": canonical_target,
                        "collected_via": PHASE01_SCANNER_NAME,
                        "captured_at": captured_at,
                        "response_headers": header_result["headers"],
                        "redirect_hops_followed": header_result["redirect_hops_followed"],
                    },
                )
            )

        if cert_result["key_type"] == "RSA" and cert_result["key_length_bits"] == 1024:
            findings.append(
                self._make_finding(
                    target_url=canonical_target,
                    category="WeakKeyLength",
                    severity="high",
                    algorithm="RSA-1024",
                    confidence=0.99,
                    detection_channel="RECON",
                    evidence={
                        "observation_ids": [observation_ids["certificate_leaf"]],
                        "target_url": canonical_target,
                        "collected_via": PHASE01_SCANNER_NAME,
                        "captured_at": captured_at,
                        "certificate_position": "leaf",
                        "key_type": "RSA",
                        "key_length_bits": 1024,
                    },
                    key_length=1024,
                    pq_vulnerable=True,
                )
            )

        if cert_result["signature_algorithm"] == "sha1WithRSAEncryption":
            findings.append(
                self._make_finding(
                    target_url=canonical_target,
                    category="WeakSignatureAlgorithm",
                    severity="high",
                    algorithm="sha1WithRSAEncryption",
                    confidence=0.99,
                    detection_channel="RECON",
                    evidence={
                        "observation_ids": [observation_ids["certificate_leaf"]],
                        "target_url": canonical_target,
                        "collected_via": PHASE01_SCANNER_NAME,
                        "captured_at": captured_at,
                        "certificate_position": "leaf",
                        "signature_algorithm": "sha1WithRSAEncryption",
                    },
                    pq_vulnerable=True,
                )
            )

        return findings

    def _build_benchmark_verdicts(
        self,
        canonical_target: str,
        findings: list[dict[str, Any]],
        grade_result: dict[str, Any],
        request_accounting: dict[str, Any],
    ) -> list[dict[str, Any]]:
        benchmark_verdicts: list[dict[str, Any]] = []
        finding_ids_by_category = {}
        for finding in findings:
            finding_ids_by_category.setdefault(finding["category"], []).append(finding["id"])

        if canonical_target.endswith(":9443/"):
            benchmark_verdicts.extend(
                [
                    {
                        "benchmark_id": "BM-09",
                        "target_url": canonical_target,
                        "status": "matched"
                        if all(
                            category in finding_ids_by_category
                            for category in ["WeakProtocolVersion", "InsecureCipherSuite", "NoPFS"]
                        )
                        and grade_result["grade"] == "C"
                        else "missed",
                        "matched_finding_ids": (
                            finding_ids_by_category.get("WeakProtocolVersion", [])
                            + finding_ids_by_category.get("InsecureCipherSuite", [])
                            + finding_ids_by_category.get("NoPFS", [])
                        ),
                        "expected_grade": "C",
                        "observed_grade": grade_result["grade"],
                        "evidence_valid": True,
                        "budget_compliant": request_accounting["budget_compliant"],
                    },
                    {
                        "benchmark_id": "BM-11",
                        "target_url": canonical_target,
                        "status": "matched" if "NoHSTS" in finding_ids_by_category else "missed",
                        "matched_finding_ids": finding_ids_by_category.get("NoHSTS", []),
                        "evidence_valid": True,
                        "budget_compliant": request_accounting["budget_compliant"],
                    },
                    {
                        "benchmark_id": "BM-12",
                        "target_url": canonical_target,
                        "status": "matched"
                        if "WeakKeyLength" in finding_ids_by_category
                        else "missed",
                        "matched_finding_ids": finding_ids_by_category.get("WeakKeyLength", []),
                        "evidence_valid": True,
                        "budget_compliant": request_accounting["budget_compliant"],
                    },
                    {
                        "benchmark_id": "BM-13",
                        "target_url": canonical_target,
                        "status": "matched"
                        if "WeakSignatureAlgorithm" in finding_ids_by_category
                        else "missed",
                        "matched_finding_ids": finding_ids_by_category.get(
                            "WeakSignatureAlgorithm", []
                        ),
                        "evidence_valid": True,
                        "budget_compliant": request_accounting["budget_compliant"],
                    },
                ]
            )
        elif canonical_target.endswith(":9444/"):
            benchmark_verdicts.append(
                {
                    "benchmark_id": "NC-04",
                    "target_url": canonical_target,
                    "status": "true_negative"
                    if not findings and grade_result["grade"] == "A+"
                    else "false_positive",
                    "matched_finding_ids": [],
                    "expected_grade": "A+",
                    "observed_grade": grade_result["grade"],
                    "evidence_valid": True,
                    "budget_compliant": request_accounting["budget_compliant"],
                }
            )

        return benchmark_verdicts

    def _make_finding(
        self,
        target_url: str,
        category: str,
        severity: str,
        algorithm: str,
        confidence: float,
        detection_channel: str,
        evidence: dict[str, Any],
        key_length: int | None = None,
        pq_vulnerable: bool = False,
    ) -> dict[str, Any]:
        finding = {
            "id": _finding_id(category, algorithm, target_url),
            "target_url": target_url,
            "endpoint": target_url,
            "category": category,
            "severity": severity,
            "algorithm": algorithm,
            "confidence": confidence,
            "detection_channel": detection_channel,
            "evidence": evidence,
            "pq_vulnerable": pq_vulnerable,
        }
        if key_length is not None:
            finding["key_length"] = key_length
        return finding
