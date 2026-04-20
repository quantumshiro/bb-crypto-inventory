"""Deterministic Phase03 application-layer misuse classification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import time
from datetime import UTC, datetime
from importlib import metadata
from typing import Any

import httpx

from bbci.phase02 import Phase02Scanner, canonicalize_base_url, normalize_methods
from bbci.tools.randomness import run_randomness_tests

PHASE03_SCANNER_NAME = "bbci-phase03"
PHASE03_SCHEMA_VERSION = "phase03-report/v1"
PHASE03_IN_SCOPE_SURFACE_KINDS = {
    "encryption_oracle",
    "hash_oracle",
    "token_issuer",
    "jwt_auth_surface",
}
PHASE03_DEFAULT_TOKEN_SAMPLE_COUNT = 16
PHASE03_RECOMMENDED_MAX_ACTIONS = 56


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _scanner_version() -> str:
    try:
        return metadata.version("bb-crypto-inventory")
    except metadata.PackageNotFoundError:
        from bbci import __version__

        return __version__


def normalize_hash_algorithm(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"md5"}:
        return "MD5"
    if lowered in {"sha1", "sha-1"}:
        return "SHA-1"
    if lowered in {"sha256", "sha-256"}:
        return "SHA-256"
    return value


def normalize_jwt_variant(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"alg=none", "jwt-none", "none"}:
        return "JWT-none"
    if lowered in {"jwt-rs256-to-hs256", "rs256->hs256", "hs256-with-public-key"}:
        return "JWT-RS256-to-HS256"
    return value


def repeated_block_metadata(ciphertext: bytes, block_size: int = 16) -> dict[str, Any]:
    if block_size <= 0 or len(ciphertext) < block_size * 2:
        return {
            "block_size_bytes": block_size,
            "block_count": len(ciphertext) // block_size if block_size > 0 else 0,
            "repeated_block_count": 0,
            "repeated_block_indexes": [],
        }

    blocks = [
        ciphertext[index : index + block_size]
        for index in range(0, len(ciphertext), block_size)
    ]
    block_indexes: dict[bytes, list[int]] = {}
    for index, block in enumerate(blocks):
        block_indexes.setdefault(block, []).append(index)

    repeated_indexes = [
        indexes for indexes in block_indexes.values() if len(indexes) > 1
    ]
    return {
        "block_size_bytes": block_size,
        "block_count": len(blocks),
        "repeated_block_count": len(repeated_indexes),
        "repeated_block_indexes": repeated_indexes,
    }


def identify_hash_algorithm(digest: str, payload: bytes) -> tuple[str | None, list[str]]:
    candidates = {
        "MD5": hashlib.md5(payload).hexdigest(),
        "SHA-1": hashlib.sha1(payload).hexdigest(),
        "SHA-256": hashlib.sha256(payload).hexdigest(),
    }
    matched = [algorithm for algorithm, hexdigest in candidates.items() if hexdigest == digest]
    return (matched[0] if matched else None, matched)


def flatten_token_words(tokens: list[str]) -> list[int]:
    words: list[int] = []
    for token in tokens:
        try:
            raw = bytes.fromhex(token)
        except ValueError:
            continue
        if len(raw) % 4 != 0:
            continue
        for index in range(0, len(raw), 4):
            words.append(int.from_bytes(raw[index : index + 4], "big"))
    return words


def detect_lcg_recurrence(words: list[int]) -> dict[str, Any]:
    if len(words) < 6:
        return {
            "lcg_detected": False,
            "lcg_recurrence_match_ratio": 0.0,
            "modulus_guess": None,
            "recovered_multiplier": None,
            "recovered_increment": None,
            "high_bit_clear_ratio": 0.0,
            "word_count": len(words),
        }

    best = {
        "lcg_recurrence_match_ratio": 0.0,
        "modulus_guess": None,
        "recovered_multiplier": None,
        "recovered_increment": None,
    }
    for modulus in (2**31, 2**32):
        for index in range(len(words) - 2):
            x0, x1, x2 = words[index], words[index + 1], words[index + 2]
            diff = (x1 - x0) % modulus
            if diff == 0 or math.gcd(diff, modulus) != 1:
                continue
            try:
                inverse = pow(diff, -1, modulus)
            except ValueError:
                continue
            multiplier = ((x2 - x1) % modulus) * inverse % modulus
            increment = (x1 - multiplier * x0) % modulus
            matches = sum(
                1
                for current, nxt in zip(words, words[1:], strict=False)
                if nxt % modulus == (multiplier * (current % modulus) + increment) % modulus
            )
            ratio = matches / max(len(words) - 1, 1)
            if ratio > best["lcg_recurrence_match_ratio"]:
                best = {
                    "lcg_recurrence_match_ratio": round(ratio, 4),
                    "modulus_guess": modulus,
                    "recovered_multiplier": multiplier,
                    "recovered_increment": increment,
                }

    high_bit_clear_ratio = round(
        sum(1 for word in words if word < 2**31) / len(words),
        4,
    )
    lcg_detected = (
        best["modulus_guess"] == 2**31
        and best["lcg_recurrence_match_ratio"] >= 0.95
        and high_bit_clear_ratio >= 0.95
    )
    return {
        "lcg_detected": lcg_detected,
        "lcg_recurrence_match_ratio": best["lcg_recurrence_match_ratio"],
        "modulus_guess": best["modulus_guess"],
        "recovered_multiplier": best["recovered_multiplier"],
        "recovered_increment": best["recovered_increment"],
        "high_bit_clear_ratio": high_bit_clear_ratio,
        "word_count": len(words),
    }


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def decode_jwt_segments(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    header_b64, payload_b64, *_ = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))
    return header, payload


def make_unsigned_jwt(payload: dict[str, Any]) -> str:
    header = {"alg": "none", "typ": "JWT"}
    header_segment = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_segment}.{payload_segment}."


def make_hs256_jwt(payload: dict[str, Any], secret: bytes) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}."
        f"{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}"
    )
    signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def _classification_id(endpoint_url: str, category: str, algorithm: str) -> str:
    digest = hashlib.sha1(f"{endpoint_url}:{category}:{algorithm}".encode()).hexdigest()
    return f"PHASE03-{digest[:10].upper()}"


def _severity_for(category: str, algorithm: str) -> str:
    if category == "JWTAlgConfusion":
        return "critical"
    if category in {"ECBMode", "StaticIV", "InsecureRandom"}:
        return "high"
    if category == "WeakHash" and algorithm == "SHA-1":
        return "medium"
    if category == "WeakHash":
        return "high"
    return "medium"


def _channel_for(category: str) -> str:
    if category in {"ECBMode", "StaticIV"}:
        return "CH2:CIPHERTEXT_STATS"
    if category == "InsecureRandom":
        return "CH6:RANDOMNESS"
    return "CH5:HASH_SIGNATURE"


def _decode_ciphertext_field(data: dict[str, Any]) -> bytes | None:
    ciphertext = data.get("ciphertext")
    if not isinstance(ciphertext, str):
        return None
    try:
        return base64.b64decode(ciphertext)
    except Exception:
        return None


class Phase03Scanner:
    """Deterministic phase03 classifier for a single application base URL."""

    def __init__(
        self, timeout: int = 10, token_sample_count: int = PHASE03_DEFAULT_TOKEN_SAMPLE_COUNT
    ) -> None:
        self.timeout = timeout
        self.token_sample_count = token_sample_count

    async def scan_target(self, base_url: str) -> dict[str, Any]:
        canonical_base_url = canonicalize_base_url(base_url)
        started_at = _utcnow()
        started_monotonic = time.monotonic()

        phase02_report = await Phase02Scanner(timeout=self.timeout).scan_target(base_url)
        observations = list(phase02_report.get("observations", []))
        discoveries = list(phase02_report.get("discoveries", []))
        in_scope_discoveries = [
            discovery
            for discovery in discoveries
            if discovery.get("surface_kind") in PHASE03_IN_SCOPE_SURFACE_KINDS
        ]
        out_of_scope_discoveries = [
            discovery
            for discovery in discoveries
            if discovery.get("surface_kind") not in PHASE03_IN_SCOPE_SURFACE_KINDS
        ]

        request_accounting = {
            "total_actions": phase02_report.get("request_accounting", {}).get("total_actions", 0),
            "discovery_actions": phase02_report.get("request_accounting", {}).get(
                "total_actions", 0
            ),
            "probe_actions": 0,
            "token_fetches": 0,
            "redirect_hops_followed": phase02_report.get("request_accounting", {}).get(
                "redirect_hops_followed", 0
            ),
            "budget_compliant": True,
        }
        classifications: list[dict[str, Any]] = []
        benchmark_verdicts: list[dict[str, Any]] = []
        time_to_first_classification_seconds: float | None = None
        inconclusive_count = 0

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=self.timeout,
        ) as client:
            for discovery in sorted(
                in_scope_discoveries,
                key=lambda item: (item.get("endpoint_url", ""), item.get("surface_kind", "")),
            ):
                classification = await self._classify_discovery(
                    client=client,
                    base_url=canonical_base_url,
                    discovery=discovery,
                    observations=observations,
                    request_accounting=request_accounting,
                )
                if classification is None:
                    continue
                if classification.get("_inconclusive"):
                    inconclusive_count += 1
                    continue
                classifications.append(classification)
                if time_to_first_classification_seconds is None:
                    time_to_first_classification_seconds = round(
                        max(time.monotonic() - started_monotonic, 0.001),
                        4,
                    )

        request_accounting["budget_compliant"] = (
            request_accounting["total_actions"] <= PHASE03_RECOMMENDED_MAX_ACTIONS
        )

        return {
            "schema_version": PHASE03_SCHEMA_VERSION,
            "suite_id": "phase03",
            "scanner": {
                "name": PHASE03_SCANNER_NAME,
                "version": _scanner_version(),
            },
            "execution": {
                "base_url": base_url,
                "canonical_base_url": canonical_base_url,
                "evaluation_mode": "base_url_classification",
                "started_at": started_at,
                "finished_at": _utcnow(),
            },
            "request_accounting": request_accounting,
            "observations": observations,
            "classifications": classifications,
            "benchmark_verdicts": benchmark_verdicts,
            "summary": {
                "candidate_count": len(discoveries),
                "in_scope_candidate_count": len(in_scope_discoveries),
                "out_of_scope_candidate_count": len(out_of_scope_discoveries),
                "classification_count": len(classifications),
                "skipped_surface_count": len(out_of_scope_discoveries),
                "inconclusive_count": inconclusive_count,
                "matched_classification_count": 0,
                "false_positive_classification_count": 0,
                "missed_expected_count": 0,
                "time_to_first_classification_seconds": time_to_first_classification_seconds,
            },
        }

    async def _classify_discovery(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        discovery: dict[str, Any],
        observations: list[dict[str, Any]],
        request_accounting: dict[str, Any],
    ) -> dict[str, Any] | None:
        surface_kind = discovery.get("surface_kind")
        if surface_kind == "encryption_oracle":
            return await self._probe_encryption_oracle(
                client, base_url, discovery, observations, request_accounting
            )
        if surface_kind == "hash_oracle":
            return await self._probe_hash_oracle(
                client, base_url, discovery, observations, request_accounting
            )
        if surface_kind == "token_issuer":
            return await self._probe_token_issuer(
                client, base_url, discovery, observations, request_accounting
            )
        if surface_kind == "jwt_auth_surface":
            return await self._probe_jwt_auth_surface(
                client, base_url, discovery, observations, request_accounting
            )
        return None

    def _add_observation(
        self,
        observations: list[dict[str, Any]],
        *,
        observation_id: str,
        observation_type: str,
        target_url: str,
        data: dict[str, Any],
    ) -> str:
        observations.append(
            {
                "id": observation_id,
                "type": observation_type,
                "target_url": target_url,
                "captured_at": _utcnow(),
                "data": data,
            }
        )
        return observation_id

    async def _request_json(
        self,
        *,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        request_accounting: dict[str, Any],
        observation_id: str,
        observation_type: str,
        observations: list[dict[str, Any]],
        token_fetch: bool = False,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> tuple[int | None, dict[str, Any] | None, str]:
        request_accounting["total_actions"] += 1
        request_accounting["probe_actions"] += 1
        if token_fetch:
            request_accounting["token_fetches"] += 1

        try:
            response = await client.request(
                method,
                url,
                headers=headers,
                content=content,
            )
        except httpx.HTTPError as exc:
            self._add_observation(
                observations,
                observation_id=observation_id,
                observation_type=observation_type,
                target_url=url,
                data={
                    "method": method,
                    "transport_error": str(exc),
                },
            )
            return None, None, observation_id

        try:
            payload = response.json()
        except ValueError:
            payload = None

        self._add_observation(
            observations,
            observation_id=observation_id,
            observation_type=observation_type,
            target_url=url,
            data={
                "method": method,
                "status_code": response.status_code,
                "response_keys": sorted(payload.keys()) if isinstance(payload, dict) else [],
                "payload_preview": payload if isinstance(payload, dict) else None,
                "content_length": len(response.content),
            },
        )
        return response.status_code, payload if isinstance(payload, dict) else None, observation_id

    def _build_classification(
        self,
        *,
        base_url: str,
        discovery: dict[str, Any],
        category: str,
        algorithm: str,
        confidence: float,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        endpoint_url = discovery["endpoint_url"]
        methods = normalize_methods(discovery.get("methods", []))
        return {
            "id": _classification_id(endpoint_url, category, algorithm),
            "endpoint_url": endpoint_url,
            "endpoint_path": discovery["endpoint_path"],
            "methods": methods,
            "surface_kind": discovery["surface_kind"],
            "category": category,
            "severity": _severity_for(category, algorithm),
            "algorithm": algorithm,
            "confidence": round(confidence, 2),
            "detection_channel": _channel_for(category),
            "evidence": {
                "base_url": base_url,
                "collected_via": PHASE03_SCANNER_NAME,
                "captured_at": _utcnow(),
                "source_discovery_id": discovery["id"],
                "endpoint_url": endpoint_url,
                "endpoint_path": discovery["endpoint_path"],
                "methods": methods,
                "surface_kind": discovery["surface_kind"],
                **evidence,
            },
        }

    async def _probe_encryption_oracle(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        discovery: dict[str, Any],
        observations: list[dict[str, Any]],
        request_accounting: dict[str, Any],
    ) -> dict[str, Any] | None:
        endpoint_url = discovery["endpoint_url"]
        discovery_observation_ids = list(discovery.get("evidence", {}).get("observation_ids", []))
        ecb_payload = b"A" * 64
        status, payload, observation_id = await self._request_json(
            client=client,
            method="POST",
            url=endpoint_url,
            request_accounting=request_accounting,
            observation_id=f"phase03:encrypt:ecb:{discovery['id']}",
            observation_type="encryption_probe",
            observations=observations,
            content=ecb_payload,
        )
        ciphertext = _decode_ciphertext_field(payload or {})
        if status is None or ciphertext is None:
            return None

        repeated = repeated_block_metadata(ciphertext)
        if repeated["repeated_block_count"] > 0:
            return self._build_classification(
                base_url=base_url,
                discovery=discovery,
                category="ECBMode",
                algorithm="AES-128-ECB",
                confidence=0.97,
                evidence={
                    "observation_ids": discovery_observation_ids + [observation_id],
                    "probe_strategy": "repeated_plaintext_blocks",
                    "ciphertext_encoding": "base64",
                    "ciphertext_length_bytes": len(ciphertext),
                    "block_size_bytes": repeated["block_size_bytes"],
                    "repeated_block_count": repeated["repeated_block_count"],
                    "repeated_block_indexes": repeated["repeated_block_indexes"],
                    "algorithm_hint": payload.get("algorithm"),
                },
            )

        static_payload = b"phase03-static-iv-probe"
        probe_ids: list[str] = []
        ciphertexts: list[bytes] = []
        ivs: list[str | None] = []
        for attempt in range(2):
            _, repeat_payload, repeat_observation_id = await self._request_json(
                client=client,
                method="POST",
                url=endpoint_url,
                request_accounting=request_accounting,
                observation_id=f"phase03:encrypt:repeat:{discovery['id']}:{attempt}",
                observation_type="encryption_probe",
                observations=observations,
                content=static_payload,
            )
            probe_ids.append(repeat_observation_id)
            repeat_ciphertext = _decode_ciphertext_field(repeat_payload or {})
            if repeat_ciphertext is None:
                return None
            ciphertexts.append(repeat_ciphertext)
            iv_value = repeat_payload.get("iv") if isinstance(repeat_payload, dict) else None
            ivs.append(iv_value if isinstance(iv_value, str) else None)

        ciphertexts_equal = len(set(ciphertexts)) == 1
        exposed_ivs = [iv for iv in ivs if iv is not None]
        ivs_equal = bool(exposed_ivs) and len(set(exposed_ivs)) == 1
        if ciphertexts_equal and ivs_equal:
            return self._build_classification(
                base_url=base_url,
                discovery=discovery,
                category="StaticIV",
                algorithm="AES-128-CBC",
                confidence=0.96,
                evidence={
                    "observation_ids": discovery_observation_ids + probe_ids,
                    "probe_strategy": "same_plaintext_repeat",
                    "ciphertext_encoding": "base64",
                    "repeated_request_count": 2,
                    "ciphertexts_equal": True,
                    "ivs_equal": True,
                    "returned_ivs": exposed_ivs,
                    "algorithm_hint": payload.get("algorithm"),
                },
            )
        return None

    async def _probe_hash_oracle(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        discovery: dict[str, Any],
        observations: list[dict[str, Any]],
        request_accounting: dict[str, Any],
    ) -> dict[str, Any] | None:
        endpoint_url = discovery["endpoint_url"]
        discovery_observation_ids = list(discovery.get("evidence", {}).get("observation_ids", []))
        probe_payload = b"phase03-hash-probe"
        _, payload, observation_id = await self._request_json(
            client=client,
            method="POST",
            url=endpoint_url,
            request_accounting=request_accounting,
            observation_id=f"phase03:hash:{discovery['id']}",
            observation_type="hash_probe",
            observations=observations,
            content=probe_payload,
        )
        if not isinstance(payload, dict):
            return None
        digest = payload.get("hash")
        if not isinstance(digest, str):
            return None
        algorithm, candidates = identify_hash_algorithm(digest, probe_payload)
        if algorithm not in {"MD5", "SHA-1"}:
            return None
        confidence = 0.96 if algorithm == "MD5" else 0.94
        return self._build_classification(
            base_url=base_url,
            discovery=discovery,
            category="WeakHash",
            algorithm=algorithm,
            confidence=confidence,
            evidence={
                "observation_ids": discovery_observation_ids + [observation_id],
                "probe_strategy": "known_input_digest_match",
                "digest_encoding": "hex",
                "digest_length_chars": len(digest),
                "exact_match_algorithm": algorithm,
                "candidate_algorithms": candidates,
            },
        )

    async def _probe_token_issuer(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        discovery: dict[str, Any],
        observations: list[dict[str, Any]],
        request_accounting: dict[str, Any],
    ) -> dict[str, Any] | None:
        endpoint_url = discovery["endpoint_url"]
        discovery_observation_ids = list(discovery.get("evidence", {}).get("observation_ids", []))
        tokens: list[str] = []
        for index in range(self.token_sample_count):
            _, payload, _ = await self._request_json(
                client=client,
                method="GET",
                url=endpoint_url,
                request_accounting=request_accounting,
                observation_id=f"phase03:token:{discovery['id']}:{index}",
                observation_type="token_fetch",
                observations=[],
                token_fetch=True,
            )
            if not isinstance(payload, dict):
                continue
            token = payload.get("token")
            if isinstance(token, str):
                tokens.append(token)

        observation_id = self._add_observation(
            observations,
            observation_id=f"phase03:token-summary:{discovery['id']}",
            observation_type="token_analysis",
            target_url=endpoint_url,
            data={
                "sample_count": len(tokens),
                "token_preview": tokens[:5],
            },
        )
        if not tokens:
            return None

        words = flatten_token_words(tokens)
        lcg_analysis = detect_lcg_recurrence(words)
        randomness_report = run_randomness_tests(tokens, max_tier=2, early_stop=False).to_dict()
        if not lcg_analysis["lcg_detected"]:
            return None

        confidence = 0.98 if lcg_analysis["lcg_recurrence_match_ratio"] >= 0.99 else 0.94
        return self._build_classification(
            base_url=base_url,
            discovery=discovery,
            category="InsecureRandom",
            algorithm="LCG",
            confidence=confidence,
            evidence={
                "observation_ids": discovery_observation_ids + [observation_id],
                "probe_strategy": "token_sampling_and_lcg_recovery",
                "sample_count": len(tokens),
                "token_field": "token",
                "lcg_detected": lcg_analysis["lcg_detected"],
                "lcg_recurrence_match_ratio": lcg_analysis["lcg_recurrence_match_ratio"],
                "modulus_guess": lcg_analysis["modulus_guess"],
                "recovered_multiplier": lcg_analysis["recovered_multiplier"],
                "recovered_increment": lcg_analysis["recovered_increment"],
                "high_bit_clear_ratio": lcg_analysis["high_bit_clear_ratio"],
                "randomness_summary": {
                    "overall_pass": randomness_report["overall_pass"],
                    "tier_reached": randomness_report["tier_reached"],
                    "failed_tests": randomness_report["failed_tests"],
                },
            },
        )

    async def _probe_jwt_auth_surface(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        discovery: dict[str, Any],
        observations: list[dict[str, Any]],
        request_accounting: dict[str, Any],
    ) -> dict[str, Any] | None:
        endpoint_url = discovery["endpoint_url"]
        discovery_observation_ids = list(discovery.get("evidence", {}).get("observation_ids", []))
        status, issue_payload, issue_observation_id = await self._request_json(
            client=client,
            method="POST",
            url=endpoint_url,
            request_accounting=request_accounting,
            observation_id=f"phase03:jwt:issue:{discovery['id']}",
            observation_type="jwt_issue",
            observations=observations,
        )
        if status is None or not isinstance(issue_payload, dict):
            return None
        token = issue_payload.get("token")
        if not isinstance(token, str):
            return None

        try:
            issued_header, issued_payload = decode_jwt_segments(token)
        except Exception:
            return None
        issued_algorithm = str(issued_header.get("alg", "unknown"))
        public_key = issue_payload.get("public_key")
        if isinstance(public_key, str):
            crafted_token = make_hs256_jwt(issued_payload, public_key.encode())
            exploit_variant = "JWT-RS256-to-HS256"
        else:
            crafted_token = make_unsigned_jwt(issued_payload)
            exploit_variant = "JWT-none"

        validation_status, validation_payload, validation_observation_id = await self._request_json(
            client=client,
            method="POST",
            url=endpoint_url,
            request_accounting=request_accounting,
            observation_id=f"phase03:jwt:validate:{discovery['id']}",
            observation_type="jwt_validation",
            observations=observations,
            headers={"Authorization": f"Bearer {crafted_token}"},
        )
        authenticated = bool(validation_payload and validation_payload.get("authenticated"))
        if not authenticated or validation_status is None:
            return None

        return self._build_classification(
            base_url=base_url,
            discovery=discovery,
            category="JWTAlgConfusion",
            algorithm=exploit_variant,
            confidence=0.98 if exploit_variant == "JWT-none" else 0.94,
            evidence={
                "observation_ids": discovery_observation_ids
                + [issue_observation_id, validation_observation_id],
                "probe_strategy": "jwt_issue_then_exploit",
                "issued_token_header_alg": issued_algorithm,
                "exploit_variant": exploit_variant,
                "exploit_response_authenticated": authenticated,
                "response_status_code": validation_status,
                "payload_keys": sorted(issued_payload.keys()),
                "public_key_present": isinstance(public_key, str),
            },
        )
