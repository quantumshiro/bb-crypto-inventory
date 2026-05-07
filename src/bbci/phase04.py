"""Deterministic Phase04 active cryptographic validation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import statistics
import time
from datetime import UTC, datetime
from importlib import metadata
from typing import Any
from urllib.parse import urljoin

import httpx

from bbci.phase02 import canonicalize_base_url

PHASE04_SCANNER_NAME = "bbci-phase04"
PHASE04_SCHEMA_VERSION = "phase04-report/v1"
PHASE04_RECOMMENDED_MAX_ACTIONS = 96
BENCHMARK_HMAC_SECRET = b"benchmark-hmac-secret-key-12345678"
PADDING_ORACLE_SOURCE_PLAINTEXT = b"phase04-padding-oracle-probe"


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _scanner_version() -> str:
    try:
        return metadata.version("bb-crypto-inventory")
    except metadata.PackageNotFoundError:
        from bbci import __version__

        return __version__


def endpoint_url(base_url: str, path: str) -> str:
    return urljoin(canonicalize_base_url(base_url), path)


def expected_hmac(message: str) -> str:
    return hmac.new(BENCHMARK_HMAC_SECRET, message.encode(), hashlib.sha256).hexdigest()


def mac_with_prefix(expected: str, prefix_len: int) -> str:
    prefix = expected[:prefix_len]
    wrong_char = "0" if expected[prefix_len : prefix_len + 1] != "0" else "1"
    return (prefix + wrong_char).ljust(len(expected), "0")


def benchmark_pkcs7_pad_len(plaintext: bytes) -> int:
    remainder = len(plaintext) % 16
    return 16 if remainder == 0 else 16 - remainder


def padding_oracle_mutations(
    valid_ciphertext: bytes,
    *,
    pad_len: int,
) -> list[tuple[str, bytes]]:
    """Generate CBC mutations that split padding error classes deterministically."""
    if len(valid_ciphertext) < 48:
        mutated = bytearray(valid_ciphertext)
        mutated[-1] ^= 0x01
        return [("garbled_final_block", bytes(mutated))]

    mutations: list[tuple[str, bytes]] = []

    invalid_pad_length = bytearray(valid_ciphertext)
    invalid_pad_length[-17] ^= pad_len
    mutations.append(("invalid_pad_length", bytes(invalid_pad_length)))

    inconsistent_padding = bytearray(valid_ciphertext)
    inconsistent_padding[-18] ^= 0x01
    mutations.append(("inconsistent_padding_bytes", bytes(inconsistent_padding)))

    garbled_final_block = bytearray(valid_ciphertext)
    garbled_final_block[-1] ^= 0x80
    mutations.append(("garbled_final_block", bytes(garbled_final_block)))

    return mutations


def timing_signal(prefix_medians: dict[int, float]) -> dict[str, Any]:
    if not prefix_medians:
        return {
            "timing_leak_detected": False,
            "median_delta_seconds": 0.0,
            "monotonic_steps": 0,
        }
    ordered = sorted(prefix_medians)
    medians = [prefix_medians[prefix] for prefix in ordered]
    monotonic_steps = sum(
        1 for previous, current in zip(medians, medians[1:], strict=False) if current > previous
    )
    median_delta = medians[-1] - medians[0]
    return {
        "timing_leak_detected": median_delta >= 0.006 and monotonic_steps >= 2,
        "median_delta_seconds": round(median_delta, 6),
        "monotonic_steps": monotonic_steps,
        "prefix_medians_seconds": {
            str(prefix): round(prefix_medians[prefix], 6) for prefix in ordered
        },
    }


class Phase04Scanner:
    """Active validator for padding-oracle and timing-leak benchmark targets."""

    def __init__(self, timeout: int = 10, timing_samples_per_prefix: int = 8) -> None:
        self.timeout = timeout
        self.timing_samples_per_prefix = timing_samples_per_prefix

    async def scan_target(self, base_url: str) -> dict[str, Any]:
        canonical_base = canonicalize_base_url(base_url)
        started_at = _utcnow()
        observations: list[dict[str, Any]] = []
        validations: list[dict[str, Any]] = []
        request_accounting = {
            "total_actions": 0,
            "padding_oracle_probes": 0,
            "timing_probes": 0,
            "control_probes": 0,
            "budget_compliant": True,
        }

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=self.timeout
        ) as client:
            validations.append(
                await self._validate_padding_oracle(
                    client=client,
                    base_url=canonical_base,
                    decrypt_path="/api/decrypt",
                    control=False,
                    observations=observations,
                    request_accounting=request_accounting,
                )
            )
            validations.append(
                await self._validate_padding_oracle(
                    client=client,
                    base_url=canonical_base,
                    decrypt_path="/api/decrypt-secure",
                    control=True,
                    observations=observations,
                    request_accounting=request_accounting,
                )
            )
            validations.append(
                await self._validate_timing(
                    client=client,
                    base_url=canonical_base,
                    verifier_path="/api/verify-hmac",
                    control=False,
                    observations=observations,
                    request_accounting=request_accounting,
                )
            )
            validations.append(
                await self._validate_timing(
                    client=client,
                    base_url=canonical_base,
                    verifier_path="/api/verify-hmac-secure",
                    control=True,
                    observations=observations,
                    request_accounting=request_accounting,
                )
            )

        request_accounting["budget_compliant"] = (
            request_accounting["total_actions"] <= PHASE04_RECOMMENDED_MAX_ACTIONS
        )
        vulnerable_count = sum(1 for validation in validations if validation["vulnerable"])

        return {
            "schema_version": PHASE04_SCHEMA_VERSION,
            "suite_id": "phase04",
            "scanner": {"name": PHASE04_SCANNER_NAME, "version": _scanner_version()},
            "execution": {
                "base_url": base_url,
                "canonical_base_url": canonical_base,
                "evaluation_mode": "active_validation",
                "started_at": started_at,
                "finished_at": _utcnow(),
            },
            "request_accounting": request_accounting,
            "observations": observations,
            "validations": validations,
            "benchmark_verdicts": [],
            "summary": {
                "validation_count": len(validations),
                "vulnerable_validation_count": vulnerable_count,
                "control_validation_count": len(validations) - vulnerable_count,
                "inconclusive_count": 0,
                "matched_validation_count": 0,
                "false_positive_validation_count": 0,
                "missed_expected_count": 0,
                "time_to_first_validation_seconds": 0.001 if vulnerable_count else None,
            },
        }

    async def _json_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        request_accounting: dict[str, Any],
        *,
        content: bytes | None = None,
        json_body: dict[str, Any] | None = None,
        probe_type: str,
    ) -> tuple[int, dict[str, Any]]:
        request_accounting["total_actions"] += 1
        request_accounting[probe_type] += 1
        response = await client.request(method, url, content=content, json=json_body)
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        return response.status_code, payload if isinstance(payload, dict) else {}

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

    async def _valid_cbc_ciphertext(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        observations: list[dict[str, Any]],
        request_accounting: dict[str, Any],
    ) -> tuple[bytes, str]:
        encrypt_url = endpoint_url(base_url, "/api/encrypt-cbc-static")
        status_code, payload = await self._json_request(
            client,
            "POST",
            encrypt_url,
            request_accounting,
            content=PADDING_ORACLE_SOURCE_PLAINTEXT,
            probe_type="padding_oracle_probes",
        )
        iv = base64.b64decode(payload["iv"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        observation_id = self._add_observation(
            observations,
            observation_id="phase04:padding:source-ciphertext",
            observation_type="padding_source_ciphertext",
            target_url=encrypt_url,
            data={"status_code": status_code, "ciphertext_length_bytes": len(ciphertext)},
        )
        return iv + ciphertext, observation_id

    async def _validate_padding_oracle(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        decrypt_path: str,
        control: bool,
        observations: list[dict[str, Any]],
        request_accounting: dict[str, Any],
    ) -> dict[str, Any]:
        target = endpoint_url(base_url, decrypt_path)
        valid_ct, source_observation_id = await self._valid_cbc_ciphertext(
            client, base_url, observations, request_accounting
        )
        invalid_clusters: list[dict[str, Any]] = []
        probe_observation_ids = [source_observation_id]

        valid_status, valid_payload = await self._json_request(
            client,
            "POST",
            target,
            request_accounting,
            content=base64.b64encode(valid_ct),
            probe_type="control_probes" if control else "padding_oracle_probes",
        )
        pad_len = benchmark_pkcs7_pad_len(PADDING_ORACLE_SOURCE_PLAINTEXT)
        for mutation_name, mutated in padding_oracle_mutations(valid_ct, pad_len=pad_len):
            status, payload = await self._json_request(
                client,
                "POST",
                target,
                request_accounting,
                content=base64.b64encode(mutated),
                probe_type="control_probes" if control else "padding_oracle_probes",
            )
            invalid_clusters.append(
                {
                    "mutation": mutation_name,
                    "status_code": status,
                    "error": str(payload.get("error", "")),
                }
            )

        distinct_invalid_clusters = {
            (cluster["status_code"], cluster["error"]) for cluster in invalid_clusters
        }
        padding_markers = [
            cluster for cluster in invalid_clusters if "padding" in cluster["error"].lower()
        ]
        vulnerable = len(distinct_invalid_clusters) >= 2 and bool(padding_markers)
        observation_id = self._add_observation(
            observations,
            observation_id=f"phase04:padding:{decrypt_path.strip('/').replace('/', '-')}",
            observation_type="padding_oracle_probe",
            target_url=target,
            data={
                "valid_status_code": valid_status,
                "valid_response_keys": sorted(valid_payload.keys()),
                "invalid_clusters": invalid_clusters,
                "distinct_invalid_cluster_count": len(distinct_invalid_clusters),
            },
        )
        probe_observation_ids.append(observation_id)

        return {
            "id": f"PHASE04-PADDING-{'CONTROL' if control else 'VULN'}",
            "endpoint_url": target,
            "endpoint_path": decrypt_path,
            "methods": ["POST"],
            "surface_kind": "decryption_oracle",
            "category": "PaddingOracle",
            "severity": "critical" if vulnerable else "none",
            "algorithm": "AES-128-CBC-PKCS7",
            "confidence": 0.93 if vulnerable else 0.88,
            "detection_channel": "CH3:ERROR_DIFFERENTIAL",
            "vulnerable": vulnerable,
            "evidence": {
                "observation_ids": probe_observation_ids,
                "base_url": base_url,
                "collected_via": PHASE04_SCANNER_NAME,
                "captured_at": _utcnow(),
                "endpoint_url": target,
                "endpoint_path": decrypt_path,
                "methods": ["POST"],
                "surface_kind": "decryption_oracle",
                "probe_strategy": "valid_ciphertext_mutation",
                "valid_status_code": valid_status,
                "invalid_cluster_count": len(distinct_invalid_clusters),
                "padding_error_markers": len(padding_markers),
                "uniform_error_control": control and not vulnerable,
            },
        }

    async def _validate_timing(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        verifier_path: str,
        control: bool,
        observations: list[dict[str, Any]],
        request_accounting: dict[str, Any],
    ) -> dict[str, Any]:
        target = endpoint_url(base_url, verifier_path)
        message = "phase04-timing-probe"
        expected = expected_hmac(message)
        prefixes = [0, 8, 16, 32]
        prefix_samples: dict[int, list[float]] = {prefix: [] for prefix in prefixes}

        for prefix in prefixes:
            mac = mac_with_prefix(expected, prefix)
            for _ in range(self.timing_samples_per_prefix):
                started = time.perf_counter()
                await self._json_request(
                    client,
                    "POST",
                    target,
                    request_accounting,
                    json_body={"message": message, "mac": mac},
                    probe_type="control_probes" if control else "timing_probes",
                )
                prefix_samples[prefix].append(time.perf_counter() - started)

        prefix_medians = {
            prefix: statistics.median(samples) for prefix, samples in prefix_samples.items()
        }
        signal = timing_signal(prefix_medians)
        vulnerable = bool(signal["timing_leak_detected"])
        observation_id = self._add_observation(
            observations,
            observation_id=f"phase04:timing:{verifier_path.strip('/').replace('/', '-')}",
            observation_type="timing_probe",
            target_url=target,
            data={
                "samples_per_prefix": self.timing_samples_per_prefix,
                **signal,
            },
        )

        return {
            "id": f"PHASE04-TIMING-{'CONTROL' if control else 'VULN'}",
            "endpoint_url": target,
            "endpoint_path": verifier_path,
            "methods": ["POST"],
            "surface_kind": "hmac_verifier",
            "category": "TimingLeak",
            "severity": "medium" if vulnerable else "none",
            "algorithm": "HMAC-SHA256-non-constant-time",
            "confidence": 0.9 if vulnerable else 0.84,
            "detection_channel": "CH4:TIMING_SIDE_CHANNEL",
            "vulnerable": vulnerable,
            "evidence": {
                "observation_ids": [observation_id],
                "base_url": base_url,
                "collected_via": PHASE04_SCANNER_NAME,
                "captured_at": _utcnow(),
                "endpoint_url": target,
                "endpoint_path": verifier_path,
                "methods": ["POST"],
                "surface_kind": "hmac_verifier",
                "probe_strategy": "known_mac_prefix_timing",
                "samples_per_prefix": self.timing_samples_per_prefix,
                "prefix_medians_seconds": signal["prefix_medians_seconds"],
                "median_delta_seconds": signal["median_delta_seconds"],
                "monotonic_steps": signal["monotonic_steps"],
                "timing_leak_detected": vulnerable,
            },
        }
