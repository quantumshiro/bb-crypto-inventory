"""Deterministic Phase05 operational robustness benchmark."""

from __future__ import annotations

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
from bbci.phase04 import BENCHMARK_HMAC_SECRET, mac_with_prefix, timing_signal

PHASE05_SCANNER_NAME = "bbci-phase05"
PHASE05_SCHEMA_VERSION = "phase05-report/v1"
PHASE05_RECOMMENDED_MAX_ACTIONS = 48


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


class Phase05Scanner:
    """Operational robustness checker for noisy and constrained benchmark surfaces."""

    def __init__(self, timeout: int = 10, timing_samples_per_prefix: int = 6) -> None:
        self.timeout = timeout
        self.timing_samples_per_prefix = timing_samples_per_prefix

    async def scan_target(self, base_url: str) -> dict[str, Any]:
        canonical_base = canonicalize_base_url(base_url)
        started_at = _utcnow()
        observations: list[dict[str, Any]] = []
        operational_results: list[dict[str, Any]] = []
        request_accounting = {
            "total_actions": 0,
            "rate_limit_probes": 0,
            "transient_probes": 0,
            "noise_probes": 0,
            "budget_compliant": True,
        }

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=self.timeout
        ) as client:
            operational_results.append(
                await self._check_rate_limit(
                    client,
                    canonical_base,
                    observations,
                    request_accounting,
                )
            )
            operational_results.append(
                await self._check_transient_recovery(
                    client, canonical_base, observations, request_accounting
                )
            )
            operational_results.append(
                await self._check_noisy_timing_control(
                    client, canonical_base, observations, request_accounting
                )
            )

        request_accounting["budget_compliant"] = (
            request_accounting["total_actions"] <= PHASE05_RECOMMENDED_MAX_ACTIONS
        )
        passed_count = sum(1 for result in operational_results if result["passed"])

        return {
            "schema_version": PHASE05_SCHEMA_VERSION,
            "suite_id": "phase05",
            "scanner": {"name": PHASE05_SCANNER_NAME, "version": _scanner_version()},
            "execution": {
                "base_url": base_url,
                "canonical_base_url": canonical_base,
                "evaluation_mode": "operational_robustness",
                "started_at": started_at,
                "finished_at": _utcnow(),
            },
            "request_accounting": request_accounting,
            "observations": observations,
            "operational_results": operational_results,
            "benchmark_verdicts": [],
            "summary": {
                "operational_result_count": len(operational_results),
                "passed_operational_count": passed_count,
                "failed_operational_count": len(operational_results) - passed_count,
                "inconclusive_count": 0,
                "matched_operational_count": 0,
                "missed_expected_count": 0,
            },
        }

    async def _json_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        request_accounting: dict[str, Any],
        *,
        counter_key: str,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        request_accounting["total_actions"] += 1
        request_accounting[counter_key] += 1
        response = await client.request(method, url, headers=headers, json=json_body)
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

    async def _check_rate_limit(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        observations: list[dict[str, Any]],
        request_accounting: dict[str, Any],
    ) -> dict[str, Any]:
        target = endpoint_url(base_url, "/api/rate-limit-token")
        statuses: list[int] = []
        for _ in range(5):
            status, _ = await self._json_request(
                client, "GET", target, request_accounting, counter_key="rate_limit_probes"
            )
            statuses.append(status)
            if status == 429:
                break
        passed = 429 in statuses and len(statuses) <= 5
        observation_id = self._add_observation(
            observations,
            observation_id="phase05:rate-limit",
            observation_type="rate_limit_probe",
            target_url=target,
            data={"statuses": statuses, "stopped_after_429": statuses[-1] == 429},
        )
        return {
            "id": "PHASE05-RATE-LIMIT",
            "target_id": "O-01",
            "endpoint_url": target,
            "endpoint_path": "/api/rate-limit-token",
            "operation": "rate_limit_handling",
            "status": "rate_limit_detected" if passed else "missed",
            "passed": passed,
            "confidence": 0.95 if passed else 0.4,
            "evidence": {
                "observation_ids": [observation_id],
                "base_url": base_url,
                "collected_via": PHASE05_SCANNER_NAME,
                "captured_at": _utcnow(),
                "status_codes": statuses,
                "saw_429": 429 in statuses,
                "stopped_after_429": statuses[-1] == 429,
            },
        }

    async def _check_transient_recovery(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        observations: list[dict[str, Any]],
        request_accounting: dict[str, Any],
    ) -> dict[str, Any]:
        target = endpoint_url(base_url, "/api/transient-hash")
        statuses: list[int] = []
        payloads: list[dict[str, Any]] = []
        for attempt in (1, 2):
            status, payload = await self._json_request(
                client,
                "GET",
                target,
                request_accounting,
                counter_key="transient_probes",
                headers={"X-BBCI-Attempt": str(attempt)},
            )
            statuses.append(status)
            payloads.append(payload)
        passed = statuses == [503, 200] and payloads[-1].get("recovered") is True
        observation_id = self._add_observation(
            observations,
            observation_id="phase05:transient-recovery",
            observation_type="transient_probe",
            target_url=target,
            data={"statuses": statuses, "final_keys": sorted(payloads[-1].keys())},
        )
        return {
            "id": "PHASE05-TRANSIENT",
            "target_id": "O-02",
            "endpoint_url": target,
            "endpoint_path": "/api/transient-hash",
            "operation": "transient_recovery",
            "status": "transient_recovered" if passed else "missed",
            "passed": passed,
            "confidence": 0.96 if passed else 0.4,
            "evidence": {
                "observation_ids": [observation_id],
                "base_url": base_url,
                "collected_via": PHASE05_SCANNER_NAME,
                "captured_at": _utcnow(),
                "status_codes": statuses,
                "retried_after_503": statuses[:1] == [503],
                "final_status_code": statuses[-1],
            },
        }

    async def _check_noisy_timing_control(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        observations: list[dict[str, Any]],
        request_accounting: dict[str, Any],
    ) -> dict[str, Any]:
        target = endpoint_url(base_url, "/api/verify-hmac-noisy")
        message = "phase05-noisy-timing-probe"
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
                    counter_key="noise_probes",
                    json_body={"message": message, "mac": mac},
                )
                prefix_samples[prefix].append(time.perf_counter() - started)
        prefix_medians = {
            prefix: statistics.median(samples) for prefix, samples in prefix_samples.items()
        }
        signal = timing_signal(prefix_medians)
        passed = not signal["timing_leak_detected"]
        observation_id = self._add_observation(
            observations,
            observation_id="phase05:noisy-timing-control",
            observation_type="noisy_timing_probe",
            target_url=target,
            data={
                "samples_per_prefix": self.timing_samples_per_prefix,
                **signal,
            },
        )
        return {
            "id": "PHASE05-NOISY-TIMING",
            "target_id": "O-03",
            "endpoint_url": target,
            "endpoint_path": "/api/verify-hmac-noisy",
            "operation": "noisy_secure_timing_suppression",
            "status": "no_timing_leak" if passed else "false_positive_timing_leak",
            "passed": passed,
            "confidence": 0.9 if passed else 0.3,
            "evidence": {
                "observation_ids": [observation_id],
                "base_url": base_url,
                "collected_via": PHASE05_SCANNER_NAME,
                "captured_at": _utcnow(),
                "samples_per_prefix": self.timing_samples_per_prefix,
                "prefix_medians_seconds": signal["prefix_medians_seconds"],
                "median_delta_seconds": signal["median_delta_seconds"],
                "timing_leak_detected": signal["timing_leak_detected"],
            },
        }
