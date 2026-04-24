"""Tests for Phase 4 active validation probes."""

from __future__ import annotations

import hmac
import json
from hashlib import sha256

import httpx
import pytest

from bbci.phase04 import ActiveValidator, Phase04Scanner
from benchmarks.scoring import score_phase04_reports


@pytest.mark.asyncio
async def test_validate_padding_oracle_detects_error_disclosure() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if b"ciphertext=" in request.content:
            return httpx.Response(400, text="Padding error: invalid padding byte")
        return httpx.Response(500, text="generic failure")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        validator = ActiveValidator(client, "https://example.test")
        result = await validator.validate_padding_oracle({"endpoint_url": "/api/decrypt"})

    assert result is not None
    assert result["status"] == "validated"
    assert result["probe_type"] == "padding_oracle_leak"
    assert result["evidence"]["leak_detected"] is True


@pytest.mark.asyncio
async def test_validate_timing_leak_detects_amplified_delay() -> None:
    known_mac = hmac.new(b"secret", b"test", sha256).hexdigest()

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode())
        if str(payload["mac"]).startswith(known_mac[:10]):
            await sleep_for_signal()
        return httpx.Response(401, json={"status": "invalid"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        validator = ActiveValidator(client, "https://example.test")
        result = await validator.validate_timing_leak(
            {
                "endpoint_url": "https://example.test/api/verify",
                "known_mac": known_mac,
                "measurements": 3,
                "threshold_seconds": 0.00001,
            }
        )

    assert result is not None
    assert result["status"] == "validated"
    assert result["probe_type"] == "timing_analysis"
    assert result["evidence"]["delta_seconds"] > 0


@pytest.mark.asyncio
async def test_phase04_scanner_emits_validations_and_score() -> None:
    known_mac = hmac.new(b"secret", b"test", sha256).hexdigest()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/decrypt":
            return httpx.Response(400, text="Padding error: invalid pad length")
        payload = json.loads(request.content.decode())
        if str(payload["mac"]).startswith(known_mac[:10]):
            await sleep_for_signal()
        return httpx.Response(401, json={"valid": False})

    transport = httpx.MockTransport(handler)
    original_client = httpx.AsyncClient

    def client_factory(*args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        return original_client(*args, **kwargs)

    targets = [
        {
            "id": "V-01",
            "endpoint_url": "http://localhost:9000/api/decrypt",
            "endpoint_path": "/api/decrypt",
            "category": "PaddingOracle",
            "algorithm": "AES-128-CBC-PKCS7",
            "severity": "critical",
            "confidence": 0.92,
            "detection_channel": "CH3:ERROR_DIFFERENTIAL",
        },
        {
            "id": "V-02",
            "endpoint_url": "http://localhost:9000/api/verify-hmac",
            "endpoint_path": "/api/verify-hmac",
            "category": "TimingLeak",
            "algorithm": "HMAC-SHA256-non-constant-time",
            "severity": "medium",
            "confidence": 0.75,
            "detection_channel": "CH4:TIMING_SIDE_CHANNEL",
            "known_mac": known_mac,
            "measurements": 3,
            "threshold_seconds": 0.00001,
        },
    ]

    try:
        httpx.AsyncClient = client_factory  # type: ignore[method-assign]
        scanner = Phase04Scanner(timing_measurements=3)
        report = await scanner.scan_target("http://localhost:9000", targets=targets)
    finally:
        httpx.AsyncClient = original_client  # type: ignore[method-assign]

    assert report["schema_version"] == "phase04-report/v1"
    assert len(report["validations"]) == 2

    score = score_phase04_reports(
        [report],
        target_ids=["V-01", "V-02"],
        negative_control_ids=[],
    )
    assert score.true_positives == 2
    assert score.false_negatives == 0
    assert score.precision == 1.0


async def sleep_for_signal() -> None:
    import asyncio

    await asyncio.sleep(0.001)
