from __future__ import annotations

from bbci.phase02 import (
    canonicalize_base_url,
    classify_surface_kind,
    extract_openapi_candidates,
    extract_service_index_candidates,
)
from benchmarks.scoring import score_phase02_reports


def _phase02_reports() -> list[dict]:
    return [
        {
            "schema_version": "phase02-report/v1",
            "suite_id": "phase02",
            "scanner": {"name": "test", "version": "0.0.0"},
            "execution": {
                "base_url": "http://localhost:9000",
                "canonical_base_url": "http://localhost:9000/",
                "evaluation_mode": "base_url_discovery",
                "started_at": "2026-04-20T00:00:00+00:00",
                "finished_at": "2026-04-20T00:00:01+00:00",
            },
            "request_accounting": {
                "total_actions": 2,
                "descriptor_fetches": 2,
                "redirect_hops_followed": 0,
                "budget_compliant": True,
            },
            "observations": [
                {
                    "id": "service_index:/",
                    "type": "service_index",
                    "target_url": "http://localhost:9000/",
                    "captured_at": "2026-04-20T00:00:00+00:00",
                    "data": {"source_url": "http://localhost:9000/", "format": "service_index"},
                },
                {
                    "id": "openapi:/openapi.json",
                    "type": "openapi",
                    "target_url": "http://localhost:9000/openapi.json",
                    "captured_at": "2026-04-20T00:00:00+00:00",
                    "data": {
                        "source_url": "http://localhost:9000/openapi.json",
                        "format": "openapi",
                    },
                },
            ],
            "discoveries": [
                _discovery("D-01", "/api/encrypt", ["POST"], "encryption_oracle"),
                _discovery("D-02", "/api/encrypt-cbc-static", ["POST"], "encryption_oracle"),
                _discovery("D-03", "/api/encrypt-strong", ["POST"], "encryption_oracle"),
                _discovery("D-04", "/api/hash", ["POST"], "hash_oracle"),
                _discovery("D-05", "/api/hash-sha1", ["POST"], "hash_oracle"),
                _discovery("D-06", "/api/hash-strong", ["POST"], "hash_oracle"),
                _discovery("D-07", "/api/token", ["GET"], "token_issuer"),
                _discovery("D-08", "/api/token-secure", ["GET"], "token_issuer"),
                _discovery("D-09", "/api/decrypt", ["POST"], "decryption_oracle"),
                _discovery("D-10", "/api/auth", ["POST"], "jwt_auth_surface"),
                _discovery("D-11", "/api/auth-rsa", ["POST"], "jwt_auth_surface"),
                _discovery("D-12", "/api/verify-hmac", ["POST"], "hmac_verifier"),
                _discovery("D-13", "/api/verify-hmac-secure", ["POST"], "hmac_verifier"),
            ],
            "benchmark_verdicts": [],
            "summary": {
                "candidate_count": 13,
                "candidate_count_before_filter": 16,
                "non_crypto_candidate_count": 3,
                "relevant_discovery_count": 13,
                "descriptor_attempts": 3,
                "successful_descriptor_fetches": 2,
                "failed_descriptor_fetches": 1,
                "descriptor_sources": ["openapi", "service_index"],
                "matched_discovery_count": 0,
                "false_positive_discovery_count": 0,
                "missed_expected_count": 0,
                "time_to_first_relevant_seconds": 0.01,
            },
        }
    ]


def _discovery(discovery_id: str, path: str, methods: list[str], surface_kind: str) -> dict:
    endpoint_url = f"http://localhost:9000{path}"
    return {
        "id": discovery_id,
        "endpoint_url": endpoint_url,
        "endpoint_path": path,
        "methods": methods,
        "surface_kind": surface_kind,
        "confidence": 0.95,
        "evidence": {
            "observation_ids": ["service_index:/", "openapi:/openapi.json"],
            "base_url": "http://localhost:9000/",
            "collected_via": "test",
            "captured_at": "2026-04-20T00:00:00+00:00",
            "sources": ["openapi", "service_index"],
            "source_urls": [
                "http://localhost:9000/",
                "http://localhost:9000/openapi.json",
            ],
            "endpoint_url": endpoint_url,
            "endpoint_path": path,
            "methods": methods,
            "surface_kind": surface_kind,
            "same_origin": True,
            "classification_basis": "declared",
            "descriptor_formats": ["openapi", "service_index"],
            "declared_surface_kind": surface_kind,
            "source_count": 2,
        },
    }


def test_canonicalize_base_url_normalizes_identity() -> None:
    assert canonicalize_base_url("HTTP://LOCALHOST:9000?x=1") == "http://localhost:9000/"


def test_classify_surface_kind_uses_path_and_context() -> None:
    assert classify_surface_kind("/api/auth-rsa", "Authenticate bearer token") == "jwt_auth_surface"
    assert classify_surface_kind("/api/ping", "Ping service") is None


def test_extract_service_index_candidates() -> None:
    payload = {
        "endpoints": [
            {
                "path": "/api/token",
                "methods": ["GET"],
                "benchmark": "BM-05",
                "summary": "Issue session token",
                "surface_kind": "token_issuer",
                "crypto_relevant": True,
            },
            {
                "path": "/api/ping",
                "methods": ["GET"],
                "benchmark": "D-NC-02",
                "summary": "Ping service",
                "surface_kind": "non_crypto",
                "crypto_relevant": False,
            },
        ]
    }
    candidates = extract_service_index_candidates(payload, "http://localhost:9000/")
    assert len(candidates) == 2
    assert candidates[0].surface_kind == "token_issuer"
    assert candidates[0].classification_bases == {"declared"}
    assert candidates[1].surface_kind is None
    assert candidates[1].classification_bases == {"declared_non_crypto"}


def test_extract_openapi_candidates() -> None:
    payload = {
        "paths": {
            "/api/verify-hmac": {
                "post": {
                    "summary": "Verify HMAC over a message",
                    "description": "Timing Leak",
                    "tags": ["BM-10"],
                    "x-bbci-surface-kind": "hmac_verifier",
                    "x-bbci-crypto-relevant": True,
                }
            }
        }
    }
    candidates = extract_openapi_candidates(payload, "http://localhost:9000/")
    assert len(candidates) == 1
    assert candidates[0].surface_kind == "hmac_verifier"
    assert candidates[0].classification_bases == {"declared"}


def test_score_phase02_reports_perfect_match() -> None:
    score = score_phase02_reports(_phase02_reports())
    assert score.true_positives == 13
    assert score.false_positives == 0
    assert score.false_negatives == 0
    assert score.true_negatives == 3
    assert score.precision == 1.0
    assert score.recall == 1.0
    assert score.budget_compliance_rate == 1.0
    assert score.mean_time_to_first_relevant_seconds == 0.01


def test_score_phase02_reports_counts_negative_control_false_positive() -> None:
    reports = _phase02_reports()
    reports[0]["discoveries"].append(_discovery("D-FP-01", "/api/ping", ["GET"], "token_issuer"))
    score = score_phase02_reports(reports)
    assert score.true_positives == 13
    assert score.false_positives == 1
    assert score.true_negatives == 2
