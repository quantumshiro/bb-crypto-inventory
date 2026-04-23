from __future__ import annotations

from bbci.phase03 import (
    detect_lcg_recurrence,
    normalize_hash_algorithm,
    normalize_jwt_variant,
    repeated_block_metadata,
)
from benchmarks.scoring import score_phase03_reports


def _phase03_report() -> list[dict]:
    return [
        {
            "schema_version": "phase03-report/v1",
            "suite_id": "phase03",
            "scanner": {"name": "test", "version": "0.0.0"},
            "execution": {
                "base_url": "http://localhost:9000",
                "canonical_base_url": "http://localhost:9000/",
                "evaluation_mode": "base_url_classification",
                "started_at": "2026-04-20T00:00:00+00:00",
                "finished_at": "2026-04-20T00:00:01+00:00",
            },
            "request_accounting": {
                "total_actions": 80,
                "discovery_actions": 3,
                "probe_actions": 77,
                "token_fetches": 64,
                "redirect_hops_followed": 0,
                "budget_compliant": True,
            },
            "observations": [],
            "classifications": [
                _classification(
                    "C-01",
                    "/api/encrypt",
                    ["POST"],
                    "encryption_oracle",
                    "ECBMode",
                    "AES-128-ECB",
                    "high",
                    "CH2:CIPHERTEXT_STATS",
                    {
                        "probe_strategy": "repeated_plaintext_blocks",
                        "ciphertext_encoding": "base64",
                        "ciphertext_length_bytes": 80,
                        "block_size_bytes": 16,
                        "repeated_block_count": 2,
                        "repeated_block_indexes": [[0, 1, 2, 3]],
                    },
                ),
                _classification(
                    "C-02",
                    "/api/encrypt-cbc-static",
                    ["POST"],
                    "encryption_oracle",
                    "StaticIV",
                    "AES-128-CBC",
                    "high",
                    "CH2:CIPHERTEXT_STATS",
                    {
                        "probe_strategy": "same_plaintext_repeat",
                        "ciphertext_encoding": "base64",
                        "repeated_request_count": 2,
                        "ciphertexts_equal": True,
                        "ivs_equal": True,
                    },
                ),
                _classification(
                    "C-03",
                    "/api/hash",
                    ["POST"],
                    "hash_oracle",
                    "WeakHash",
                    "MD5",
                    "high",
                    "CH5:HASH_SIGNATURE",
                    {
                        "probe_strategy": "known_input_digest_match",
                        "digest_encoding": "hex",
                        "digest_length_chars": 32,
                        "exact_match_algorithm": "MD5",
                        "candidate_algorithms": ["MD5"],
                    },
                ),
                _classification(
                    "C-04",
                    "/api/hash-sha1",
                    ["POST"],
                    "hash_oracle",
                    "WeakHash",
                    "SHA-1",
                    "medium",
                    "CH5:HASH_SIGNATURE",
                    {
                        "probe_strategy": "known_input_digest_match",
                        "digest_encoding": "hex",
                        "digest_length_chars": 40,
                        "exact_match_algorithm": "SHA-1",
                        "candidate_algorithms": ["SHA-1"],
                    },
                ),
                _classification(
                    "C-05",
                    "/api/token",
                    ["GET"],
                    "token_issuer",
                    "InsecureRandom",
                    "LCG",
                    "high",
                    "CH6:RANDOMNESS",
                    {
                        "probe_strategy": "token_sampling_and_lcg_recovery",
                        "sample_count": 64,
                        "token_field": "token",
                        "lcg_detected": True,
                        "lcg_recurrence_match_ratio": 1.0,
                        "modulus_guess": 2147483648,
                    },
                ),
                _classification(
                    "C-06",
                    "/api/auth",
                    ["POST"],
                    "jwt_auth_surface",
                    "JWTAlgConfusion",
                    "JWT-none",
                    "critical",
                    "CH5:HASH_SIGNATURE",
                    {
                        "probe_strategy": "jwt_issue_then_exploit",
                        "issued_token_header_alg": "HS256",
                        "exploit_variant": "JWT-none",
                        "exploit_response_authenticated": True,
                        "response_status_code": 200,
                    },
                ),
                _classification(
                    "C-07",
                    "/api/auth-rsa",
                    ["POST"],
                    "jwt_auth_surface",
                    "JWTAlgConfusion",
                    "JWT-RS256-to-HS256",
                    "critical",
                    "CH5:HASH_SIGNATURE",
                    {
                        "probe_strategy": "jwt_issue_then_exploit",
                        "issued_token_header_alg": "RS256",
                        "exploit_variant": "JWT-RS256-to-HS256",
                        "exploit_response_authenticated": True,
                        "response_status_code": 200,
                    },
                ),
            ],
            "benchmark_verdicts": [],
            "summary": {
                "candidate_count": 13,
                "in_scope_candidate_count": 10,
                "out_of_scope_candidate_count": 3,
                "classification_count": 7,
                "skipped_surface_count": 3,
                "inconclusive_count": 0,
                "matched_classification_count": 0,
                "false_positive_classification_count": 0,
                "missed_expected_count": 0,
                "time_to_first_classification_seconds": 0.05,
            },
        }
    ]


def _classification(
    discovery_id: str,
    path: str,
    methods: list[str],
    surface_kind: str,
    category: str,
    algorithm: str,
    severity: str,
    channel: str,
    evidence: dict,
) -> dict:
    endpoint_url = f"http://localhost:9000{path}"
    return {
        "id": f"PHASE03-{discovery_id}",
        "endpoint_url": endpoint_url,
        "endpoint_path": path,
        "methods": methods,
        "surface_kind": surface_kind,
        "category": category,
        "severity": severity,
        "algorithm": algorithm,
        "confidence": 0.96,
        "detection_channel": channel,
        "evidence": {
            "observation_ids": [f"obs:{discovery_id}"],
            "base_url": "http://localhost:9000/",
            "collected_via": "test",
            "captured_at": "2026-04-20T00:00:00+00:00",
            "source_discovery_id": discovery_id,
            "endpoint_url": endpoint_url,
            "endpoint_path": path,
            "methods": methods,
            "surface_kind": surface_kind,
            **evidence,
        },
    }


def test_repeated_block_metadata_detects_duplicates() -> None:
    block = b"A" * 16
    metadata = repeated_block_metadata(block * 4 + b"B" * 16)
    assert metadata["block_size_bytes"] == 16
    assert metadata["repeated_block_count"] == 1
    assert metadata["repeated_block_indexes"] == [[0, 1, 2, 3]]


def test_detect_lcg_recurrence_recovers_benchmark_pattern() -> None:
    state = 42
    words: list[int] = []
    for _ in range(20):
        state = (state * 1103515245 + 12345) % (2**31)
        words.append(state)
    result = detect_lcg_recurrence(words)
    assert result["lcg_detected"] is True
    assert result["lcg_recurrence_match_ratio"] == 1.0
    assert result["modulus_guess"] == 2**31


def test_normalizers_apply_suite_aliases() -> None:
    assert normalize_hash_algorithm("sha1") == "SHA-1"
    assert normalize_jwt_variant("alg=none") == "JWT-none"


def test_score_phase03_reports_perfect_match() -> None:
    score = score_phase03_reports(_phase03_report())
    assert score.true_positives == 7
    assert score.false_positives == 0
    assert score.false_negatives == 0
    assert score.true_negatives == 3
    assert score.precision == 1.0
    assert score.recall == 1.0
    assert score.budget_compliance_rate == 1.0
    assert score.mean_time_to_first_classification_seconds == 0.05


def test_score_phase03_reports_counts_negative_control_false_positive() -> None:
    reports = _phase03_report()
    reports[0]["classifications"].append(
        _classification(
            "C-FP-01",
            "/api/token-secure",
            ["GET"],
            "token_issuer",
            "InsecureRandom",
            "LCG",
            "high",
            "CH6:RANDOMNESS",
            {
                "probe_strategy": "token_sampling_and_lcg_recovery",
                "sample_count": 64,
                "token_field": "token",
                "lcg_detected": True,
                "lcg_recurrence_match_ratio": 1.0,
                "modulus_guess": 2147483648,
            },
        )
    )
    score = score_phase03_reports(reports)
    assert score.true_positives == 7
    assert score.false_positives == 1
    assert score.true_negatives == 2
