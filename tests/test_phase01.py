from __future__ import annotations

from bbci.phase01 import canonicalize_https_url, compute_tls_grade
from benchmarks.scoring import score_phase01_reports


def _weak_finding(category: str, algorithm: str, evidence: dict, finding_id: str) -> dict:
    return {
        "id": finding_id,
        "target_url": "https://localhost:9443/",
        "endpoint": "https://localhost:9443/",
        "category": category,
        "severity": "high" if category != "NoHSTS" else "low",
        "algorithm": algorithm,
        "confidence": 0.99,
        "detection_channel": "RECON"
        if category in {"NoHSTS", "WeakKeyLength", "WeakSignatureAlgorithm"}
        else "CH1:TLS_HANDSHAKE",
        "evidence": {
            "observation_ids": ["obs"],
            "target_url": "https://localhost:9443/",
            "collected_via": "test",
            "captured_at": "2026-04-04T00:00:00+00:00",
            **evidence,
        },
    }


def _phase01_reports() -> list[dict]:
    weak_report = {
        "schema_version": "phase01-report/v1",
        "suite_id": "phase01",
        "scanner": {"name": "test"},
        "execution": {
            "target_url": "https://localhost:9443/",
            "canonical_target": "https://localhost:9443/",
            "evaluation_mode": "url_scoped",
            "started_at": "2026-04-04T00:00:00+00:00",
            "finished_at": "2026-04-04T00:00:01+00:00",
        },
        "request_accounting": {
            "total_actions": 14,
            "header_fetches": 1,
            "certificate_fetches": 1,
            "version_probes": 4,
            "cipher_probes": 7,
            "budget_compliant": True,
        },
        "observations": [
            {
                "id": "grade-weak",
                "type": "tls_grade",
                "target_url": "https://localhost:9443/",
                "captured_at": "2026-04-04T00:00:00+00:00",
                "data": {"grade": "C"},
            },
        ],
        "findings": [
            _weak_finding(
                "WeakProtocolVersion",
                "TLSv1.0",
                {
                    "supported_protocols": ["TLSv1.0", "TLSv1.1", "TLSv1.2"],
                    "accepted_protocol": "TLSv1.0",
                },
                "F-001",
            ),
            _weak_finding(
                "WeakProtocolVersion",
                "TLSv1.1",
                {
                    "supported_protocols": ["TLSv1.0", "TLSv1.1", "TLSv1.2"],
                    "accepted_protocol": "TLSv1.1",
                },
                "F-002",
            ),
            _weak_finding(
                "InsecureCipherSuite",
                "RC4-family",
                {
                    "accepted_suites": ["RC4-SHA", "AES128-SHA"],
                    "normalized_suite_families": ["RC4-family", "static-RSA"],
                    "representative_suite": "RC4-SHA",
                },
                "F-003",
            ),
            _weak_finding(
                "NoPFS",
                "static-RSA",
                {
                    "accepted_suites": ["AES128-SHA"],
                    "accepted_key_exchange_families": ["static-RSA", "ECDHE"],
                    "non_pfs_accepted": True,
                },
                "F-004",
            ),
            _weak_finding(
                "NoHSTS",
                "HSTS-missing",
                {"response_headers": {"server": "nginx"}, "redirect_hops_followed": 0},
                "F-005",
            ),
            _weak_finding(
                "WeakKeyLength",
                "RSA-1024",
                {"certificate_position": "leaf", "key_type": "RSA", "key_length_bits": 1024},
                "F-006",
            ),
            _weak_finding(
                "WeakSignatureAlgorithm",
                "sha1WithRSAEncryption",
                {"certificate_position": "leaf", "signature_algorithm": "sha1WithRSAEncryption"},
                "F-007",
            ),
        ],
        "benchmark_verdicts": [
            {
                "benchmark_id": "BM-09",
                "target_url": "https://localhost:9443/",
                "status": "matched",
                "matched_finding_ids": ["F-001", "F-002", "F-003", "F-004"],
                "expected_grade": "C",
                "observed_grade": "C",
                "evidence_valid": True,
                "budget_compliant": True,
            },
            {
                "benchmark_id": "BM-11",
                "target_url": "https://localhost:9443/",
                "status": "matched",
                "matched_finding_ids": ["F-005"],
                "evidence_valid": True,
                "budget_compliant": True,
            },
            {
                "benchmark_id": "BM-12",
                "target_url": "https://localhost:9443/",
                "status": "matched",
                "matched_finding_ids": ["F-006"],
                "evidence_valid": True,
                "budget_compliant": True,
            },
            {
                "benchmark_id": "BM-13",
                "target_url": "https://localhost:9443/",
                "status": "matched",
                "matched_finding_ids": ["F-007"],
                "evidence_valid": True,
                "budget_compliant": True,
            },
        ],
    }
    strong_report = {
        "schema_version": "phase01-report/v1",
        "suite_id": "phase01",
        "scanner": {"name": "test"},
        "execution": {
            "target_url": "https://localhost:9444/",
            "canonical_target": "https://localhost:9444/",
            "evaluation_mode": "url_scoped",
            "started_at": "2026-04-04T00:00:00+00:00",
            "finished_at": "2026-04-04T00:00:01+00:00",
        },
        "request_accounting": {
            "total_actions": 14,
            "header_fetches": 1,
            "certificate_fetches": 1,
            "version_probes": 4,
            "cipher_probes": 7,
            "budget_compliant": True,
        },
        "observations": [
            {
                "id": "grade-strong",
                "type": "tls_grade",
                "target_url": "https://localhost:9444/",
                "captured_at": "2026-04-04T00:00:00+00:00",
                "data": {"grade": "A+"},
            },
        ],
        "findings": [],
        "benchmark_verdicts": [
            {
                "benchmark_id": "NC-04",
                "target_url": "https://localhost:9444/",
                "status": "true_negative",
                "matched_finding_ids": [],
                "expected_grade": "A+",
                "observed_grade": "A+",
                "evidence_valid": True,
                "budget_compliant": True,
            },
        ],
    }
    return [weak_report, strong_report]


def test_canonicalize_https_url_normalizes_identity() -> None:
    assert canonicalize_https_url("HTTPS://LOCALHOST:9443?x=1") == "https://localhost:9443/"


def test_compute_tls_grade_promotes_a_plus_with_hsts() -> None:
    grade = compute_tls_grade(
        supported_protocols=["TLSv1.3"],
        accepted_suites=[
            {
                "suite": "TLS_AES_128_GCM_SHA256",
                "normalized_family": "TLSv1.3-AEAD",
                "key_exchange_family": "ECDHE",
                "bits": 128,
            },
            {
                "suite": "TLS_AES_256_GCM_SHA384",
                "normalized_family": "TLSv1.3-AEAD",
                "key_exchange_family": "ECDHE",
                "bits": 256,
            },
        ],
        key_exchange_bits=2048,
        hsts_header="max-age=63072000; includeSubDomains; preload",
    )
    assert grade["grade"] == "A+"


def test_score_phase01_reports_perfect_match() -> None:
    score = score_phase01_reports(_phase01_reports())
    assert score.true_positives == 7
    assert score.false_positives == 0
    assert score.false_negatives == 0
    assert score.true_negatives == 1
    assert score.precision == 1.0
    assert score.recall == 1.0
    assert score.ssl_grade_accuracy == 1.0
    assert score.budget_compliance_rate == 1.0
    assert score.inconclusive_rate == 0.0


def test_score_phase01_reports_counts_duplicate_false_positive() -> None:
    reports = _phase01_reports()
    reports[0]["findings"].append(
        _weak_finding(
            "InsecureCipherSuite",
            "RC4-family",
            {
                "accepted_suites": ["RC4-MD5"],
                "normalized_suite_families": ["RC4-family"],
                "representative_suite": "RC4-MD5",
            },
            "F-008",
        )
    )
    score = score_phase01_reports(reports)
    assert score.true_positives == 7
    assert score.false_positives == 1
    assert score.duplicate_false_positives == 1
