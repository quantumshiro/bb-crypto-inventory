from __future__ import annotations

from benchmarks.scoring import score_phase05_reports


def _result(target_id: str, path: str, operation: str, status: str, evidence: dict) -> dict:
    endpoint_url = f"http://localhost:9000{path}"
    return {
        "id": f"PHASE05-{target_id}",
        "target_id": target_id,
        "endpoint_url": endpoint_url,
        "endpoint_path": path,
        "operation": operation,
        "status": status,
        "passed": True,
        "confidence": 0.93,
        "evidence": {
            "observation_ids": [f"obs:{target_id}"],
            "base_url": "http://localhost:9000/",
            "collected_via": "test",
            "captured_at": "2026-05-06T00:00:00+00:00",
            **evidence,
        },
    }


def _phase05_report() -> list[dict]:
    return [
        {
            "schema_version": "phase05-report/v1",
            "suite_id": "phase05",
            "scanner": {"name": "test", "version": "0.0.0"},
            "execution": {
                "base_url": "http://localhost:9000",
                "canonical_base_url": "http://localhost:9000/",
                "evaluation_mode": "operational_robustness",
                "started_at": "2026-05-06T00:00:00+00:00",
                "finished_at": "2026-05-06T00:00:01+00:00",
            },
            "request_accounting": {
                "total_actions": 28,
                "rate_limit_probes": 3,
                "transient_probes": 2,
                "noise_probes": 24,
                "budget_compliant": True,
            },
            "observations": [],
            "operational_results": [
                _result(
                    "O-01",
                    "/api/rate-limit-token",
                    "rate_limit_handling",
                    "rate_limit_detected",
                    {
                        "status_codes": [200, 200, 429],
                        "saw_429": True,
                        "stopped_after_429": True,
                    },
                ),
                _result(
                    "O-02",
                    "/api/transient-hash",
                    "transient_recovery",
                    "transient_recovered",
                    {
                        "status_codes": [503, 200],
                        "retried_after_503": True,
                        "final_status_code": 200,
                    },
                ),
                _result(
                    "O-03",
                    "/api/verify-hmac-noisy",
                    "noisy_secure_timing_suppression",
                    "no_timing_leak",
                    {
                        "samples_per_prefix": 6,
                        "prefix_medians_seconds": {"0": 0.001, "32": 0.0015},
                        "median_delta_seconds": 0.0005,
                        "timing_leak_detected": False,
                    },
                ),
            ],
            "benchmark_verdicts": [],
            "summary": {
                "operational_result_count": 3,
                "passed_operational_count": 3,
                "failed_operational_count": 0,
                "inconclusive_count": 0,
                "matched_operational_count": 0,
                "missed_expected_count": 0,
            },
        }
    ]


def test_score_phase05_reports_perfect_match() -> None:
    score = score_phase05_reports(_phase05_report())
    assert score.true_positives == 3
    assert score.false_positives == 0
    assert score.false_negatives == 0
    assert score.precision == 1.0
    assert score.recall == 1.0
    assert score.budget_compliance_rate == 1.0


def test_score_phase05_reports_ignores_out_of_scope_filter_results() -> None:
    score = score_phase05_reports(_phase05_report(), target_ids=["O-01"])
    assert score.true_positives == 1
    assert score.false_positives == 0
    assert score.false_negatives == 0
    assert score.total_expected == 1


def test_score_phase05_reports_rejects_wrong_noisy_timing_status() -> None:
    reports = _phase05_report()
    reports[0]["operational_results"][2]["status"] = "false_positive_timing_leak"
    reports[0]["operational_results"][2]["evidence"]["timing_leak_detected"] = True
    score = score_phase05_reports(reports)
    assert score.true_positives == 2
    assert score.false_negatives == 1
