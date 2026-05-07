from __future__ import annotations

from bbci.phase04 import padding_oracle_mutations, timing_signal
from benchmarks.scoring import score_phase04_reports


def _validation(
    validation_id: str,
    path: str,
    category: str,
    algorithm: str,
    vulnerable: bool,
    evidence: dict,
) -> dict:
    endpoint_url = f"http://localhost:9000{path}"
    surface_kind = "decryption_oracle" if category == "PaddingOracle" else "hmac_verifier"
    channel = "CH3:ERROR_DIFFERENTIAL" if category == "PaddingOracle" else "CH4:TIMING_SIDE_CHANNEL"
    return {
        "id": validation_id,
        "endpoint_url": endpoint_url,
        "endpoint_path": path,
        "methods": ["POST"],
        "surface_kind": surface_kind,
        "category": category,
        "severity": "critical" if vulnerable else "none",
        "algorithm": algorithm,
        "confidence": 0.92,
        "detection_channel": channel,
        "vulnerable": vulnerable,
        "evidence": {
            "observation_ids": [f"obs:{validation_id}"],
            "base_url": "http://localhost:9000/",
            "collected_via": "test",
            "captured_at": "2026-05-06T00:00:00+00:00",
            "endpoint_url": endpoint_url,
            "endpoint_path": path,
            "methods": ["POST"],
            "surface_kind": surface_kind,
            "probe_strategy": "test",
            **evidence,
        },
    }


def _phase04_report() -> list[dict]:
    return [
        {
            "schema_version": "phase04-report/v1",
            "suite_id": "phase04",
            "scanner": {"name": "test", "version": "0.0.0"},
            "execution": {
                "base_url": "http://localhost:9000",
                "canonical_base_url": "http://localhost:9000/",
                "evaluation_mode": "active_validation",
                "started_at": "2026-05-06T00:00:00+00:00",
                "finished_at": "2026-05-06T00:00:01+00:00",
            },
            "request_accounting": {
                "total_actions": 64,
                "padding_oracle_probes": 12,
                "timing_probes": 32,
                "control_probes": 20,
                "budget_compliant": True,
            },
            "observations": [],
            "validations": [
                _validation(
                    "PHASE04-PADDING-VULN",
                    "/api/decrypt",
                    "PaddingOracle",
                    "AES-128-CBC-PKCS7",
                    True,
                    {
                        "valid_status_code": 200,
                        "invalid_cluster_count": 2,
                        "padding_error_markers": 2,
                    },
                ),
                _validation(
                    "PHASE04-TIMING-VULN",
                    "/api/verify-hmac",
                    "TimingLeak",
                    "HMAC-SHA256-non-constant-time",
                    True,
                    {
                        "samples_per_prefix": 8,
                        "prefix_medians_seconds": {"0": 0.001, "32": 0.02},
                        "median_delta_seconds": 0.019,
                        "monotonic_steps": 3,
                        "timing_leak_detected": True,
                    },
                ),
                _validation(
                    "PHASE04-PADDING-CONTROL",
                    "/api/decrypt-secure",
                    "PaddingOracle",
                    "AES-128-CBC-PKCS7",
                    False,
                    {
                        "valid_status_code": 200,
                        "invalid_cluster_count": 1,
                        "padding_error_markers": 0,
                    },
                ),
                _validation(
                    "PHASE04-TIMING-CONTROL",
                    "/api/verify-hmac-secure",
                    "TimingLeak",
                    "HMAC-SHA256-non-constant-time",
                    False,
                    {
                        "samples_per_prefix": 8,
                        "prefix_medians_seconds": {"0": 0.001, "32": 0.0012},
                        "median_delta_seconds": 0.0002,
                        "monotonic_steps": 1,
                        "timing_leak_detected": False,
                    },
                ),
            ],
            "benchmark_verdicts": [],
            "summary": {
                "validation_count": 4,
                "vulnerable_validation_count": 2,
                "control_validation_count": 2,
                "inconclusive_count": 0,
                "matched_validation_count": 0,
                "false_positive_validation_count": 0,
                "missed_expected_count": 0,
                "time_to_first_validation_seconds": 0.001,
            },
        }
    ]


def test_timing_signal_detects_prefix_correlation() -> None:
    signal = timing_signal({0: 0.001, 8: 0.006, 16: 0.01, 32: 0.02})
    assert signal["timing_leak_detected"] is True
    assert signal["monotonic_steps"] == 3


def test_padding_oracle_mutations_target_previous_ciphertext_block() -> None:
    valid_ciphertext = bytes(range(48))
    mutations = dict(padding_oracle_mutations(valid_ciphertext, pad_len=4))

    assert mutations["invalid_pad_length"][-17] == valid_ciphertext[-17] ^ 4
    assert mutations["inconsistent_padding_bytes"][-18] == valid_ciphertext[-18] ^ 1
    assert all(len(mutated) == len(valid_ciphertext) for mutated in mutations.values())


def test_score_phase04_reports_perfect_match() -> None:
    score = score_phase04_reports(_phase04_report())
    assert score.true_positives == 2
    assert score.false_positives == 0
    assert score.false_negatives == 0
    assert score.true_negatives == 2
    assert score.precision == 1.0
    assert score.recall == 1.0
    assert score.budget_compliance_rate == 1.0


def test_score_phase04_reports_counts_control_false_positive() -> None:
    reports = _phase04_report()
    reports[0]["validations"][2]["vulnerable"] = True
    reports[0]["validations"][2]["evidence"]["invalid_cluster_count"] = 2
    reports[0]["validations"][2]["evidence"]["padding_error_markers"] = 1
    score = score_phase04_reports(reports)
    assert score.true_positives == 2
    assert score.false_positives == 1
    assert score.true_negatives == 1
