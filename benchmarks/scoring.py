"""Scoring engine for benchmark evaluation.

Computes precision, recall, F1, and confidence calibration
by comparing bbci findings against ground truth.

Standards alignment:
- IR metrics (precision/recall/F1) as used in CamBench [1] and CryptoAPI-Bench [2] evaluations
- TLS scoring follows Qualys SSL Labs Rating Guide v2009r [3]
- CWE mapping from MITRE CWE database

References:
  [1] Schlichtig et al., "CamBench", MSR 2022, arXiv:2204.06447
  [2] Afrose et al., "CryptoAPI-Bench", IEEE SecDev 2019
  [3] Qualys SSL Labs, "SSL Server Rating Guide", v2009r (2025)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

from bbci.phase01 import (
    canonicalize_https_url,
    compute_tls_grade,
    normalize_protocol,
    normalize_signature_algorithm,
)
from bbci.phase02 import canonicalize_endpoint_url, normalize_methods
from bbci.phase03 import normalize_hash_algorithm, normalize_jwt_variant


@dataclass
class MatchResult:
    """Result of matching a single finding against ground truth."""

    benchmark_id: str
    expected_category: str
    expected_algorithm: str
    matched: bool
    matched_finding_id: str | None = None
    matched_confidence: float | None = None
    expected_min_confidence: float = 0.5
    notes: str = ""


@dataclass
class BenchmarkScore:
    """Overall benchmark scoring results."""

    total_expected: int = 0
    total_detected: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0  # Negative controls that correctly produced no findings
    duplicate_false_positives: int = 0

    matches: list[MatchResult] = field(default_factory=list)
    false_positive_findings: list[dict] = field(default_factory=list)
    negative_control_results: list[dict] = field(default_factory=list)
    benchmark_verdicts: list[dict[str, Any]] = field(default_factory=list)
    phase01_reports: list[dict[str, Any]] = field(default_factory=list)
    phase02_reports: list[dict[str, Any]] = field(default_factory=list)
    phase03_reports: list[dict[str, Any]] = field(default_factory=list)

    per_benchmark: dict[str, dict[str, Any]] = field(default_factory=dict)
    per_channel: dict[str, dict[str, Any]] = field(default_factory=dict)

    confidence_calibration: list[dict] = field(default_factory=list)
    ssl_grade_accuracy: float = 0.0
    budget_compliance_rate: float = 0.0
    inconclusive_rate: float = 0.0
    mean_time_to_first_relevant_seconds: float = 0.0
    mean_time_to_first_classification_seconds: float = 0.0

    @property
    def precision(self) -> float:
        """Fraction of reported findings that are true positives."""
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        """Fraction of ground-truth vulnerabilities that were detected."""
        if self.total_expected == 0:
            return 0.0
        return self.true_positives / self.total_expected

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)

    def summary(self) -> dict[str, Any]:
        """Generate a summary dict."""
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1, 4),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "duplicate_false_positives": self.duplicate_false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "total_expected": self.total_expected,
            "total_detected": self.total_detected,
            "ssl_grade_accuracy": round(self.ssl_grade_accuracy, 4),
            "budget_compliance_rate": round(self.budget_compliance_rate, 4),
            "inconclusive_rate": round(self.inconclusive_rate, 4),
            "mean_time_to_first_relevant_seconds": round(
                self.mean_time_to_first_relevant_seconds, 4
            ),
            "mean_time_to_first_classification_seconds": round(
                self.mean_time_to_first_classification_seconds, 4
            ),
            "per_benchmark": self.per_benchmark,
            "per_channel": self.per_channel,
            "confidence_calibration": self.confidence_calibration,
            "negative_control_results": self.negative_control_results,
            "benchmark_verdicts": self.benchmark_verdicts,
        }


def load_ground_truth(path: str = "benchmarks/ground_truth.yaml") -> dict:
    """Load ground truth from YAML file."""
    with open(path) as f:
        return yaml.safe_load(f)


def compute_ssl_labs_grade(
    supported_protocols: list[str],
    cipher_suites: list[dict],
    has_pfs: bool = False,
    has_rc4: bool = False,
    has_3des: bool = False,
    key_exchange_bits: int = 2048,
    hsts_header: str | None = None,
) -> dict[str, Any]:
    """Backward-compatible wrapper around the phase01 grade calculator."""
    suites = [dict(suite) for suite in cipher_suites]
    for suite in suites:
        if "normalized_family" not in suite:
            family = suite.get("suite", "")
            if has_rc4 and "RC4" in family:
                suite["normalized_family"] = "RC4-family"
            elif has_3des and "3DES" in family:
                suite["normalized_family"] = "3DES-family"
            else:
                suite["normalized_family"] = family
        if "key_exchange_family" not in suite:
            suite["key_exchange_family"] = "ECDHE" if has_pfs else "static-RSA"

    return compute_tls_grade(
        supported_protocols=supported_protocols,
        accepted_suites=suites,
        key_exchange_bits=key_exchange_bits,
        hsts_header=hsts_header,
    )


def _phase01_in_scope_categories(contract: dict[str, Any]) -> set[str]:
    return set(contract.get("suite_categories", []))


def _normalize_phase01_algorithm(category: str, algorithm: str) -> str:
    if category == "WeakProtocolVersion":
        return normalize_protocol(algorithm)
    if category == "WeakSignatureAlgorithm":
        return normalize_signature_algorithm(algorithm)
    if category == "InsecureCipherSuite" and algorithm in {"RC4", "RC4-SHA", "RC4-MD5"}:
        return "RC4-family"
    if category == "NoPFS" and algorithm in {"RSA-key-exchange", "RSA", "static RSA"}:
        return "static-RSA"
    return algorithm


def _finding_target(finding: dict[str, Any]) -> str:
    target = finding.get("target_url") or finding.get("endpoint") or ""
    return canonicalize_https_url(target) if target else ""


def _required_evidence_keys(contract: dict[str, Any], category: str) -> list[str]:
    by_category = contract.get("evidence_contract", {}).get("by_category", {})
    common = contract.get("evidence_contract", {}).get("common_required_keys", [])
    return list(common) + list(by_category.get(category, []))


def _evidence_valid(
    finding: dict[str, Any], contract: dict[str, Any], category: str, algorithm: str
) -> bool:
    evidence = finding.get("evidence", {})
    if not isinstance(evidence, dict):
        return False
    for key in _required_evidence_keys(contract, category):
        if key not in evidence:
            return False

    if category == "WeakProtocolVersion":
        return normalize_protocol(evidence.get("accepted_protocol", "")) == algorithm
    if category == "InsecureCipherSuite":
        families = set(evidence.get("normalized_suite_families", []))
        return "RC4-family" in families
    if category == "NoPFS":
        return evidence.get("non_pfs_accepted") is True
    if category == "NoHSTS":
        headers = {k.lower(): v for k, v in evidence.get("response_headers", {}).items()}
        return "strict-transport-security" not in headers
    if category == "WeakKeyLength":
        return (
            evidence.get("certificate_position") == "leaf"
            and evidence.get("key_type") == "RSA"
            and evidence.get("key_length_bits") == 1024
        )
    if category == "WeakSignatureAlgorithm":
        return (
            evidence.get("certificate_position") == "leaf"
            and normalize_signature_algorithm(evidence.get("signature_algorithm", "")) == algorithm
        )
    return True


def _phase01_grade_from_report(report: dict[str, Any]) -> str | None:
    for observation in report.get("observations", []):
        if observation.get("type") == "tls_grade":
            data = observation.get("data", {})
            return data.get("grade")
    return None


def _phase02_discovery_evidence_valid(discovery: dict[str, Any], contract: dict[str, Any]) -> bool:
    evidence = discovery.get("evidence", {})
    if not isinstance(evidence, dict):
        return False
    required_keys = list(contract.get("evidence_contract", {}).get("common_required_keys", []))
    required_keys += list(contract.get("evidence_contract", {}).get("discovery_required_keys", []))
    for key in required_keys:
        if key not in evidence:
            return False
    if evidence.get("same_origin") is not True:
        return False
    if evidence.get("endpoint_url") != discovery.get("endpoint_url"):
        return False
    if evidence.get("endpoint_path") != discovery.get("endpoint_path"):
        return False
    if evidence.get("surface_kind") != discovery.get("surface_kind"):
        return False
    if evidence.get("classification_basis") not in {"declared", "heuristic"}:
        return False
    source_urls = evidence.get("source_urls", [])
    if not isinstance(source_urls, list) or not source_urls:
        return False
    return True


def _normalize_phase03_algorithm(category: str, algorithm: str) -> str:
    if category == "WeakHash":
        return normalize_hash_algorithm(algorithm)
    if category == "JWTAlgConfusion":
        return normalize_jwt_variant(algorithm)
    return algorithm


def _phase03_classification_evidence_valid(
    classification: dict[str, Any], contract: dict[str, Any], category: str, algorithm: str
) -> bool:
    evidence = classification.get("evidence", {})
    if not isinstance(evidence, dict):
        return False
    required_keys = list(contract.get("evidence_contract", {}).get("common_required_keys", []))
    required_keys += list(
        contract.get("evidence_contract", {}).get("by_category", {}).get(category, [])
    )
    for key in required_keys:
        if key not in evidence:
            return False

    if evidence.get("endpoint_url") != classification.get("endpoint_url"):
        return False
    if evidence.get("endpoint_path") != classification.get("endpoint_path"):
        return False
    if evidence.get("surface_kind") != classification.get("surface_kind"):
        return False

    if category == "ECBMode":
        return (
            evidence.get("ciphertext_encoding") == "base64"
            and evidence.get("block_size_bytes") == 16
            and evidence.get("repeated_block_count", 0) >= 1
            and isinstance(evidence.get("repeated_block_indexes"), list)
            and bool(evidence.get("repeated_block_indexes"))
        )
    if category == "StaticIV":
        return (
            evidence.get("ciphertext_encoding") == "base64"
            and evidence.get("repeated_request_count", 0) >= 2
            and evidence.get("ciphertexts_equal") is True
            and evidence.get("ivs_equal") is True
        )
    if category == "WeakHash":
        return normalize_hash_algorithm(evidence.get("exact_match_algorithm", "")) == algorithm
    if category == "InsecureRandom":
        return (
            evidence.get("sample_count", 0) >= 8
            and evidence.get("lcg_detected") is True
            and float(evidence.get("lcg_recurrence_match_ratio", 0.0)) >= 0.95
            and evidence.get("modulus_guess") == 2**31
        )
    if category == "JWTAlgConfusion":
        return (
            normalize_jwt_variant(evidence.get("exploit_variant", "")) == algorithm
            and evidence.get("exploit_response_authenticated") is True
            and isinstance(evidence.get("response_status_code"), int)
            and evidence["response_status_code"] < 400
        )
    return True


def score_phase02_reports(
    reports: list[dict[str, Any]],
    ground_truth_path: str = "benchmarks/ground_truth.yaml",
    target_ids: list[str] | None = None,
    negative_control_ids: list[str] | None = None,
) -> BenchmarkScore:
    """Score phase02 base-URL discovery reports against the phase02 contract."""
    gt = load_ground_truth(ground_truth_path)
    contract = gt.get("phase02_contract", {})
    suite = gt.get("benchmark_suites", {}).get("phase02", {})
    targets = gt.get("phase02_targets", {})
    negative_controls = gt.get("phase02_negative_controls", {})

    score = BenchmarkScore()
    score.phase02_reports = reports

    selected_target_ids = target_ids or list(suite.get("target_ids", []))
    selected_negative_control_ids = negative_control_ids or list(
        suite.get("negative_control_ids", [])
    )

    expected_units: list[tuple[str, str, str, list[str]]] = []
    for target_id in selected_target_ids:
        target = targets[target_id]
        endpoint_url = canonicalize_endpoint_url(target["target_url"], target["endpoint_path"])
        expected_methods = normalize_methods(target.get("methods"))
        expected_units.append((target_id, endpoint_url, target["surface_kind"], expected_methods))
        score.per_benchmark[target_id] = {
            "name": target["name"],
            "expected": 1,
            "detected": 0,
            "findings": [],
        }

    score.total_expected = len(expected_units)

    allowed_endpoint_urls = {
        canonicalize_endpoint_url(
            targets[target_id]["target_url"],
            targets[target_id]["endpoint_path"],
        )
        for target_id in selected_target_ids
    }
    allowed_endpoint_urls.update(
        canonicalize_endpoint_url(
            negative_controls[nc_id]["target_url"], negative_controls[nc_id]["endpoint_path"]
        )
        for nc_id in selected_negative_control_ids
    )

    all_discoveries: list[dict[str, Any]] = []
    for report in reports:
        for discovery in report.get("discoveries", []):
            if discovery.get("endpoint_url") in allowed_endpoint_urls:
                all_discoveries.append(discovery)
    score.total_detected = len(all_discoveries)

    matched_ids: set[str] = set()
    duplicate_ids: set[str] = set()
    mean_ttf_values: list[float] = []
    inconclusive_reports = 0
    budget_reports = 0
    budget_compliant_reports = 0

    for target_id, endpoint_url, surface_kind, expected_methods in expected_units:
        candidates = []
        for discovery in all_discoveries:
            if discovery.get("id") in matched_ids:
                continue
            if discovery.get("endpoint_url") != endpoint_url:
                continue
            if discovery.get("surface_kind") != surface_kind:
                continue
            observed_methods = normalize_methods(discovery.get("methods", []))
            if expected_methods and not set(observed_methods).intersection(expected_methods):
                continue
            if not _phase02_discovery_evidence_valid(discovery, contract):
                continue
            candidates.append(discovery)

        candidates.sort(
            key=lambda discovery: (
                -float(discovery.get("confidence", 0.0)),
                discovery.get("id", ""),
            )
        )

        if candidates:
            chosen = candidates[0]
            matched_ids.add(chosen["id"])
            for duplicate in candidates[1:]:
                duplicate_ids.add(duplicate["id"])
            score.true_positives += 1
            score.per_benchmark[target_id]["detected"] += 1
            score.confidence_calibration.append(
                {
                    "benchmark": target_id,
                    "expected_min": 0.8,
                    "actual": chosen.get("confidence", 0.0),
                    "meets_threshold": chosen.get("confidence", 0.0) >= 0.8,
                }
            )
            score.benchmark_verdicts.append(
                {
                    "benchmark_id": target_id,
                    "endpoint_url": endpoint_url,
                    "status": "matched",
                    "surface_kind": surface_kind,
                }
            )
            score.matches.append(
                MatchResult(
                    benchmark_id=target_id,
                    expected_category="DiscoverySurface",
                    expected_algorithm=surface_kind,
                    matched=True,
                    matched_finding_id=chosen.get("id"),
                    matched_confidence=chosen.get("confidence", 0.0),
                    expected_min_confidence=0.8,
                )
            )
        else:
            score.false_negatives += 1
            score.benchmark_verdicts.append(
                {
                    "benchmark_id": target_id,
                    "endpoint_url": endpoint_url,
                    "status": "missed",
                    "surface_kind": surface_kind,
                }
            )
            score.matches.append(
                MatchResult(
                    benchmark_id=target_id,
                    expected_category="DiscoverySurface",
                    expected_algorithm=surface_kind,
                    matched=False,
                    expected_min_confidence=0.8,
                    notes="Not discovered",
                )
            )

    for discovery in all_discoveries:
        discovery_id = discovery.get("id", "")
        if discovery_id in matched_ids:
            continue
        score.false_positives += 1
        if discovery_id in duplicate_ids:
            score.duplicate_false_positives += 1
        score.false_positive_findings.append(discovery)

    score.per_channel["PHASE02:SURFACE_DISCOVERY"] = {
        "expected": score.total_expected,
        "detected": score.true_positives,
    }

    for report in reports:
        request_accounting = report.get("request_accounting", {})
        if request_accounting:
            budget_reports += 1
            if request_accounting.get("budget_compliant"):
                budget_compliant_reports += 1
        if any(
            verdict.get("status") == "inconclusive"
            for verdict in report.get("benchmark_verdicts", [])
        ):
            inconclusive_reports += 1
        ttf = report.get("summary", {}).get("time_to_first_relevant_seconds")
        if isinstance(ttf, (int, float)):
            mean_ttf_values.append(float(ttf))

    score.budget_compliance_rate = (
        budget_compliant_reports / budget_reports if budget_reports else 0.0
    )
    score.inconclusive_rate = inconclusive_reports / len(reports) if reports else 0.0
    score.mean_time_to_first_relevant_seconds = (
        sum(mean_ttf_values) / len(mean_ttf_values) if mean_ttf_values else 0.0
    )

    for nc_id in selected_negative_control_ids:
        nc_def = negative_controls[nc_id]
        endpoint_url = canonicalize_endpoint_url(nc_def["target_url"], nc_def["endpoint_path"])
        discovered = any(
            discovery.get("endpoint_url") == endpoint_url for discovery in all_discoveries
        )
        passed = not discovered
        score.negative_control_results.append(
            {
                "id": nc_id,
                "name": nc_def["name"],
                "passed": passed,
                "endpoint_url": endpoint_url,
            }
        )
        if passed:
            score.true_negatives += 1

    return score


def score_phase03_reports(
    reports: list[dict[str, Any]],
    ground_truth_path: str = "benchmarks/ground_truth.yaml",
    target_ids: list[str] | None = None,
    negative_control_ids: list[str] | None = None,
) -> BenchmarkScore:
    """Score phase03 classification reports against the phase03 contract."""
    gt = load_ground_truth(ground_truth_path)
    contract = gt.get("phase03_contract", {})
    suite = gt.get("benchmark_suites", {}).get("phase03", {})
    targets = gt.get("phase03_targets", {})
    negative_controls = gt.get("phase03_negative_controls", {})
    benchmarks = gt.get("benchmarks", {})

    score = BenchmarkScore()
    score.phase03_reports = reports

    selected_target_ids = target_ids or list(suite.get("target_ids", []))
    selected_negative_control_ids = negative_control_ids or list(
        suite.get("negative_control_ids", [])
    )

    expected_units: list[tuple[str, str, str, str, str, list[str], float]] = []
    for target_id in selected_target_ids:
        target = targets[target_id]
        mapped_benchmark = target["mapped_benchmark"]
        benchmark = benchmarks[mapped_benchmark]
        expected_finding = benchmark["expected_findings"][0]
        endpoint_url = canonicalize_endpoint_url(target["target_url"], target["endpoint_path"])
        expected_methods = normalize_methods(target.get("methods"))
        score.per_benchmark[target_id] = {
            "name": target["name"],
            "expected": 1,
            "detected": 0,
            "findings": [],
        }
        expected_units.append(
            (
                target_id,
                endpoint_url,
                target["surface_kind"],
                expected_finding["category"],
                _normalize_phase03_algorithm(
                    expected_finding["category"], expected_finding.get("algorithm", "")
                ),
                expected_methods,
                expected_finding.get("min_confidence", 0.5),
            )
        )

    score.total_expected = len(expected_units)

    allowed_endpoint_urls = {
        canonicalize_endpoint_url(
            targets[target_id]["target_url"],
            targets[target_id]["endpoint_path"],
        )
        for target_id in selected_target_ids
    }
    allowed_endpoint_urls.update(
        canonicalize_endpoint_url(
            negative_controls[nc_id]["target_url"],
            negative_controls[nc_id]["endpoint_path"],
        )
        for nc_id in selected_negative_control_ids
    )

    in_scope_categories = set(contract.get("suite_categories", []))
    all_classifications: list[dict[str, Any]] = []
    for report in reports:
        for classification in report.get("classifications", []):
            if (
                classification.get("endpoint_url") in allowed_endpoint_urls
                and classification.get("category") in in_scope_categories
            ):
                all_classifications.append(classification)
    score.total_detected = len(all_classifications)

    matched_ids: set[str] = set()
    duplicate_ids: set[str] = set()
    ttfc_values: list[float] = []
    budget_reports = 0
    budget_compliant_reports = 0
    inconclusive_reports = 0

    for (
        target_id,
        endpoint_url,
        surface_kind,
        category,
        algorithm,
        expected_methods,
        min_confidence,
    ) in expected_units:
        candidates = []
        for classification in all_classifications:
            if classification.get("id") in matched_ids:
                continue
            if classification.get("endpoint_url") != endpoint_url:
                continue
            if classification.get("surface_kind") != surface_kind:
                continue
            if classification.get("category") != category:
                continue
            normalized_algorithm = _normalize_phase03_algorithm(
                category, classification.get("algorithm", "")
            )
            if normalized_algorithm != algorithm:
                continue
            observed_methods = normalize_methods(classification.get("methods", []))
            if expected_methods and not set(observed_methods).intersection(expected_methods):
                continue
            if not _phase03_classification_evidence_valid(
                classification, contract, category, algorithm
            ):
                continue
            candidates.append(classification)

        candidates.sort(
            key=lambda item: (
                -float(item.get("confidence", 0.0)),
                item.get("id", ""),
            )
        )

        if candidates:
            chosen = candidates[0]
            matched_ids.add(chosen["id"])
            for duplicate in candidates[1:]:
                duplicate_ids.add(duplicate["id"])
            score.true_positives += 1
            score.per_benchmark[target_id]["detected"] += 1
            score.confidence_calibration.append(
                {
                    "benchmark": target_id,
                    "expected_min": min_confidence,
                    "actual": chosen.get("confidence", 0.0),
                    "meets_threshold": chosen.get("confidence", 0.0) >= min_confidence,
                }
            )
            score.benchmark_verdicts.append(
                {
                    "benchmark_id": target_id,
                    "endpoint_url": endpoint_url,
                    "status": "matched",
                    "category": category,
                    "algorithm": algorithm,
                }
            )
            score.matches.append(
                MatchResult(
                    benchmark_id=target_id,
                    expected_category=category,
                    expected_algorithm=algorithm,
                    matched=True,
                    matched_finding_id=chosen.get("id"),
                    matched_confidence=chosen.get("confidence", 0.0),
                    expected_min_confidence=min_confidence,
                )
            )
        else:
            score.false_negatives += 1
            score.benchmark_verdicts.append(
                {
                    "benchmark_id": target_id,
                    "endpoint_url": endpoint_url,
                    "status": "missed",
                    "category": category,
                    "algorithm": algorithm,
                }
            )
            score.matches.append(
                MatchResult(
                    benchmark_id=target_id,
                    expected_category=category,
                    expected_algorithm=algorithm,
                    matched=False,
                    expected_min_confidence=min_confidence,
                    notes="Not classified",
                )
            )

    for classification in all_classifications:
        classification_id = classification.get("id", "")
        if classification_id in matched_ids:
            continue
        score.false_positives += 1
        if classification_id in duplicate_ids:
            score.duplicate_false_positives += 1
        score.false_positive_findings.append(classification)

    for target_id in selected_target_ids:
        mapped_benchmark = targets[target_id]["mapped_benchmark"]
        for channel in benchmarks[mapped_benchmark].get("detection_channels", []):
            if channel not in score.per_channel:
                score.per_channel[channel] = {"expected": 0, "detected": 0}
            score.per_channel[channel]["expected"] += 1
            score.per_channel[channel]["detected"] += score.per_benchmark[target_id]["detected"]

    for report in reports:
        request_accounting = report.get("request_accounting", {})
        if request_accounting:
            budget_reports += 1
            if request_accounting.get("budget_compliant"):
                budget_compliant_reports += 1
        if any(
            verdict.get("status") == "inconclusive"
            for verdict in report.get("benchmark_verdicts", [])
        ):
            inconclusive_reports += 1
        ttfc = report.get("summary", {}).get("time_to_first_classification_seconds")
        if isinstance(ttfc, (int, float)):
            ttfc_values.append(float(ttfc))

    score.budget_compliance_rate = (
        budget_compliant_reports / budget_reports if budget_reports else 0.0
    )
    score.inconclusive_rate = inconclusive_reports / len(reports) if reports else 0.0
    score.mean_time_to_first_classification_seconds = (
        sum(ttfc_values) / len(ttfc_values) if ttfc_values else 0.0
    )

    for nc_id in selected_negative_control_ids:
        nc_def = negative_controls[nc_id]
        endpoint_url = canonicalize_endpoint_url(nc_def["target_url"], nc_def["endpoint_path"])
        classified = any(
            classification.get("endpoint_url") == endpoint_url
            for classification in all_classifications
        )
        passed = not classified
        score.negative_control_results.append(
            {
                "id": nc_id,
                "name": nc_def["name"],
                "passed": passed,
                "endpoint_url": endpoint_url,
            }
        )
        if passed:
            score.true_negatives += 1

    return score


def score_phase01_reports(
    reports: list[dict[str, Any]],
    ground_truth_path: str = "benchmarks/ground_truth.yaml",
    benchmark_ids: list[str] | None = None,
    negative_control_ids: list[str] | None = None,
) -> BenchmarkScore:
    """Score phase01 target reports against the phase01 contract."""
    gt = load_ground_truth(ground_truth_path)
    contract = gt.get("phase01_contract", {})
    suite = gt.get("benchmark_suites", {}).get("phase01", {})
    benchmarks = gt.get("benchmarks", {})
    negative_controls = gt.get("negative_controls", {})
    in_scope_categories = _phase01_in_scope_categories(contract)

    score = BenchmarkScore()
    score.phase01_reports = reports

    expected_units: list[tuple[str, str, str, str, float]] = []
    selected_benchmark_ids = benchmark_ids or list(suite.get("benchmark_ids", []))
    selected_negative_control_ids = negative_control_ids or list(
        suite.get("negative_control_ids", [])
    )

    for benchmark_id in selected_benchmark_ids:
        benchmark = benchmarks[benchmark_id]
        target_url = canonicalize_https_url(benchmark["target_url"])
        score.per_benchmark[benchmark_id] = {
            "name": benchmark["name"],
            "expected": len(benchmark.get("expected_findings", [])),
            "detected": 0,
            "findings": [],
        }
        for expected in benchmark.get("expected_findings", []):
            expected_units.append(
                (
                    benchmark_id,
                    target_url,
                    expected["category"],
                    _normalize_phase01_algorithm(
                        expected["category"], expected.get("algorithm", "")
                    ),
                    expected.get("min_confidence", 0.5),
                )
            )
    score.total_expected = len(expected_units)

    canonical_reports = {
        canonicalize_https_url(report["execution"]["canonical_target"]): report
        for report in reports
    }
    all_findings: list[dict[str, Any]] = []
    for report in reports:
        all_findings.extend(report.get("findings", []))

    in_scope_findings = [
        finding for finding in all_findings if finding.get("category") in in_scope_categories
    ]
    score.total_detected = len(in_scope_findings)

    matched_ids: set[str] = set()
    duplicate_ids: set[str] = set()

    for benchmark_id, target_url, category, algorithm, min_confidence in expected_units:
        candidates = []
        for finding in in_scope_findings:
            if finding.get("id") in matched_ids:
                continue
            if _finding_target(finding) != target_url:
                continue
            if finding.get("category") != category:
                continue
            if _normalize_phase01_algorithm(category, finding.get("algorithm", "")) != algorithm:
                continue
            if finding.get("detection_channel") not in {"RECON", "CH1:TLS_HANDSHAKE"}:
                continue
            if not _evidence_valid(finding, contract, category, algorithm):
                continue
            candidates.append(finding)

        candidates.sort(
            key=lambda finding: (
                -float(finding.get("confidence", 0.0)),
                str(finding.get("id", "")),
            )
        )

        if candidates:
            chosen = candidates[0]
            matched_ids.add(chosen["id"])
            for duplicate in candidates[1:]:
                duplicate_ids.add(duplicate["id"])
            score.true_positives += 1
            score.per_benchmark[benchmark_id]["detected"] += 1
            score.confidence_calibration.append(
                {
                    "benchmark": benchmark_id,
                    "expected_min": min_confidence,
                    "actual": chosen.get("confidence", 0.0),
                    "meets_threshold": chosen.get("confidence", 0.0) >= min_confidence,
                }
            )
            score.matches.append(
                MatchResult(
                    benchmark_id=benchmark_id,
                    expected_category=category,
                    expected_algorithm=algorithm,
                    matched=True,
                    matched_finding_id=chosen.get("id"),
                    matched_confidence=chosen.get("confidence", 0.0),
                    expected_min_confidence=min_confidence,
                )
            )
        else:
            score.false_negatives += 1
            score.matches.append(
                MatchResult(
                    benchmark_id=benchmark_id,
                    expected_category=category,
                    expected_algorithm=algorithm,
                    matched=False,
                    expected_min_confidence=min_confidence,
                    notes="Not detected",
                )
            )

    for benchmark_id in selected_benchmark_ids:
        for channel in benchmarks[benchmark_id].get("detection_channels", []):
            if channel not in score.per_channel:
                score.per_channel[channel] = {"expected": 0, "detected": 0}
            score.per_channel[channel]["expected"] += score.per_benchmark[benchmark_id]["expected"]
            score.per_channel[channel]["detected"] += score.per_benchmark[benchmark_id]["detected"]

    for finding in in_scope_findings:
        finding_id = finding.get("id", "")
        if finding_id in matched_ids:
            continue
        score.false_positives += 1
        if finding_id in duplicate_ids:
            score.duplicate_false_positives += 1
        score.false_positive_findings.append(finding)

    grade_targets: list[tuple[str, str, str]] = []
    if "BM-09" in selected_benchmark_ids:
        grade_targets.append(
            (
                "BM-09",
                canonicalize_https_url(benchmarks["BM-09"]["target_url"]),
                benchmarks["BM-09"]["expected_ssl_labs_grade"],
            )
        )
    for nc_id in selected_negative_control_ids:
        nc_def = negative_controls[nc_id]
        grade_targets.append(
            (nc_id, canonicalize_https_url(nc_def["target_url"]), nc_def["expected_ssl_labs_grade"])
        )

    grade_matches = 0
    assessed_grade_targets = 0
    for benchmark_id, target_url, expected_grade in grade_targets:
        report = canonical_reports.get(target_url)
        if report is None:
            continue
        observed_grade = _phase01_grade_from_report(report)
        if observed_grade is None:
            continue
        assessed_grade_targets += 1
        if observed_grade == expected_grade:
            grade_matches += 1
        score.benchmark_verdicts.append(
            {
                "benchmark_id": benchmark_id,
                "target_url": target_url,
                "expected_grade": expected_grade,
                "observed_grade": observed_grade,
                "status": "matched" if observed_grade == expected_grade else "missed",
            }
        )
    score.ssl_grade_accuracy = (
        grade_matches / assessed_grade_targets if assessed_grade_targets else 0.0
    )

    budget_reports = 0
    budget_compliant = 0
    inconclusive = 0
    for report in reports:
        request_accounting = report.get("request_accounting", {})
        if request_accounting:
            budget_reports += 1
            if request_accounting.get("budget_compliant"):
                budget_compliant += 1
        if any(
            verdict.get("status") == "inconclusive"
            for verdict in report.get("benchmark_verdicts", [])
        ):
            inconclusive += 1
        score.benchmark_verdicts.extend(report.get("benchmark_verdicts", []))

    score.budget_compliance_rate = budget_compliant / budget_reports if budget_reports else 0.0
    score.inconclusive_rate = inconclusive / len(reports) if reports else 0.0

    for nc_id in selected_negative_control_ids:
        nc_def = negative_controls[nc_id]
        target_url = canonicalize_https_url(nc_def["target_url"])
        has_finding = any(_finding_target(finding) == target_url for finding in in_scope_findings)
        expected_grade = nc_def.get("expected_ssl_labs_grade")
        observed_grade = _phase01_grade_from_report(canonical_reports.get(target_url, {}))
        passed = not has_finding and observed_grade == expected_grade
        score.negative_control_results.append(
            {
                "id": nc_id,
                "name": nc_def["name"],
                "passed": passed,
                "observed_grade": observed_grade,
                "expected_grade": expected_grade,
            }
        )
        if passed:
            score.true_negatives += 1

    return score


def score_findings(
    findings: list[dict[str, Any]],
    ground_truth_path: str = "benchmarks/ground_truth.yaml",
    benchmark_ids: list[str] | None = None,
    negative_control_ids: list[str] | None = None,
) -> BenchmarkScore:
    """Score bbci findings against ground truth.

    Args:
        findings: List of finding dicts from bbci scan.
        ground_truth_path: Path to ground truth YAML.

    Returns:
        BenchmarkScore with precision/recall/F1 metrics.
    """
    gt = load_ground_truth(ground_truth_path)
    benchmarks = gt.get("benchmarks", {})
    negative_controls = gt.get("negative_controls", {})

    if benchmark_ids is not None:
        allowed = set(benchmark_ids)
        benchmarks = {k: v for k, v in benchmarks.items() if k in allowed}

    if negative_control_ids is not None:
        allowed_nc = set(negative_control_ids)
        negative_controls = {k: v for k, v in negative_controls.items() if k in allowed_nc}

    score = BenchmarkScore()

    # Count total expected findings
    for bm_id, bm in benchmarks.items():
        expected = bm.get("expected_findings", [])
        score.total_expected += len(expected)

    score.total_detected = len(findings)

    # Track which findings have been matched
    matched_finding_ids: set[str] = set()

    # Match findings to ground truth
    for bm_id, bm in benchmarks.items():
        bm_results: dict[str, Any] = {
            "name": bm["name"],
            "expected": len(bm.get("expected_findings", [])),
            "detected": 0,
            "findings": [],
        }

        for expected in bm.get("expected_findings", []):
            exp_cat = expected["category"]
            exp_alg = expected.get("algorithm", "")
            exp_min_conf = expected.get("min_confidence", 0.5)

            # Find a matching finding
            best_match = None
            best_confidence = 0.0

            for f in findings:
                f_id = f.get("id", "")
                if f_id in matched_finding_ids:
                    continue

                f_cat = f.get("category", "")
                f_conf = f.get("confidence", 0.0)

                # Category must match
                if f_cat == exp_cat:
                    if f_conf > best_confidence:
                        best_match = f
                        best_confidence = f_conf

            if best_match:
                matched_finding_ids.add(best_match.get("id", ""))
                score.true_positives += 1
                bm_results["detected"] += 1

                match = MatchResult(
                    benchmark_id=bm_id,
                    expected_category=exp_cat,
                    expected_algorithm=exp_alg,
                    matched=True,
                    matched_finding_id=best_match.get("id"),
                    matched_confidence=best_confidence,
                    expected_min_confidence=exp_min_conf,
                )
                score.matches.append(match)

                # Confidence calibration
                score.confidence_calibration.append(
                    {
                        "benchmark": bm_id,
                        "expected_min": exp_min_conf,
                        "actual": best_confidence,
                        "meets_threshold": best_confidence >= exp_min_conf,
                    }
                )
            else:
                score.false_negatives += 1
                match = MatchResult(
                    benchmark_id=bm_id,
                    expected_category=exp_cat,
                    expected_algorithm=exp_alg,
                    matched=False,
                    notes="Not detected",
                )
                score.matches.append(match)

        score.per_benchmark[bm_id] = bm_results

        # Track per-channel stats
        for ch in bm.get("detection_channels", []):
            if ch not in score.per_channel:
                score.per_channel[ch] = {"expected": 0, "detected": 0}
            score.per_channel[ch]["expected"] += bm_results["expected"]
            score.per_channel[ch]["detected"] += bm_results["detected"]

    # Count false positives (findings that don't match any ground truth)
    for f in findings:
        if f.get("id", "") not in matched_finding_ids:
            score.false_positives += 1
            score.false_positive_findings.append(f)

    # Evaluate negative controls
    for nc_id, nc in negative_controls.items():
        nc_endpoint = nc.get("endpoint", "")
        # Check if any finding references this endpoint
        has_finding = any(
            nc_endpoint in f.get("endpoint", "") or nc_endpoint in str(f.get("evidence", {}))
            for f in findings
        )

        result = {
            "id": nc_id,
            "name": nc["name"],
            "passed": not has_finding,
        }
        score.negative_control_results.append(result)
        if not has_finding:
            score.true_negatives += 1

    return score
