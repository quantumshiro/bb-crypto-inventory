"""Scoring engine for benchmark evaluation.

Computes precision, recall, F1, and confidence calibration
by comparing bbci findings against ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml


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

    matches: list[MatchResult] = field(default_factory=list)
    false_positive_findings: list[dict] = field(default_factory=list)
    negative_control_results: list[dict] = field(default_factory=list)

    per_benchmark: dict[str, dict[str, Any]] = field(default_factory=dict)
    per_channel: dict[str, dict[str, Any]] = field(default_factory=dict)

    confidence_calibration: list[dict] = field(default_factory=list)

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
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "total_expected": self.total_expected,
            "total_detected": self.total_detected,
            "per_benchmark": self.per_benchmark,
            "per_channel": self.per_channel,
            "confidence_calibration": self.confidence_calibration,
        }


def load_ground_truth(path: str = "benchmarks/ground_truth.yaml") -> dict:
    """Load ground truth from YAML file."""
    with open(path) as f:
        return yaml.safe_load(f)


def score_findings(
    findings: list[dict[str, Any]],
    ground_truth_path: str = "benchmarks/ground_truth.yaml",
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
                score.confidence_calibration.append({
                    "benchmark": bm_id,
                    "expected_min": exp_min_conf,
                    "actual": best_confidence,
                    "meets_threshold": best_confidence >= exp_min_conf,
                })
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
