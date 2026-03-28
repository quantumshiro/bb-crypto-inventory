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


# ============================================================
# SSL Labs Rating Guide v2009r scoring
# ============================================================

# Protocol scores per SSL Labs guide
SSL_LABS_PROTOCOL_SCORES: dict[str, int] = {
    "SSLv2": 0,
    "SSLv3": 80,
    "TLSv1.0": 90,
    "TLSv1.1": 95,
    "TLSv1.2": 100,
    "TLSv1.3": 100,
}

# Cipher strength scores (bits -> score)
def _cipher_strength_score(bits: int) -> int:
    """Score cipher strength per SSL Labs guide."""
    if bits == 0:
        return 0
    elif bits < 128:
        return 20
    elif bits < 256:
        return 80
    else:
        return 100


def compute_ssl_labs_grade(
    supported_protocols: list[str],
    cipher_suites: list[dict],
    has_pfs: bool = False,
    has_rc4: bool = False,
    has_3des: bool = False,
    key_exchange_bits: int = 2048,
) -> dict[str, Any]:
    """Compute SSL Labs-style grade from TLS scan results.

    Follows Qualys SSL Labs Rating Guide v2009r:
    - Protocol support: 30%
    - Key exchange: 30%
    - Cipher strength: 40%
    - Grade caps for specific weaknesses

    Returns dict with score, grade, and breakdown.
    """
    # Protocol score (average of best and worst)
    proto_scores = [
        SSL_LABS_PROTOCOL_SCORES.get(p, 50)
        for p in supported_protocols
    ]
    if proto_scores:
        protocol_score = (max(proto_scores) + min(proto_scores)) / 2
    else:
        protocol_score = 0

    # Key exchange score
    if key_exchange_bits >= 4096:
        kx_score = 100
    elif key_exchange_bits >= 2048:
        kx_score = 90
    elif key_exchange_bits >= 1024:
        kx_score = 80
    elif key_exchange_bits >= 512:
        kx_score = 40
    else:
        kx_score = 20

    # Cipher strength score (average of strongest and weakest)
    cipher_bits = [s.get("bits", 128) for s in cipher_suites] if cipher_suites else [128]
    if cipher_bits:
        strongest = _cipher_strength_score(max(cipher_bits))
        weakest = _cipher_strength_score(min(cipher_bits))
        cipher_score = (strongest + weakest) / 2
    else:
        cipher_score = 0

    # Combined score (30/30/40 weighting)
    overall = (protocol_score * 0.30 + kx_score * 0.30 + cipher_score * 0.40)

    # Determine base grade
    if overall >= 80:
        grade = "A"
    elif overall >= 65:
        grade = "B"
    elif overall >= 50:
        grade = "C"
    elif overall >= 35:
        grade = "D"
    elif overall >= 20:
        grade = "E"
    else:
        grade = "F"

    # Grade caps per SSL Labs rules
    caps_applied = []

    if "SSLv2" in supported_protocols:
        grade = "F"
        caps_applied.append("SSLv2 → F")
    if "SSLv3" in supported_protocols and grade < "C":
        grade = max(grade, "C")
        caps_applied.append("SSLv3 → max B")
    if has_rc4 and grade < "C":
        grade = "C"
        caps_applied.append("RC4 → max C")
    if has_3des and grade < "C":
        grade = "C"
        caps_applied.append("3DES (64-bit block) → max C")
    if not has_pfs and grade < "B":
        grade = "B"
        caps_applied.append("No PFS → max B")
    if any(p in supported_protocols for p in ["TLSv1.0", "TLSv1.1"]):
        if grade == "A":
            grade = "B"
            caps_applied.append("TLS 1.0/1.1 → max B")

    return {
        "overall_score": round(overall, 1),
        "grade": grade,
        "protocol_score": round(protocol_score, 1),
        "key_exchange_score": round(kx_score, 1),
        "cipher_strength_score": round(cipher_score, 1),
        "caps_applied": caps_applied,
        "methodology": "Qualys SSL Labs Rating Guide v2009r",
    }


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
