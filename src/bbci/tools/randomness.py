"""CH6: Small-sample randomness quality assessment.

Implements the tiered approach described in docs/07-small-sample-randomness.md:
- Tier 1 (N=50-100):  Pattern detection (diff analysis, permutation entropy)
- Tier 2 (N=100-500): Statistical tests (SHR entropy, Anderson-Darling, χ², collision)
- Tier 3 (N=500-2000): High-precision (SPRT, min-entropy estimation, Maurer's test)
"""

from __future__ import annotations

import base64
import logging
import math
import statistics
from collections import Counter
from dataclasses import dataclass, field
from itertools import permutations
from typing import Any

from bbci.tools.common import ToolResult, timed

logger = logging.getLogger("bbci")


# ---------------------------------------------------------------------------
# Data conversion helpers
# ---------------------------------------------------------------------------

def _samples_to_integers(samples: list[str]) -> list[int]:
    """Convert hex/base64/utf-8 token strings to integers."""
    integers: list[int] = []
    for s in samples:
        raw = _decode_sample(s)
        if raw:
            integers.append(int.from_bytes(raw, "big"))
    return integers


def _samples_to_bytes(samples: list[str]) -> list[bytes]:
    """Convert token strings to raw byte sequences."""
    result: list[bytes] = []
    for s in samples:
        raw = _decode_sample(s)
        if raw:
            result.append(raw)
    return result


def _decode_sample(s: str) -> bytes | None:
    """Decode a single sample string (hex, base64, or UTF-8 fallback)."""
    s = s.strip()
    if not s:
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        pass
    try:
        return base64.b64decode(s + "==")
    except Exception:
        pass
    return s.encode("utf-8")


# ---------------------------------------------------------------------------
# Tier 1: Immediate detection (N = 50-100)
# ---------------------------------------------------------------------------

def tier1_diff_analysis(integers: list[int]) -> dict[str, Any]:
    """Detect sequential/timestamp/LCG patterns via difference analysis.

    Checks:
    - Constant differences → sequential/counter IDs
    - Differences clustered around time-like values → timestamp-based
    - Periodic difference patterns → LCG low-bit issues
    """
    if len(integers) < 3:
        return {"skipped": True, "reason": "Need at least 3 samples"}

    diffs = [integers[i] - integers[i - 1] for i in range(1, len(integers))]

    # 1. Sequential / counter detection
    unique_diffs = len(set(diffs))
    is_sequential = unique_diffs <= 3 and len(diffs) >= 5

    # 2. Constant increment detection
    diff_counter = Counter(diffs)
    most_common_diff, most_common_count = diff_counter.most_common(1)[0]
    constant_ratio = most_common_count / len(diffs)

    # 3. Timestamp-based detection: diffs in typical ms/μs ranges
    abs_diffs = [abs(d) for d in diffs]
    median_diff = statistics.median(abs_diffs) if abs_diffs else 0
    # Typical patterns: ms-resolution timestamps → diffs ~1-1000
    # μs-resolution → diffs ~1000-1_000_000
    timestamp_like = (
        len(abs_diffs) > 5
        and 0 < median_diff < 10_000_000
        and statistics.stdev(abs_diffs) / (median_diff + 1) < 2.0  # low relative variance
    )

    # 4. LCG low-bit periodicity: check low N bits for short period
    lcg_detected = False
    lcg_period = None
    for mask_bits in (8, 16):
        mask = (1 << mask_bits) - 1
        low_bits = [v & mask for v in integers]
        low_diffs = [(low_bits[i] - low_bits[i - 1]) & mask for i in range(1, len(low_bits))]
        # Check for short period in low-bit diffs
        for period in range(1, min(len(low_diffs) // 3, 64)):
            matches = sum(
                1 for i in range(period, len(low_diffs))
                if low_diffs[i] == low_diffs[i - period]
            )
            if matches / (len(low_diffs) - period) > 0.9:
                lcg_detected = True
                lcg_period = period
                break
        if lcg_detected:
            break

    passed = not (is_sequential or timestamp_like or lcg_detected)
    issues: list[str] = []
    if is_sequential:
        issues.append(f"sequential_counter (constant diff ≈ {most_common_diff})")
    if timestamp_like:
        issues.append(f"timestamp_based (median_diff={median_diff:.0f})")
    if lcg_detected:
        issues.append(f"lcg_periodicity (period={lcg_period})")

    return {
        "test": "diff_analysis",
        "pass": passed,
        "sample_count": len(integers),
        "unique_diffs": unique_diffs,
        "constant_diff_ratio": round(constant_ratio, 4),
        "most_common_diff": most_common_diff,
        "is_sequential": is_sequential,
        "timestamp_like": timestamp_like,
        "lcg_detected": lcg_detected,
        "lcg_period": lcg_period,
        "issues": issues,
        "sample_diffs": diffs[:10],
    }


def tier1_permutation_entropy(integers: list[int], m: int = 3) -> dict[str, Any]:
    """Compute permutation entropy of the token value time series.

    Args:
        integers: List of token integer values in temporal order.
        m: Embedding dimension (order). m=3 gives 6 patterns, m=4 gives 24.
    """
    n = len(integers)
    if n < m + 10:
        return {"skipped": True, "reason": f"Need at least {m + 10} samples for m={m}"}

    # Extract ordinal patterns
    pattern_counts: Counter[tuple[int, ...]] = Counter()
    for i in range(n - m + 1):
        window = integers[i : i + m]
        # Rank the values: which position has 1st smallest, 2nd, etc.
        indexed = sorted(range(m), key=lambda k: window[k])
        pattern = tuple(indexed)
        pattern_counts[pattern] += 1

    total_patterns = sum(pattern_counts.values())
    max_entropy = math.log2(math.factorial(m))  # log2(m!)

    # Shannon entropy of the pattern distribution
    pe = 0.0
    for count in pattern_counts.values():
        p = count / total_patterns
        if p > 0:
            pe -= p * math.log2(p)

    # Normalized PE: 1.0 = perfectly random, 0.0 = perfectly deterministic
    npe = pe / max_entropy if max_entropy > 0 else 0.0

    # Threshold: NPE < 0.9 is suspicious, < 0.7 is clearly non-random
    passed = npe >= 0.9

    return {
        "test": "permutation_entropy",
        "pass": passed,
        "embedding_dim": m,
        "permutation_entropy": round(pe, 4),
        "normalized_pe": round(npe, 4),
        "max_entropy": round(max_entropy, 4),
        "unique_patterns": len(pattern_counts),
        "possible_patterns": math.factorial(m),
        "total_windows": total_patterns,
        "assessment": (
            "good" if npe >= 0.95
            else "acceptable" if npe >= 0.9
            else "suspicious" if npe >= 0.7
            else "non_random"
        ),
    }


# ---------------------------------------------------------------------------
# Tier 2: Statistical detection (N = 100-500)
# ---------------------------------------------------------------------------

def tier2_shr_entropy(byte_sequences: list[bytes]) -> dict[str, Any]:
    """Shrinkage (James-Stein) entropy estimator for byte distribution.

    The SHR estimator has the least bias for short byte sequences among
    18 compared estimators (Marcon et al. 2021).
    """
    all_bytes = b"".join(byte_sequences)
    n = len(all_bytes)
    if n < 10:
        return {"skipped": True, "reason": "Need at least 10 bytes"}

    k = 256  # alphabet size for bytes

    # Empirical frequencies
    counts = Counter(all_bytes)
    freqs = [counts.get(i, 0) / n for i in range(k)]

    # Target (uniform) distribution
    target = 1.0 / k

    # James-Stein shrinkage intensity
    # λ = (1 - Σ p_i²) / ((n-1) * Σ (1/k - p_i)²)
    sum_sq = sum(f * f for f in freqs)
    sum_dev_sq = sum((target - f) ** 2 for f in freqs)

    if sum_dev_sq == 0:
        # Already perfectly uniform
        lam = 1.0
    else:
        lam = (1.0 - sum_sq) / ((n - 1) * sum_dev_sq)
    lam = max(0.0, min(1.0, lam))  # Clip to [0, 1]

    # Shrinkage estimate: p_i^shr = λ/k + (1-λ)*f_i
    shrunk = [lam * target + (1 - lam) * f for f in freqs]

    # Plugin entropy
    entropy = -sum(p * math.log2(p) for p in shrunk if p > 0)
    max_entropy = math.log2(k)  # 8.0 for bytes
    normalized = entropy / max_entropy

    passed = normalized >= 0.95

    return {
        "test": "shr_entropy",
        "pass": passed,
        "entropy_bits": round(entropy, 4),
        "max_entropy_bits": max_entropy,
        "normalized_entropy": round(normalized, 4),
        "shrinkage_lambda": round(lam, 4),
        "total_bytes": n,
        "unique_byte_values": len(counts),
        "assessment": (
            "full_entropy" if normalized >= 0.99
            else "good" if normalized >= 0.95
            else "suspicious" if normalized >= 0.85
            else "weak"
        ),
    }


def tier2_anderson_darling(integers: list[int], bit_length: int | None = None) -> dict[str, Any]:
    """Anderson-Darling test for uniformity.

    More sensitive to tail deviations than Kolmogorov-Smirnov.
    """
    n = len(integers)
    if n < 10:
        return {"skipped": True, "reason": "Need at least 10 samples"}

    # Determine range for normalization
    if bit_length is None:
        # Estimate from max value
        max_val = max(integers)
        bit_length = max_val.bit_length() if max_val > 0 else 8
        # Round up to nearest byte
        bit_length = ((bit_length + 7) // 8) * 8

    range_max = (1 << bit_length) - 1
    if range_max == 0:
        return {"skipped": True, "reason": "All values are zero"}

    # Normalize to [0, 1] and sort
    u = sorted(v / range_max for v in integers)

    # Compute A² statistic
    a_sq = -n
    for i in range(n):
        ui = max(1e-15, min(1 - 1e-15, u[i]))  # Avoid log(0)
        a_sq -= (1.0 / n) * (
            (2 * (i + 1) - 1) * math.log(ui)
            + (2 * n - 2 * (i + 1) + 1) * math.log(1.0 - ui)
        )

    # Adjusted statistic for finite sample
    a_sq_star = a_sq * (1.0 + 0.75 / n + 2.25 / (n * n))

    # Critical values for uniform distribution (significance levels)
    # At α=0.05: 2.492, α=0.01: 3.857
    critical_005 = 2.492
    critical_001 = 3.857

    passed = a_sq_star < critical_005

    return {
        "test": "anderson_darling",
        "pass": passed,
        "statistic_A2": round(a_sq, 4),
        "adjusted_A2_star": round(a_sq_star, 4),
        "critical_005": critical_005,
        "critical_001": critical_001,
        "significance": (
            "pass" if a_sq_star < critical_005
            else "reject_005" if a_sq_star < critical_001
            else "reject_001"
        ),
        "sample_count": n,
        "assumed_bit_length": bit_length,
    }


def tier2_chi_square(byte_sequences: list[bytes]) -> dict[str, Any]:
    """Chi-square test for byte frequency uniformity."""
    all_bytes = b"".join(byte_sequences)
    n = len(all_bytes)
    if n < 256:
        return {"skipped": True, "reason": f"Need at least 256 bytes, got {n}"}

    expected = n / 256.0
    counts = Counter(all_bytes)
    chi_sq = sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(256))

    # Chi-square critical values for df=255
    # α=0.05: 293.25, α=0.01: 310.46, α=0.001: 330.52
    # Use α=0.01 to reduce false positives with small sample sizes
    critical_001 = 310.46
    critical_005 = 293.25

    passed = chi_sq < critical_001

    return {
        "test": "chi_square_bytes",
        "pass": passed,
        "chi_square": round(chi_sq, 2),
        "degrees_of_freedom": 255,
        "expected_per_byte": round(expected, 2),
        "critical_005": critical_005,
        "critical_001": critical_001,
        "total_bytes": n,
        "unique_byte_values": len(counts),
        "assessment": (
            "pass" if chi_sq < critical_005
            else "marginal" if chi_sq < critical_001
            else "fail"
        ),
    }


def tier2_collision_test(integers: list[int], bit_length: int | None = None) -> dict[str, Any]:
    """Collision test: check if identical values appear more than expected.

    For truly random N values from a space of size 2^b, expected collisions
    follow the birthday problem: E[C] ≈ N²/(2·2^b).
    """
    n = len(integers)
    if n < 20:
        return {"skipped": True, "reason": "Need at least 20 samples"}

    # Detect bit length from data
    if bit_length is None:
        max_val = max(integers) if integers else 0
        bit_length = max_val.bit_length() if max_val > 0 else 8
        bit_length = ((bit_length + 7) // 8) * 8

    space_size = 2 ** bit_length

    # Count collisions
    seen: Counter[int] = Counter(integers)
    collisions = sum(c - 1 for c in seen.values() if c > 1)
    unique = len(seen)

    # Expected collisions: E[C] ≈ N(N-1) / (2 · 2^b)
    expected_collisions = n * (n - 1) / (2 * space_size) if space_size > 0 else float("inf")

    # If space is huge (e.g., 128-bit), expected collisions ≈ 0
    # Any collision is suspicious
    if bit_length >= 64:
        passed = collisions == 0
    else:
        # For smaller spaces, use statistical test
        # Poisson approximation: P(C > k) where C ~ Poisson(λ=expected)
        passed = collisions <= max(3 * expected_collisions, 1)

    return {
        "test": "collision",
        "pass": passed,
        "collisions": collisions,
        "expected_collisions": round(expected_collisions, 4),
        "unique_values": unique,
        "total_samples": n,
        "assumed_bit_length": bit_length,
        "space_size_log2": bit_length,
        "assessment": (
            "pass" if passed
            else "suspicious_small_space" if collisions > 0 and bit_length >= 64
            else "excessive_collisions"
        ),
    }


# ---------------------------------------------------------------------------
# Tier 3: High-precision evaluation (N = 500-2000)
# ---------------------------------------------------------------------------

def tier3_sprt(
    byte_sequences: list[bytes],
    alpha: float = 0.01,
    beta: float = 0.01,
) -> dict[str, Any]:
    """Sequential Probability Ratio Test for randomness.

    Tests H0: bytes are drawn from uniform distribution (p=1/256 per byte)
    vs H1: bytes are biased (most common byte has p > 1/256).

    Uses per-byte log-likelihood ratio with a concrete alternative model.

    Args:
        byte_sequences: Token byte sequences in order of collection.
        alpha: Type I error rate (false positive).
        beta: Type II error rate (false negative).
    """
    if len(byte_sequences) < 10:
        return {"skipped": True, "reason": "Need at least 10 samples"}

    # SPRT boundaries (Wald)
    log_A = math.log(beta / (1 - alpha))       # Accept H0 boundary
    log_B = math.log((1 - beta) / alpha)       # Reject H0 boundary

    # H0: uniform → p0 = 1/256 for each byte
    # H1: biased → most common byte has p1_high, rest share remainder
    # Use a clearly distinguishable alternative: ~5/256 for biased byte
    p0 = 1.0 / 256
    p1_high = 5.0 / 256
    p1_low = (1.0 - p1_high) / 255

    all_bytes = b"".join(byte_sequences)
    n = len(all_bytes)

    if n < 100:
        return {"skipped": True, "reason": f"Need at least 100 bytes, got {n}"}

    # Find the most common byte across all data (used as the "biased" byte)
    counts = Counter(all_bytes)
    biased_byte = counts.most_common(1)[0][0]

    # Compute cumulative LLR
    log_lambda = 0.0
    decision = "inconclusive"
    decision_at = n

    history: list[dict[str, Any]] = []
    checkpoint_interval = max(n // 20, 50)

    for i, b in enumerate(all_bytes):
        if b == biased_byte:
            log_lambda += math.log(p1_high / p0)
        else:
            log_lambda += math.log(p1_low / p0)

        # Check boundaries periodically (not every byte for efficiency)
        if (i + 1) % 16 == 0 or i == n - 1:
            if log_lambda <= log_A:
                decision = "accept_uniform"
                decision_at = i + 1
                break
            elif log_lambda >= log_B:
                decision = "reject_uniform"
                decision_at = i + 1
                break

        if (i + 1) % checkpoint_interval == 0:
            history.append({
                "byte_index": i + 1,
                "log_lambda": round(log_lambda, 4),
            })

    passed = decision != "reject_uniform"

    return {
        "test": "sprt",
        "pass": passed,
        "decision": decision,
        "decision_at_byte": decision_at,
        "total_bytes": n,
        "total_samples": len(byte_sequences),
        "final_log_lambda": round(log_lambda, 4),
        "boundary_log_A": round(log_A, 4),
        "boundary_log_B": round(log_B, 4),
        "alpha": alpha,
        "beta": beta,
        "biased_byte": f"0x{biased_byte:02x}",
        "biased_byte_freq": round(counts[biased_byte] / n, 4),
        "history": history[-5:],
        "early_termination": decision_at < n,
    }


def tier3_min_entropy(byte_sequences: list[bytes]) -> dict[str, Any]:
    """Estimate min-entropy using SP 800-90B inspired estimators.

    Implements:
    1. Most Common Value (MCV) estimator
    2. Collision estimator
    3. Markov predictor (simplified)
    """
    all_bytes = b"".join(byte_sequences)
    n = len(all_bytes)
    if n < 50:
        return {"skipped": True, "reason": "Need at least 50 bytes"}

    counts = Counter(all_bytes)

    # 1. MCV estimator: H_min = -log2(p_max)
    max_count = max(counts.values())
    p_max = max_count / n
    # Upper bound with confidence interval (Wald)
    p_max_upper = min(1.0, p_max + 2.576 * math.sqrt(p_max * (1 - p_max) / n))
    mcv_entropy = -math.log2(p_max_upper)

    # 2. Collision estimator (SP 800-90B style)
    # For byte-level data, expected mean collision distance for uniform:
    # E[distance] ≈ sqrt(π·k/2) where k=256 → ≈ 20.1
    # Min-entropy ≈ -log2(1 / mean_distance) is a rough bound.
    # Instead, use the SP 800-90B approach: compare against expected for uniform.
    collision_sum = 0
    collision_count = 0
    i = 0
    while i < n - 1:
        seen_set: set[int] = set()
        j = i
        while j < n:
            if all_bytes[j] in seen_set:
                collision_sum += j - i + 1
                collision_count += 1
                break
            seen_set.add(all_bytes[j])
            j += 1
        i = j + 1 if j < n else n

    if collision_count > 0:
        mean_collision = collision_sum / collision_count
        # For uniform k=256, expected mean collision distance ≈ sqrt(π·256/2) ≈ 20.1
        expected_collision = math.sqrt(math.pi * 256 / 2)
        # Entropy estimate: scale relative to expected
        collision_ratio = mean_collision / expected_collision
        # If ratio ≈ 1.0, entropy is ~8 bits; if much less, entropy is lower
        collision_entropy = min(8.0, 8.0 * min(collision_ratio, 1.0))
    else:
        collision_entropy = 8.0  # No collisions found = high entropy

    # 3. Lag predictor: try to predict next byte from previous
    # Use train/test split to avoid overfitting
    correct_predictions = 0
    prediction_attempts = 0
    if n >= 200:
        split = n // 2
        train_bytes = all_bytes[:split]
        test_bytes = all_bytes[split:]

        # Build transition model from training set
        transition: dict[int, Counter[int]] = {}
        for i in range(len(train_bytes) - 1):
            curr = train_bytes[i]
            nxt = train_bytes[i + 1]
            if curr not in transition:
                transition[curr] = Counter()
            transition[curr][nxt] += 1

        # Evaluate on test set
        for i in range(len(test_bytes) - 1):
            curr = test_bytes[i]
            nxt = test_bytes[i + 1]
            prediction_attempts += 1
            if curr in transition:
                predicted = transition[curr].most_common(1)[0][0]
                if predicted == nxt:
                    correct_predictions += 1

        prediction_rate = correct_predictions / prediction_attempts if prediction_attempts > 0 else 0.0
        predictor_entropy = -math.log2(max(prediction_rate, 1.0 / 256))
    else:
        prediction_rate = 0.0
        predictor_entropy = 8.0  # Not enough data, assume full entropy

    # Conservative estimate: minimum of all estimators
    min_ent = min(mcv_entropy, collision_entropy, predictor_entropy)
    max_possible = 8.0  # bits per byte

    passed = min_ent >= 6.0  # At least 6 bits of min-entropy per byte

    return {
        "test": "min_entropy",
        "pass": passed,
        "min_entropy_per_byte": round(min_ent, 4),
        "max_possible": max_possible,
        "estimators": {
            "mcv": round(mcv_entropy, 4),
            "collision": round(collision_entropy, 4),
            "lag_predictor": round(predictor_entropy, 4),
        },
        "most_common_byte_freq": round(p_max, 4),
        "prediction_rate": round(prediction_rate, 4) if n >= 2 else None,
        "total_bytes": n,
        "assessment": (
            "full_entropy" if min_ent >= 7.5
            else "good" if min_ent >= 6.0
            else "weak" if min_ent >= 4.0
            else "critically_weak"
        ),
    }


def tier3_maurer_universal(byte_sequences: list[bytes], L: int = 6) -> dict[str, Any]:
    """Maurer's Universal Statistical Test.

    Measures entropy per bit by detecting compressible patterns.

    Args:
        L: Block length in bits. L=6 requires Q≥640 init blocks + K test blocks.
    """
    all_bytes = b"".join(byte_sequences)
    bits = "".join(f"{b:08b}" for b in all_bytes)
    n_bits = len(bits)

    Q = 10 * (2 ** L)  # Initialization segment length
    K_min = 100  # Minimum test blocks
    total_blocks_needed = Q + K_min

    if n_bits // L < total_blocks_needed:
        return {
            "skipped": True,
            "reason": (
                f"Need at least {total_blocks_needed * L} bits "
                f"({total_blocks_needed * L // 8} bytes) for L={L}, "
                f"got {n_bits} bits"
            ),
        }

    n_blocks = n_bits // L
    K = n_blocks - Q  # Test segment length

    # Parse all blocks
    blocks = [int(bits[i * L : (i + 1) * L], 2) for i in range(n_blocks)]

    # Initialization: record last occurrence of each pattern
    last_seen: dict[int, int] = {}
    for i in range(Q):
        last_seen[blocks[i]] = i

    # Test: compute sum of log2(distance)
    total = 0.0
    for i in range(Q, Q + K):
        pattern = blocks[i]
        if pattern in last_seen:
            distance = i - last_seen[pattern]
            total += math.log2(distance)
        last_seen[pattern] = i

    fn = total / K  # Test statistic

    # Expected value and variance for truly random sequences
    # Approximation from Coron & Naccache (1998)
    expected = {
        1: 0.7326495, 2: 1.5374383, 3: 2.4016068, 4: 3.3112247,
        5: 4.2534266, 6: 5.2177052, 7: 6.1962507, 8: 7.1836656,
    }
    variance = {
        1: 0.690, 2: 1.338, 3: 1.901, 4: 2.358,
        5: 2.705, 6: 2.954, 7: 3.125, 8: 3.238,
    }

    if L not in expected:
        return {"skipped": True, "reason": f"L={L} not supported (use 1-8)"}

    mu = expected[L]
    sigma = math.sqrt(variance[L] / K)

    # Z-score
    z = (fn - mu) / sigma if sigma > 0 else 0.0

    # Two-tailed test at α=0.01: |z| < 2.576
    passed = abs(z) < 2.576

    return {
        "test": "maurer_universal",
        "pass": passed,
        "statistic_fn": round(fn, 6),
        "expected_mu": mu,
        "z_score": round(z, 4),
        "block_length_L": L,
        "init_blocks_Q": Q,
        "test_blocks_K": K,
        "total_bits": n_bits,
        "assessment": (
            "pass" if abs(z) < 1.96
            else "marginal" if abs(z) < 2.576
            else "fail"
        ),
    }


# ---------------------------------------------------------------------------
# Integrated runner
# ---------------------------------------------------------------------------

@dataclass
class RandomnessReport:
    """Aggregated report from all tiers."""

    tier1: list[dict[str, Any]] = field(default_factory=list)
    tier2: list[dict[str, Any]] = field(default_factory=list)
    tier3: list[dict[str, Any]] = field(default_factory=list)
    overall_pass: bool = True
    overall_assessment: str = ""
    total_samples: int = 0
    tier_reached: int = 0
    early_termination: bool = False
    failed_tests: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_pass": self.overall_pass,
            "overall_assessment": self.overall_assessment,
            "total_samples": self.total_samples,
            "tier_reached": self.tier_reached,
            "early_termination": self.early_termination,
            "failed_tests": self.failed_tests,
            "tier1_results": self.tier1,
            "tier2_results": self.tier2,
            "tier3_results": self.tier3,
        }


def run_randomness_tests(
    samples: list[str],
    max_tier: int = 2,
    early_stop: bool = True,
) -> RandomnessReport:
    """Run tiered randomness tests on collected token samples.

    Args:
        samples: List of token strings (hex, base64, or raw).
        max_tier: Maximum tier to run (1, 2, or 3).
        early_stop: Stop at lower tier if definitive failure is detected.

    Returns:
        RandomnessReport with results from all executed tiers.
    """
    report = RandomnessReport(total_samples=len(samples))

    integers = _samples_to_integers(samples)
    byte_seqs = _samples_to_bytes(samples)

    if not integers or not byte_seqs:
        report.overall_pass = False
        report.overall_assessment = "ERROR: Could not decode any samples"
        return report

    # Detect bit length for AD and collision tests
    max_val = max(integers) if integers else 0
    bit_length = max_val.bit_length() if max_val > 0 else 8
    bit_length = ((bit_length + 7) // 8) * 8

    # --- Tier 1 ---
    report.tier_reached = 1

    diff_result = tier1_diff_analysis(integers)
    report.tier1.append(diff_result)
    if not diff_result.get("pass", True) and not diff_result.get("skipped"):
        report.failed_tests.append("diff_analysis")

    pe_result = tier1_permutation_entropy(integers)
    report.tier1.append(pe_result)
    if not pe_result.get("pass", True) and not pe_result.get("skipped"):
        report.failed_tests.append("permutation_entropy")

    # Early stop on Tier 1 failure
    if early_stop and report.failed_tests:
        report.overall_pass = False
        report.early_termination = True
        report.overall_assessment = (
            f"WEAK: Tier 1 detected critical issues: {', '.join(report.failed_tests)}"
        )
        return report

    if max_tier < 2 or len(samples) < 50:
        report.overall_assessment = _summarize(report)
        report.overall_pass = len(report.failed_tests) == 0
        return report

    # --- Tier 2 ---
    report.tier_reached = 2

    shr_result = tier2_shr_entropy(byte_seqs)
    report.tier2.append(shr_result)
    if not shr_result.get("pass", True) and not shr_result.get("skipped"):
        report.failed_tests.append("shr_entropy")

    ad_result = tier2_anderson_darling(integers, bit_length)
    report.tier2.append(ad_result)
    if not ad_result.get("pass", True) and not ad_result.get("skipped"):
        report.failed_tests.append("anderson_darling")

    chi_result = tier2_chi_square(byte_seqs)
    report.tier2.append(chi_result)
    if not chi_result.get("pass", True) and not chi_result.get("skipped"):
        report.failed_tests.append("chi_square_bytes")

    collision_result = tier2_collision_test(integers, bit_length)
    report.tier2.append(collision_result)
    if not collision_result.get("pass", True) and not collision_result.get("skipped"):
        report.failed_tests.append("collision")

    # Early stop on Tier 2 failure
    tier2_failures = [
        t for t in report.failed_tests
        if t not in ("diff_analysis", "permutation_entropy")
    ]
    if early_stop and tier2_failures:
        report.overall_pass = False
        report.early_termination = True
        report.overall_assessment = (
            f"WEAK: Tier 2 statistical tests failed: {', '.join(tier2_failures)}"
        )
        return report

    if max_tier < 3 or len(samples) < 200:
        report.overall_assessment = _summarize(report)
        report.overall_pass = len(report.failed_tests) == 0
        return report

    # --- Tier 3 ---
    report.tier_reached = 3

    sprt_result = tier3_sprt(byte_seqs)
    report.tier3.append(sprt_result)
    if not sprt_result.get("pass", True) and not sprt_result.get("skipped"):
        report.failed_tests.append("sprt")

    me_result = tier3_min_entropy(byte_seqs)
    report.tier3.append(me_result)
    if not me_result.get("pass", True) and not me_result.get("skipped"):
        report.failed_tests.append("min_entropy")

    maurer_result = tier3_maurer_universal(byte_seqs)
    report.tier3.append(maurer_result)
    if not maurer_result.get("pass", True) and not maurer_result.get("skipped"):
        report.failed_tests.append("maurer_universal")

    report.overall_pass = len(report.failed_tests) == 0
    report.overall_assessment = _summarize(report)
    return report


def _summarize(report: RandomnessReport) -> str:
    """Generate overall assessment string."""
    if report.failed_tests:
        return f"WEAK RANDOMNESS: Failed {len(report.failed_tests)} test(s): {', '.join(report.failed_tests)}"
    total_run = sum(
        1 for tier in (report.tier1, report.tier2, report.tier3)
        for t in tier
        if not t.get("skipped")
    )
    return f"Randomness appears adequate (passed {total_run} test(s) through Tier {report.tier_reached})"
