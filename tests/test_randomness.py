"""Tests for the tiered randomness quality assessment module."""

from __future__ import annotations

import os
import secrets

import pytest

from bbci.tools.randomness import (
    RandomnessReport,
    run_randomness_tests,
    tier1_diff_analysis,
    tier1_permutation_entropy,
    tier2_anderson_darling,
    tier2_chi_square,
    tier2_collision_test,
    tier2_shr_entropy,
    tier3_maurer_universal,
    tier3_min_entropy,
    tier3_sprt,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_hex_tokens(n: int, length: int = 32) -> list[str]:
    """Generate n cryptographically random hex tokens."""
    return [secrets.token_hex(length) for _ in range(n)]


def _sequential_tokens(n: int, start: int = 1000) -> list[str]:
    """Generate n sequential (incrementing) token hex strings."""
    return [format(start + i, "032x") for i in range(n)]


def _lcg_tokens(n: int, seed: int = 42, a: int = 1103515245, c: int = 12345, m: int = 2**31) -> list[str]:
    """Generate tokens from a Linear Congruential Generator."""
    tokens: list[str] = []
    x = seed
    for _ in range(n):
        x = (a * x + c) % m
        tokens.append(format(x, "08x"))
    return tokens


def _biased_tokens(n: int, bias_byte: int = 0xAA) -> list[str]:
    """Generate tokens with heavily biased byte distribution."""
    tokens: list[str] = []
    for _ in range(n):
        # 80% of bytes are the bias_byte, 20% random
        raw = bytes(
            bias_byte if secrets.randbelow(5) != 0 else secrets.randbelow(256)
            for _ in range(16)
        )
        tokens.append(raw.hex())
    return tokens


# ---------------------------------------------------------------------------
# Tier 1 tests
# ---------------------------------------------------------------------------

class TestTier1DiffAnalysis:
    def test_sequential_detected(self):
        integers = list(range(1000, 1100))
        result = tier1_diff_analysis(integers)
        assert result["pass"] is False
        assert result["is_sequential"] is True

    def test_random_passes(self):
        integers = [int.from_bytes(secrets.token_bytes(8), "big") for _ in range(100)]
        result = tier1_diff_analysis(integers)
        assert result["pass"] is True
        assert result["is_sequential"] is False

    def test_too_few_samples(self):
        result = tier1_diff_analysis([1, 2])
        assert result.get("skipped") is True


class TestTier1PermutationEntropy:
    def test_sequential_low_entropy(self):
        integers = list(range(200))
        result = tier1_permutation_entropy(integers)
        assert result["pass"] is False
        assert result["normalized_pe"] < 0.5

    def test_random_high_entropy(self):
        integers = [int.from_bytes(secrets.token_bytes(8), "big") for _ in range(200)]
        result = tier1_permutation_entropy(integers)
        assert result["pass"] is True
        assert result["normalized_pe"] > 0.9

    def test_too_few_samples(self):
        result = tier1_permutation_entropy([1, 2, 3])
        assert result.get("skipped") is True


# ---------------------------------------------------------------------------
# Tier 2 tests
# ---------------------------------------------------------------------------

class TestTier2SHREntropy:
    def test_random_full_entropy(self):
        byte_seqs = [secrets.token_bytes(16) for _ in range(100)]
        result = tier2_shr_entropy(byte_seqs)
        assert result["pass"] is True
        assert result["normalized_entropy"] > 0.9

    def test_biased_low_entropy(self):
        # All same byte
        byte_seqs = [bytes([0xAA] * 16) for _ in range(100)]
        result = tier2_shr_entropy(byte_seqs)
        assert result["pass"] is False
        assert result["normalized_entropy"] < 0.5


class TestTier2AndersonDarling:
    def test_uniform_passes(self):
        bit_length = 32
        max_val = 2**bit_length - 1
        integers = [secrets.randbelow(max_val) for _ in range(200)]
        result = tier2_anderson_darling(integers, bit_length)
        assert result["pass"] is True

    def test_biased_fails(self):
        # All values in lower 10% of range
        bit_length = 32
        max_val = 2**bit_length - 1
        integers = [secrets.randbelow(max_val // 10) for _ in range(200)]
        result = tier2_anderson_darling(integers, bit_length)
        assert result["pass"] is False


class TestTier2ChiSquare:
    def test_random_passes(self):
        byte_seqs = [secrets.token_bytes(32) for _ in range(50)]
        result = tier2_chi_square(byte_seqs)
        if not result.get("skipped"):
            assert result["pass"] is True

    def test_constant_fails(self):
        byte_seqs = [bytes([42] * 32) for _ in range(50)]
        result = tier2_chi_square(byte_seqs)
        if not result.get("skipped"):
            assert result["pass"] is False


class TestTier2Collision:
    def test_random_no_collisions(self):
        integers = [int.from_bytes(secrets.token_bytes(16), "big") for _ in range(100)]
        result = tier2_collision_test(integers, bit_length=128)
        assert result["pass"] is True
        assert result["collisions"] == 0

    def test_small_space_collisions(self):
        # Only 256 possible values → guaranteed collisions with 100 samples
        integers = [secrets.randbelow(256) for _ in range(100)]
        result = tier2_collision_test(integers, bit_length=8)
        # With 8-bit space and 100 samples, collisions are expected and normal
        # This tests that the function runs without error
        assert "collisions" in result


# ---------------------------------------------------------------------------
# Tier 3 tests
# ---------------------------------------------------------------------------

class TestTier3SPRT:
    def test_random_accepted(self):
        byte_seqs = [secrets.token_bytes(16) for _ in range(500)]
        result = tier3_sprt(byte_seqs)
        assert result["pass"] is True

    def test_constant_rejected(self):
        byte_seqs = [bytes([0] * 16) for _ in range(500)]
        result = tier3_sprt(byte_seqs)
        assert result["pass"] is False
        assert result["decision"] == "reject_uniform"


class TestTier3MinEntropy:
    def test_random_high_entropy(self):
        byte_seqs = [secrets.token_bytes(32) for _ in range(100)]
        result = tier3_min_entropy(byte_seqs)
        assert result["pass"] is True
        assert result["min_entropy_per_byte"] > 6.0

    def test_constant_zero_entropy(self):
        byte_seqs = [bytes([0xBB] * 32) for _ in range(100)]
        result = tier3_min_entropy(byte_seqs)
        assert result["pass"] is False
        assert result["min_entropy_per_byte"] < 1.0


class TestTier3Maurer:
    def test_random_passes(self):
        # Need enough data: L=6, Q=640, K≥100 → ≥740 blocks of 6 bits ≈ 555 bytes
        byte_seqs = [secrets.token_bytes(64) for _ in range(20)]
        result = tier3_maurer_universal(byte_seqs, L=6)
        if not result.get("skipped"):
            assert result["pass"] is True

    def test_too_little_data_skipped(self):
        byte_seqs = [secrets.token_bytes(4) for _ in range(5)]
        result = tier3_maurer_universal(byte_seqs, L=6)
        assert result.get("skipped") is True


# ---------------------------------------------------------------------------
# Integration: run_randomness_tests
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_random_tokens_pass_all(self):
        tokens = _random_hex_tokens(300, length=16)
        report = run_randomness_tests(tokens, max_tier=3)
        assert report.overall_pass is True
        assert report.tier_reached >= 2
        assert len(report.failed_tests) == 0

    def test_sequential_fails_tier1(self):
        tokens = _sequential_tokens(100)
        report = run_randomness_tests(tokens, max_tier=3, early_stop=True)
        assert report.overall_pass is False
        assert report.early_termination is True
        assert report.tier_reached == 1
        assert "diff_analysis" in report.failed_tests

    def test_lcg_detected(self):
        tokens = _lcg_tokens(200)
        report = run_randomness_tests(tokens, max_tier=2)
        assert report.overall_pass is False
        assert len(report.failed_tests) > 0

    def test_biased_detected(self):
        tokens = _biased_tokens(200)
        report = run_randomness_tests(tokens, max_tier=2)
        assert report.overall_pass is False

    def test_fast_mode_tier1_only(self):
        tokens = _random_hex_tokens(50, length=16)
        report = run_randomness_tests(tokens, max_tier=1)
        assert report.tier_reached == 1
        assert len(report.tier2) == 0
        assert len(report.tier3) == 0

    def test_report_to_dict(self):
        tokens = _random_hex_tokens(100, length=16)
        report = run_randomness_tests(tokens, max_tier=2)
        d = report.to_dict()
        assert "overall_pass" in d
        assert "tier1_results" in d
        assert "tier2_results" in d
        assert "failed_tests" in d
