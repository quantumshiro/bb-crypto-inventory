# Phase05 Scoring Specification

Normative scoring rules for the `phase05` benchmark suite.

## Expected Units

`phase05` contains `3` operational units:

1. `O-01 / rate_limit_handling / rate_limit_detected`
2. `O-02 / transient_recovery / transient_recovered`
3. `O-03 / noisy_secure_timing_suppression / no_timing_leak`

## Matching

An operational unit is a true positive only if all of the following hold:

- `target_id` matches
- operation matches
- observed status matches the expected status
- `passed` is `true`
- evidence satisfies the operation-specific contract

## False Positives

An operational result is a false positive if:

- it is not one of the expected operational units, or
- it claims `passed=true` with invalid evidence, or
- it reports a vulnerability-like status for the noisy secure timing control

## Metrics

`phase05` uses:

- Operational Recall
- Precision
- F1
- Budget Compliance Rate
- Inconclusive Rate

## Release Gate

- operational recall `>= 0.95`
- false operational failures `== 0`
- budget compliance `== 1.0`
