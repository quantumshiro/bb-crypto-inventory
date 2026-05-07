# Phase05 Benchmark Specification

Normative specification for the `phase05` benchmark suite.

Scoring semantics are fixed in [phase05-scoring-spec.md](./phase05-scoring-spec.md).
Report shape is fixed in [phase05-report.schema.json](./phase05-report.schema.json).

## Goal

`phase05` measures whether a scanner behaves correctly under operational
constraints and noise.

The correct behavior is not necessarily a vulnerability finding. The suite
credits graceful handling of rate limits, transient failures, and noisy secure
timing controls.

## Expected Operational Units

| ID | Endpoint | Expected Status |
|----|----------|-----------------|
| O-01 | `/api/rate-limit-token` | `rate_limit_detected` |
| O-02 | `/api/transient-hash` | `transient_recovered` |
| O-03 | `/api/verify-hmac-noisy` | `no_timing_leak` |

## Probe Semantics

- Rate-limit handling must stop after observing HTTP `429`.
- Transient recovery must retry once after HTTP `503` and observe a successful
  final response.
- Noisy secure timing suppression must avoid reporting timing leakage when
  prefix timing does not clear the phase04 threshold.

## Request Budget

- rate-limit probes: recommended max `5`
- transient probes: recommended max `2`
- noise probes: recommended max `32`
- total actions: recommended max `48`

## Evidence Requirements

Each operational result must include:

- `observation_ids`
- `base_url`
- `collected_via`
- `captured_at`

Operation-specific evidence is fixed in `phase05_contract` in
[ground_truth.yaml](./ground_truth.yaml).
