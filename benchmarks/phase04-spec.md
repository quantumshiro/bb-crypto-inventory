# Phase04 Active Validation Benchmark Specification

Phase04 evaluates bounded, authorized active validation for runtime-only cryptographic weaknesses that cannot be reliably confirmed by passive classification alone.

## Scope

The MVP suite contains two positive targets:

- `V-01` / `BM-06`: padding-oracle validation on `/api/decrypt` via response differential evidence.
- `V-02` / `BM-10`: timing side-channel validation on `/api/verify-hmac` via repeated short-prefix and long-prefix probes.

The suite also includes `V-NC-01`, a constant-time HMAC verification negative control, which is scored by absence of active validation findings.

## Probe Budget

The recommended budget is 80 validation actions per base URL. Reports must include request accounting and a `budget_compliant` flag.

## Evidence Requirements

Each validation must include `endpoint_url`, `endpoint_path`, `probe_type`, `validated`, and observation IDs. Padding-oracle evidence must include the matching differential observation. Timing evidence must include short/long averages, delta, threshold, and measurement count.
