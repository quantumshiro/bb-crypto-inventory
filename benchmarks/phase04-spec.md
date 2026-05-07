# Phase04 Benchmark Specification

Normative specification for the `phase04` benchmark suite.

Scoring semantics are fixed in [phase04-scoring-spec.md](./phase04-scoring-spec.md).
Report shape is fixed in [phase04-report.schema.json](./phase04-report.schema.json).

## Goal

`phase04` measures whether a scanner can perform authorized active validation
for runtime cryptographic vulnerabilities that require targeted probing.

The suite covers:

- padding-oracle response differentials
- HMAC timing leakage

## Unit Under Test

The unit under test is the supplied application base URL plus explicitly
declared active-validation targets.

`phase04` is deliberately separate from `phase03` because it uses higher-volume
and more intrusive probes than deterministic misuse classification.

## Positive Targets

| ID | Endpoint | Expected Finding |
|----|----------|------------------|
| V-01 | `/api/decrypt` | `PaddingOracle / AES-128-CBC-PKCS7` |
| V-02 | `/api/verify-hmac` | `TimingLeak / HMAC-SHA256-non-constant-time` |

## Negative Controls

| ID | Endpoint | Expected Result |
|----|----------|-----------------|
| V-NC-01 | `/api/verify-hmac-secure` | no `TimingLeak` |

## Probe Semantics

Padding-oracle validation requires:

- obtaining a valid CBC ciphertext from the benchmark encryption fixture
- sending valid and mutated ciphertexts to the decryption endpoint
- clustering invalid responses by status code and error body
- reporting `PaddingOracle` only when invalid responses split into multiple
  distinguishable clusters with padding-specific evidence

Timing validation requires:

- using benchmark test-vector knowledge for a valid HMAC
- sending invalid MACs with increasing correct-prefix lengths
- measuring median response time by prefix length
- reporting `TimingLeak` only when median timing increases monotonically enough
  to clear the suite threshold

## Request Budget

- padding probes: recommended max `8`
- timing probes: recommended max `48`
- total actions: recommended max `80`

## Evidence Requirements

Every positive validation must include:

- `observation_ids`
- `base_url`
- `collected_via`
- `captured_at`
- `endpoint_url`
- `endpoint_path`
- `methods`
- `surface_kind`
- `probe_strategy`

Category-specific evidence is fixed in `phase04_contract` in
[ground_truth.yaml](./ground_truth.yaml).
