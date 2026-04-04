# Phase01 Scoring Spec

Normative scoring rules for the `phase01` benchmark suite.

This file defines how normalized findings are converted into benchmark verdicts.
Suite boundary and normalization rules are defined in
[phase01-spec.md](./phase01-spec.md).

## 1. Scoring Units

### 1.1 Positive Units

The suite has `7` positive expected units:

1. `BM-09 / WeakProtocolVersion / TLSv1.0`
2. `BM-09 / WeakProtocolVersion / TLSv1.1`
3. `BM-09 / InsecureCipherSuite / RC4-family`
4. `BM-09 / NoPFS / static-RSA`
5. `BM-11 / NoHSTS / HSTS-missing`
6. `BM-12 / WeakKeyLength / RSA-1024`
7. `BM-13 / WeakSignatureAlgorithm / sha1WithRSAEncryption`

### 1.2 Negative Control Unit

The suite has `1` negative-control target:

- `NC-04 / https://localhost:9444/`

Success means:

- no in-scope `phase01` finding is emitted for that target
- computed TLS grade is exactly `A+`, if grade is emitted

## 2. Matching Pipeline

For every run, scoring proceeds in this order:

1. canonicalize target URLs
2. discard out-of-suite categories from `phase01` scoring
3. normalize protocols, suites, algorithms, and signature names
4. validate evidence shape
5. match findings to expected units
6. classify unmatched findings
7. evaluate grade accuracy
8. compute summary metrics

## 3. Candidate Match Rules

An actual finding is a valid candidate for an expected unit only if all of the
following are true:

- canonical `target_url` matches the expected target
- `category` matches exactly
- normalized `algorithm` matches exactly
- `detection_channel` is allowed for that category
- required evidence keys are present
- evidence contents are semantically consistent with the expected unit

Examples:

- `WeakProtocolVersion / TLSv1` is accepted after normalization to `TLSv1.0`
- `InsecureCipherSuite / RC4` is accepted after normalization to `RC4-family`
- `WeakSignatureAlgorithm / sha1WithRSA` is accepted after normalization to
  `sha1WithRSAEncryption`

## 4. Evidence Validation Rules

### 4.1 WeakProtocolVersion

Required:

- `supported_protocols`
- `accepted_protocol`

Valid only if the normalized `accepted_protocol` equals the expected algorithm.

### 4.2 InsecureCipherSuite

Required:

- `accepted_suites`
- `normalized_suite_families`
- `representative_suite`

Valid only if at least one accepted suite normalizes to `RC4-family`.

### 4.3 NoPFS

Required:

- `accepted_suites`
- `accepted_key_exchange_families`
- `non_pfs_accepted`

Valid only if:

- `non_pfs_accepted == true`
- evidence shows at least one accepted non-PFS handshake

`NoPFS` does not require proving the absence of all PFS support.

### 4.4 NoHSTS

Required:

- `response_headers`
- `redirect_hops_followed`

Valid only if `Strict-Transport-Security` is absent after allowed same-origin
redirect following.

### 4.5 WeakKeyLength

Required:

- `certificate_position`
- `key_type`
- `key_length_bits`

Valid only if `certificate_position == leaf`, `key_type == RSA`, and
`key_length_bits == 1024`.

### 4.6 WeakSignatureAlgorithm

Required:

- `certificate_position`
- `signature_algorithm`

Valid only if the normalized signature algorithm equals
`sha1WithRSAEncryption`.

## 5. One-to-One Matching and Duplicate Policy

- Each expected unit can match at most one actual finding.
- Each actual finding can satisfy at most one expected unit.
- If multiple actual findings match the same expected unit, choose:
  1. highest `confidence`
  2. lowest `request_count` if present
  3. lexicographically smallest `id`
- All additional matching findings are scored as `duplicate_false_positive`.

This makes deduplication part of benchmark quality.

## 6. False Positive Policy

An in-scope `phase01` finding is a false positive if it:

- targets `NC-04`
- targets the wrong URL
- has the right category but wrong normalized algorithm
- lacks required evidence
- duplicates an already matched expected unit

Out-of-suite findings are not counted in `phase01` precision/recall, but should
be reported separately as out-of-suite emissions.

## 7. Inconclusive Policy

The allowed benchmark verdict statuses are:

- `matched`
- `missed`
- `false_positive`
- `duplicate_false_positive`
- `true_negative`
- `inconclusive`

`inconclusive` is allowed in raw reporting for reasons such as:

- cross-origin redirect
- TLS library limitation
- handshake failure after allowed retry
- budget exhaustion before required probes completed

Scoring treatment:

- positive target `inconclusive` counts as `missed` for recall
- negative-control `inconclusive` is not a true negative
- `inconclusive_rate` is tracked separately

The canonical benchmark environment is expected to produce `0` inconclusives.

## 8. TLS Grade Scoring

### 8.1 Base Score

Use SSL Labs style weighted scoring:

```text
overall = protocol_score * 0.30
        + key_exchange_score * 0.30
        + cipher_strength_score * 0.40
```

### 8.2 Grade Thresholds

| Score | Grade |
|-------|-------|
| `>= 80` | `A` |
| `>= 65` | `B` |
| `>= 50` | `C` |
| `>= 35` | `D` |
| `>= 20` | `E` |
| `< 20` | `F` |

### 8.3 Grade Caps

Apply the strongest cap triggered by the observed posture:

- `SSLv2` accepted -> `F`
- `RC4-family` accepted -> max `C`
- `3DES-family` accepted -> max `C`
- `TLSv1.0` or `TLSv1.1` accepted -> max `B`
- non-PFS accepted -> max `B`

### 8.4 A+ Promotion

Promote `A` to `A+` only if:

- final uncapped grade is `A`
- no cap reduces the grade below `A`
- `Strict-Transport-Security` is present
- parsed HSTS `max-age >= 15552000`

For `phase01`, `NC-04` is the only grade-bearing target expected to reach `A+`.

### 8.5 Grade Accuracy Metric

Grade accuracy is:

```text
exact grade matches / grade-bearing targets assessed
```

Grade-bearing targets in `phase01`:

- `BM-09` -> expected `C`
- `NC-04` -> expected `A+`

## 9. Metric Definitions

### 9.1 Precision

```text
TP / (TP + FP)
```

### 9.2 Recall

```text
TP / total_positive_expected_units
```

### 9.3 F1

```text
2 * precision * recall / (precision + recall)
```

### 9.4 Confidence Threshold Pass Rate

Per expected unit, a match passes if:

```text
matched_confidence >= expected_min_confidence
```

### 9.5 Budget Compliance Rate

```text
targets within recommended budget / assessed targets
```

### 9.6 Inconclusive Rate

```text
inconclusive target verdicts / total targets
```

## 10. Release Gate

`phase01` is considered implementation-ready only if repeated fresh-container
runs satisfy all of the following:

- precision `>= 0.95`
- recall `>= 0.90`
- SSL grade accuracy `= 1.0`
- negative-control false positives `= 0`
- budget compliance rate `= 1.0`
- inconclusive rate `= 0`
- stable verdicts across at least `10` fresh-container runs

## 11. Determinism Requirements

To avoid implementation-dependent ambiguity:

- canonicalization rules are fixed in `phase01-spec.md`
- normalized algorithm values are exact, not fuzzy
- tie-breaking is deterministic
- same input and same fixture must produce the same benchmark verdicts
