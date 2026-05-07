# Phase04 Scoring Specification

Normative scoring rules for the `phase04` benchmark suite.

## Expected Positive Units

`phase04` contains `2` positive active-validation units:

1. `V-01 / /api/decrypt / PaddingOracle / AES-128-CBC-PKCS7`
2. `V-02 / /api/verify-hmac / TimingLeak / HMAC-SHA256-non-constant-time`

## Negative Controls

The following endpoint must not produce vulnerable phase04 validations:

- `V-NC-01 / /api/verify-hmac-secure / TimingLeak`

## Matching

An expected unit is a true positive only if all of the following hold:

- canonical endpoint URL matches
- category and algorithm match
- `vulnerable` is `true`
- evidence satisfies the category-specific contract

## False Positives

A validation is a false positive if it is in-scope and:

- targets a negative-control endpoint with `vulnerable=true`, or
- lacks valid evidence, or
- reports the wrong category for the endpoint

## Metrics

`phase04` uses:

- Precision
- Recall
- F1
- Budget Compliance Rate
- Inconclusive Rate
- Negative Control Suppression
- Mean Time To First Validation

## Release Gate

- precision `>= 0.95`
- recall `>= 0.95`
- negative-control false positives `== 0`
- budget compliance `== 1.0`
