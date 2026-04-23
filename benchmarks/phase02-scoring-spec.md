# Phase02 Scoring Specification

Normative scoring rules for the `phase02` benchmark suite.

The suite contract is fixed in [phase02-spec.md](./phase02-spec.md).

## Expected Positive Units

`phase02` contains `13` positive discovery units:

1. `D-01 / /api/encrypt / encryption_oracle`
2. `D-02 / /api/encrypt-cbc-static / encryption_oracle`
3. `D-03 / /api/encrypt-strong / encryption_oracle`
4. `D-04 / /api/hash / hash_oracle`
5. `D-05 / /api/hash-sha1 / hash_oracle`
6. `D-06 / /api/hash-strong / hash_oracle`
7. `D-07 / /api/token / token_issuer`
8. `D-08 / /api/token-secure / token_issuer`
9. `D-09 / /api/decrypt / decryption_oracle`
10. `D-10 / /api/auth / jwt_auth_surface`
11. `D-11 / /api/auth-rsa / jwt_auth_surface`
12. `D-12 / /api/verify-hmac / hmac_verifier`
13. `D-13 / /api/verify-hmac-secure / hmac_verifier`

## Negative Controls

The following must not be reported as crypto-relevant discoveries:

- `D-NC-01 / /health`
- `D-NC-02 / /api/ping`
- `D-NC-03 / /api/profile`

## Normalization

Before matching:

1. canonicalize the base URL
2. canonicalize each endpoint URL
3. uppercase and sort methods
4. discard discoveries whose `surface_kind` is outside the suite contract

## Matching

An expected unit is a true positive only if all of the following hold:

- canonical endpoint URL matches
- normalized `surface_kind` matches
- discovery methods overlap the expected method set
- required evidence keys are present
- explicit descriptor metadata, when present, is preferred over heuristic inference
- `same_origin` is `true`

If multiple discoveries match the same expected unit, the highest-confidence one
is credited and the others are counted as duplicate false positives.

## False Positives

A discovery is a false positive if it is in-scope and:

- does not correspond to any expected positive unit, or
- targets a negative-control endpoint, or
- lacks valid evidence for the claimed surface kind

## Metrics

`phase02` uses:

- Precision
- Recall
- F1
- Budget Compliance Rate
- Inconclusive Rate
- Mean Time To First Relevant Discovery

## Release Gate

`phase02` is implementation-ready only if repeated fresh-container runs satisfy:

- precision `>= 0.95`
- recall `>= 0.95`
- negative-control false positives `== 0`
- budget compliance `== 1.0`
- mean time to first relevant discovery `<= 2.0s`
