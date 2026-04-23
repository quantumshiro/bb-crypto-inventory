# Phase03 Scoring Specification

Normative scoring rules for the `phase03` benchmark suite.

The suite contract is fixed in [phase03-spec.md](./phase03-spec.md).

## Expected Positive Units

`phase03` contains `7` positive classification units:

1. `C-01 / /api/encrypt / ECBMode / AES-128-ECB`
2. `C-02 / /api/encrypt-cbc-static / StaticIV / AES-128-CBC`
3. `C-03 / /api/hash / WeakHash / MD5`
4. `C-04 / /api/hash-sha1 / WeakHash / SHA-1`
5. `C-05 / /api/token / InsecureRandom / LCG`
6. `C-06 / /api/auth / JWTAlgConfusion / JWT-none`
7. `C-07 / /api/auth-rsa / JWTAlgConfusion / JWT-RS256-to-HS256`

## Negative Controls

The following endpoints must not produce in-scope phase03 findings:

- `C-NC-01 / /api/encrypt-strong`
- `C-NC-02 / /api/hash-strong`
- `C-NC-03 / /api/token-secure`

## Normalization

Before matching:

1. canonicalize the base URL
2. canonicalize each endpoint URL
3. uppercase and sort methods
4. discard classifications whose category is outside the phase03 contract
5. normalize `SHA1 -> SHA-1` and `alg=none -> JWT-none`

## Matching

An expected unit is a true positive only if all of the following hold:

- canonical endpoint URL matches
- normalized category matches
- normalized algorithm matches
- methods overlap the expected method set
- required evidence keys are present
- the classification originates from the expected surface kind
- the finding uses one of the benchmark-declared detection channels

If multiple classifications match the same expected unit, the highest-confidence
one is credited and the others are counted as duplicate false positives.

## Evidence Semantics

Category-specific minimum evidence:

- `ECBMode`
  - repeated 16-byte ciphertext blocks are present
  - repeated block indexes are reported
- `StaticIV`
  - same plaintext was sent repeatedly
  - ciphertext outputs are identical
  - identical IV evidence is present when the endpoint exposes an IV field
- `WeakHash`
  - returned digest matches the locally computed digest for the claimed
    algorithm
- `InsecureRandom`
  - the report shows a near-perfect LCG recurrence or equivalent deterministic
    recurrence evidence
- `JWTAlgConfusion`
  - the report shows the exploit variant attempted and accepted by the server

## False Positives

A classification is a false positive if it is in-scope and:

- does not correspond to any expected positive unit, or
- targets a negative-control endpoint, or
- lacks valid evidence for the claimed category, or
- uses the wrong normalized algorithm for the matched category

## Metrics

`phase03` uses:

- Precision
- Recall
- F1
- Budget Compliance Rate
- Inconclusive Rate
- Mean Time To First Classification

## Release Gate

`phase03` is implementation-ready only if repeated fresh-container runs satisfy:

- precision `>= 0.95`
- recall `>= 0.95`
- negative-control false positives `== 0`
- budget compliance `== 1.0`
- inconclusive rate `== 0.0`
