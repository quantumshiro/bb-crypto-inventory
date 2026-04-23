# Phase03 Benchmark Specification

Normative specification for the `phase03` benchmark suite.

Scoring semantics are fixed in [phase03-scoring-spec.md](./phase03-scoring-spec.md).
Report shape is fixed in [phase03-report.schema.json](./phase03-report.schema.json).

## Goal

`phase03` measures whether a scanner can start from an authorized **application
base URL**, reuse same-origin discovery, and then classify the externally
observable cryptographic misuses that are exposed by those application
surfaces.

This suite is intentionally about **classification**, not deep exploit
validation.

## Unit Under Test

The unit under test is the supplied **base URL** plus the same-origin surfaces
discovered from it.

- Same-origin descriptor fetching is allowed.
- Deterministic HTTP probing of discovered crypto surfaces is required.
- Adjacent-port discovery is out of scope.
- Padding-oracle and timing validation are out of scope.

## Required Capabilities

A conforming implementation must be able to:

- discover same-origin crypto-relevant surfaces from the supplied base URL
- probe encryption endpoints with repeated-block and repeat-plaintext payloads
- probe hash endpoints with known-input digest comparison
- collect enough token samples to classify obvious predictable generators
- probe JWT authentication surfaces with deterministic exploit variants
- emit normalized findings with category-specific evidence

## Out of Scope

`phase03` does not score:

- TLS posture
- service discovery beyond the supplied origin
- padding-oracle testing
- timing-side-channel testing
- purely whitebox-only cryptographic weaknesses

## Discovery Dependency

`phase03` is defined on top of the `phase02` discovery boundary.

- same-origin descriptor paths remain `/`, `/openapi.json`, and `/swagger.json`
- only discoveries with these surface kinds are in scope:
  - `encryption_oracle`
  - `hash_oracle`
  - `token_issuer`
  - `jwt_auth_surface`
- discovered `decryption_oracle` and `hmac_verifier` surfaces must be skipped as
  phase04 concerns

## Classification Targets

The suite expects the scanner to classify the following positive units from
`http://localhost:9000/`:

| ID | Endpoint | Methods | Surface Kind | Expected Finding |
|----|----------|---------|--------------|------------------|
| C-01 | `/api/encrypt` | `POST` | `encryption_oracle` | `ECBMode / AES-128-ECB` |
| C-02 | `/api/encrypt-cbc-static` | `POST` | `encryption_oracle` | `StaticIV / AES-128-CBC` |
| C-03 | `/api/hash` | `POST` | `hash_oracle` | `WeakHash / MD5` |
| C-04 | `/api/hash-sha1` | `POST` | `hash_oracle` | `WeakHash / SHA-1` |
| C-05 | `/api/token` | `GET` | `token_issuer` | `InsecureRandom / LCG` |
| C-06 | `/api/auth` | `POST` | `jwt_auth_surface` | `JWTAlgConfusion / JWT-none` |
| C-07 | `/api/auth-rsa` | `POST` | `jwt_auth_surface` | `JWTAlgConfusion / JWT-RS256-to-HS256` |

## Negative Controls

The scanner must not report phase03 findings on:

- `C-NC-01 / /api/encrypt-strong`
- `C-NC-02 / /api/hash-strong`
- `C-NC-03 / /api/token-secure`

## Probe Semantics

### Encryption Oracles

- ECB detection requires repeated 16-byte plaintext blocks and repeated
  ciphertext blocks in the returned ciphertext.
- Static-IV detection requires repeated requests with identical plaintext and
  identical ciphertext outputs, with identical returned IVs when an IV field is
  exposed.

### Hash Oracles

- The scanner must hash a known input locally and compare it to the returned
  digest.
- Digest-length heuristics alone are not enough for credit; exact local-match
  evidence is required.

### Token Issuers

- The scanner must collect multiple samples from the token endpoint.
- LCG classification requires evidence stronger than “looks patterned”.
- A recovered or near-perfect linear recurrence over token words is sufficient.

### JWT Auth Surfaces

- `JWT-none` requires obtaining an issued token, crafting an unsigned token with
  `alg=none`, and showing that the server accepts it.
- `JWT-RS256-to-HS256` requires obtaining the advertised public key, crafting an
  `HS256` token signed with that public key as the HMAC secret, and showing that
  the server accepts it.

## Canonicalization

- scheme and host are lowercased
- default port is `80` for HTTP and `443` for HTTPS
- empty path becomes `/`
- query string and fragment are ignored for base-URL identity
- endpoint identity is `canonical_base_url + normalized endpoint path`
- methods are uppercased and sorted before comparison

## Request Budget

`phase03` is allowed to send more traffic than `phase02`, but it is still meant
to be bounded and deterministic.

- descriptor fetches: recommended max `4`
- classification probes: recommended max `92`
- token samples per issuer: recommended max `16`
- total actions: recommended max `56`

Retries count toward the action budget.

## Evidence Requirements

Every positive classification must include:

- `observation_ids`
- `base_url`
- `collected_via`
- `captured_at`
- `source_discovery_id`
- `endpoint_url`
- `endpoint_path`
- `methods`
- `surface_kind`
- `probe_strategy`

Category-specific evidence is defined in
[benchmarks/ground_truth.yaml](./ground_truth.yaml) under `phase03_contract`.

## Report Contract

A conforming `phase03` run must emit a report that validates against
[phase03-report.schema.json](./phase03-report.schema.json).
