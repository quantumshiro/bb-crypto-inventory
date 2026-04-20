# Phase02 Benchmark Specification

Normative specification for the `phase02` benchmark suite.

Scoring semantics are fixed in [phase02-scoring-spec.md](./phase02-scoring-spec.md).
Report shape is fixed in [phase02-report.schema.json](./phase02-report.schema.json).

## Goal

`phase02` measures whether a scanner can start from an authorized **application
base URL** and discover the cryptography-relevant HTTP surfaces that matter for
later blackbox testing.

This suite is intentionally about **discovery**, not vulnerability
classification.

## Unit Under Test

The unit under test is the supplied **base URL**.

- Same-origin descriptor fetching is allowed.
- Adjacent-port discovery is out of scope.
- Cross-origin crawling is out of scope.
- Active misuse detection is out of scope.

## Required Capabilities

A conforming implementation must be able to:

- fetch a service index and/or OpenAPI-like descriptor from the supplied origin
- extract candidate endpoints from those descriptors
- normalize endpoint paths and methods
- classify crypto-relevant surfaces using deterministic evidence

If explicit descriptor metadata is present, it takes precedence over heuristic
classification.

## Out of Scope

`phase02` does not score:

- TLS posture
- ECB / static-IV / weak-hash classification
- oracle, timing, or randomness probing
- HTML crawling beyond the explicitly declared descriptor paths

## Discovery Sources

The normative descriptor paths are:

- `/`
- `/openapi.json`
- `/swagger.json`

At least one successful same-origin descriptor fetch is required for a
meaningful run.

## Surface Kinds

Only the following normalized surface kinds are in scope:

- `encryption_oracle`
- `hash_oracle`
- `token_issuer`
- `decryption_oracle`
- `jwt_auth_surface`
- `hmac_verifier`

`non_crypto` is used only for negative controls and must not be emitted as a
positive discovery.

## Canonicalization

- scheme and host are lowercased
- default port is `80` for HTTP and `443` for HTTPS
- empty path becomes `/`
- query string and fragment are ignored for base-URL identity
- discovered endpoint identity is `canonical_base_url + normalized endpoint path`

Methods must be normalized to uppercase and sorted for deterministic comparison.

## Request Budget

`phase02` is meant to stay low-volume.

- descriptor fetches: recommended max `4`
- total actions: recommended max `6`

Retries count toward the action budget.

## Evidence Requirements

Every positive discovery must include:

- `observation_ids`
- `base_url`
- `collected_via`
- `captured_at`
- `sources`
- `endpoint_url`
- `endpoint_path`
- `methods`
- `surface_kind`
- `same_origin`
- `classification_basis`
- `source_urls`

## Positive Targets

The discovery suite expects the scanner to identify the following relevant
surfaces from `http://localhost:9000/`:

| ID | Endpoint | Methods | Surface Kind |
|----|----------|---------|--------------|
| D-01 | `/api/encrypt` | `POST` | `encryption_oracle` |
| D-02 | `/api/encrypt-cbc-static` | `POST` | `encryption_oracle` |
| D-03 | `/api/encrypt-strong` | `POST` | `encryption_oracle` |
| D-04 | `/api/hash` | `POST` | `hash_oracle` |
| D-05 | `/api/hash-sha1` | `POST` | `hash_oracle` |
| D-06 | `/api/hash-strong` | `POST` | `hash_oracle` |
| D-07 | `/api/token` | `GET` | `token_issuer` |
| D-08 | `/api/token-secure` | `GET` | `token_issuer` |
| D-09 | `/api/decrypt` | `POST` | `decryption_oracle` |
| D-10 | `/api/auth` | `POST` | `jwt_auth_surface` |
| D-11 | `/api/auth-rsa` | `POST` | `jwt_auth_surface` |
| D-12 | `/api/verify-hmac` | `POST` | `hmac_verifier` |
| D-13 | `/api/verify-hmac-secure` | `POST` | `hmac_verifier` |

## Negative Controls

The scanner must not report the following as crypto-relevant:

- `/health`
- `/api/ping`
- `/api/profile`

## Matching Semantics

A positive unit matches if and only if:

- endpoint URL matches exactly after canonicalization
- `surface_kind` matches exactly
- methods overlap the expected method set
- evidence satisfies the required discovery keys

## Report Contract

A conforming `phase02` run must emit a report that validates against
[phase02-report.schema.json](./phase02-report.schema.json).
