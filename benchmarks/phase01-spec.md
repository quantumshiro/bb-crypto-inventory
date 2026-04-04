# Phase01 Spec

Normative specification for the `phase01` benchmark suite.

This file defines the suite boundary and the normalization contract.
Scoring semantics are fixed in [phase01-scoring-spec.md](./phase01-scoring-spec.md).
Report shape is fixed in [phase01-report.schema.json](./phase01-report.schema.json).
Per-target ground truth lives in [ground_truth.yaml](./ground_truth.yaml).

## 1. Purpose

`phase01` is the first suite to stabilize for `bbci`.

It measures whether a scanner can take an explicitly supplied HTTPS edge URL and
produce a correct, evidence-backed assessment of:

- HTTP security headers visible from that URL
- TLS certificate metadata visible from that URL
- TLS protocol posture for that URL
- TLS cipher posture for that URL
- forward secrecy posture for that URL
- SSL Labs style grade for that URL

It does **not** measure:

- network neighborhood discovery
- SSH discovery
- OpenAPI discovery
- app-layer crypto misuse
- padding-oracle behavior
- timing attacks
- randomness analysis

## 2. Input Contract

### 2.1 Accepted Input

- Input is a single user-supplied HTTPS URL.
- The benchmark contract requires scheme `https`.
- Benchmark targets are:
  - `https://localhost:9443/`
  - `https://localhost:9444/`

### 2.2 Canonical Target Identity

All scoring is performed against a canonical target identity.

Canonicalization rules:

- lowercase scheme and host
- default empty path to `/`
- preserve explicit non-default port
- treat omitted HTTPS port as `443`
- strip fragment
- strip query for scoring identity

Examples:

- `HTTPS://LOCALHOST:9443` -> `https://localhost:9443/`
- `https://localhost:9443/?x=1` -> `https://localhost:9443/`
- `https://localhost` -> `https://localhost:443/`

### 2.3 Redirect Policy

- Same-origin redirect following is allowed for **header observation only**.
- Maximum same-origin redirect hops: `1`.
- Cross-origin redirect makes the target verdict `inconclusive`.
- Scheme-changing redirect makes the target verdict `inconclusive`.
- TLS observations are always attached to the authority in the input URL, not a
  redirected authority.

### 2.4 TLS Session Policy

- TLS probes **must** send SNI equal to the canonical host.
- Self-signed certificates are allowed in the benchmark environment.
- Certificate trust failure does **not** invalidate certificate evidence.
- The benchmark fixtures do not require client authentication.

## 3. Unit Under Test

The unit under test is the exact supplied HTTPS URL.

Credit is **not** awarded for:

- finding adjacent ports
- expanding to neighboring services
- crawling beyond the supplied path
- reporting unrelated app-layer findings

If a scanner performs those internally, they are ignored unless they leak into
the normalized `phase01` findings or consume request budget.

## 4. Fixture Contract

### 4.1 Weak Edge

Target: `https://localhost:9443/`

Expected fixture properties:

- supports `TLSv1.0`, `TLSv1.1`, `TLSv1.2`
- does not support `TLSv1.3`
- accepts RC4-family suites
- accepts static-RSA suites
- may also support some PFS suites
- does **not** require PFS for all successful handshakes
- omits `Strict-Transport-Security`
- leaf certificate is `RSA-1024`
- leaf certificate signature algorithm is `sha1WithRSAEncryption`
- expected TLS grade is `C`

### 4.2 Strong Edge

Target: `https://localhost:9444/`

Expected fixture properties:

- supports `TLSv1.3` only
- accepts AEAD-only modern suites
- does not accept non-PFS suites
- includes `Strict-Transport-Security`
- leaf certificate is `RSA-2048`
- leaf certificate signature algorithm is `sha256WithRSAEncryption`
- expected TLS grade is `A+`

## 5. Observation Contract

Implementations may collect richer internal state, but a conforming `phase01`
report must be able to express the following normalized observation types:

- `http_headers`
- `certificate_leaf`
- `tls_protocol_support`
- `tls_cipher_acceptance`
- `tls_grade`

Each observation must carry:

- stable `id`
- `type`
- `target_url`
- `captured_at`
- raw `data`

## 6. Request Accounting Contract

`phase01` is intended to be low-volume and deterministic.

### 6.1 Counted Action Types

- `http_request`
- `certificate_handshake`
- `version_probe`
- `cipher_probe`
- `retry`
- `redirect_follow`

### 6.2 Counting Rules

- One HTTP request counts as one action.
- One TLS handshake counts as one action.
- If a single handshake yields both certificate metadata and protocol success,
  it counts once.
- Retries count as actions.
- Maximum retries per failed action: `1`.

### 6.3 Recommended Budget

- header fetch: `<= 2`
- certificate extraction: `<= 2`
- version probes: `<= 4`
- cipher probes: `<= 8`
- total: `<= 16`

Budget breach does not invalidate the run, but it fails budget compliance.

## 7. Normalization Contract

### 7.1 Suite Categories

Only the following categories are in-scope for `phase01` scoring:

- `WeakProtocolVersion`
- `InsecureCipherSuite`
- `NoPFS`
- `NoHSTS`
- `WeakKeyLength`
- `WeakSignatureAlgorithm`

Out-of-scope findings may appear in raw output, but they do not participate in
`phase01` matching.

### 7.2 Detection Channels

- `RECON` for HSTS and certificate findings
- `CH1:TLS_HANDSHAKE` for protocol, cipher, PFS, and grade inputs

### 7.3 Protocol Normalization

Accepted aliases:

| Raw | Normalized |
|-----|------------|
| `TLSv1` | `TLSv1.0` |
| `TLS1.0` | `TLSv1.0` |
| `TLS1.1` | `TLSv1.1` |
| `TLS1.2` | `TLSv1.2` |
| `TLS1.3` | `TLSv1.3` |

### 7.4 Cipher and Key-Exchange Normalization

Fixture-relevant mapping:

| Raw suite or family | Normalized family |
|---------------------|-------------------|
| `RC4-SHA` | `RC4-family` |
| `RC4-MD5` | `RC4-family` |
| `DES-CBC3-SHA` | `3DES-family` |
| `AES128-SHA` | `static-RSA` |
| `AES256-SHA` | `static-RSA` |
| `AES128-SHA256` | `static-RSA` |
| `AES256-SHA256` | `static-RSA` |
| `ECDHE-RSA-AES128-SHA` | `ECDHE-RSA` |
| `ECDHE-RSA-AES256-SHA` | `ECDHE-RSA` |
| `TLS_AES_128_GCM_SHA256` | `TLSv1.3-AEAD` |
| `TLS_AES_256_GCM_SHA384` | `TLSv1.3-AEAD` |
| `TLS_CHACHA20_POLY1305_SHA256` | `TLSv1.3-AEAD` |

### 7.5 PFS Semantics

For `phase01`, `NoPFS` does **not** mean "the server supports zero PFS suites".

It means:

- the server accepts at least one successful **non-PFS** handshake
- where the negotiated key-exchange family is not `ECDHE` or `DHE`

Therefore:

- a server can support some PFS suites and still legitimately trigger `NoPFS`
- `NC-04` passes only if no successful non-PFS handshake is accepted

### 7.6 Signature Algorithm Normalization

Accepted aliases:

| Raw | Normalized |
|-----|------------|
| `sha1WithRSA` | `sha1WithRSAEncryption` |
| `sha1_rsa` | `sha1WithRSAEncryption` |
| `sha256WithRSA` | `sha256WithRSAEncryption` |
| `sha256_rsa` | `sha256WithRSAEncryption` |

### 7.7 Finding Algorithm Values

The normalized `algorithm` field must use these values for `phase01`:

| Category | Normalized algorithm |
|----------|----------------------|
| `WeakProtocolVersion` | `TLSv1.0` or `TLSv1.1` |
| `InsecureCipherSuite` | `RC4-family` |
| `NoPFS` | `static-RSA` |
| `NoHSTS` | `HSTS-missing` |
| `WeakKeyLength` | `RSA-1024` |
| `WeakSignatureAlgorithm` | `sha1WithRSAEncryption` |

## 8. Evidence Contract

### 8.1 Common Required Fields

Every scored finding must include evidence with:

- `observation_ids`
- `target_url`
- `collected_via`
- `captured_at`

### 8.2 Category-Specific Required Fields

| Category | Required evidence keys |
|----------|------------------------|
| `WeakProtocolVersion` | `supported_protocols`, `accepted_protocol` |
| `InsecureCipherSuite` | `accepted_suites`, `normalized_suite_families`, `representative_suite` |
| `NoPFS` | `accepted_suites`, `accepted_key_exchange_families`, `non_pfs_accepted` |
| `NoHSTS` | `response_headers`, `redirect_hops_followed` |
| `WeakKeyLength` | `certificate_position`, `key_type`, `key_length_bits` |
| `WeakSignatureAlgorithm` | `certificate_position`, `signature_algorithm` |

Evidence may contain more fields, but these keys are mandatory for scoring.

## 9. Expected Benchmark Units

`phase01` has seven positive expected units and one negative-control target.

| Benchmark | Target | Expected unit |
|-----------|--------|---------------|
| BM-09 | `https://localhost:9443/` | `WeakProtocolVersion` / `TLSv1.0` |
| BM-09 | `https://localhost:9443/` | `WeakProtocolVersion` / `TLSv1.1` |
| BM-09 | `https://localhost:9443/` | `InsecureCipherSuite` / `RC4-family` |
| BM-09 | `https://localhost:9443/` | `NoPFS` / `static-RSA` |
| BM-11 | `https://localhost:9443/` | `NoHSTS` / `HSTS-missing` |
| BM-12 | `https://localhost:9443/` | `WeakKeyLength` / `RSA-1024` |
| BM-13 | `https://localhost:9443/` | `WeakSignatureAlgorithm` / `sha1WithRSAEncryption` |
| NC-04 | `https://localhost:9444/` | no in-scope finding; grade `A+` |

## 10. Report Contract

A conforming `phase01` run must emit a report that validates against
[phase01-report.schema.json](./phase01-report.schema.json).

At minimum the report must contain:

- scanner metadata
- execution metadata
- request accounting
- normalized observations
- normalized findings
- benchmark verdicts
- suite metrics, if already computed

## 11. Operational Expectations

In the canonical benchmark environment:

- positive targets should not end `inconclusive`
- the negative control should not end `inconclusive`
- TLS grade should be deterministic across repeated runs
- budget compliance should be deterministic across repeated runs

Any `inconclusive` result in the canonical benchmark environment is treated as a
coverage gap to fix before Phase 2.

## 12. Out of Scope

The following are intentionally left for later suites:

- discovery quality across neighboring services
- app-layer crypto classification
- runtime exploitability
- oracle confirmation
- remote timing confirmation
- randomness quality assessment
