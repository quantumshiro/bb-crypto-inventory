# Benchmarks

Blackbox cryptographic benchmark suite for evaluating `bbci` detection capabilities.

The first stabilized suites are:

- `phase01`: a URL-scoped benchmark for Recon (Phase 0) and Protocol Layer testing (Phase 1)
- `phase02`: a base-URL-scoped benchmark for application-surface discovery (Phase 2)
- `phase03`: a base-URL-scoped benchmark for deterministic misuse classification on discovered application surfaces

The normative design artifacts are:

- [phase01-spec.md](./phase01-spec.md)
- [phase01-scoring-spec.md](./phase01-scoring-spec.md)
- [phase01-report.schema.json](./phase01-report.schema.json)
- [phase02-spec.md](./phase02-spec.md)
- [phase02-scoring-spec.md](./phase02-scoring-spec.md)
- [phase02-report.schema.json](./phase02-report.schema.json)
- [phase03-spec.md](./phase03-spec.md)
- [phase03-scoring-spec.md](./phase03-scoring-spec.md)
- [phase03-report.schema.json](./phase03-report.schema.json)
- [ground_truth.yaml](./ground_truth.yaml)

## Standards Alignment

This benchmark suite aligns with established standards and taxonomies from the cryptographic security research community:

### Vulnerability Taxonomy
- **[CamBench](https://github.com/CROSSINGTUD/CamBench)** (MSR 2022, [arXiv:2204.06447](https://arxiv.org/abs/2204.06447)) — The standard benchmark for cryptographic API misuse detection tools. Our vulnerability categories map to CamBench rules where blackbox observation permits it.
- **[CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench)** (IEEE SecDev 2019) — Reference taxonomy for weak algorithm / weak key / predictable randomness classes.
- **[MASC](https://dl.acm.org/doi/10.1145/3611643.3613099)** (FSE 2023, [arXiv:2107.07065](https://arxiv.org/abs/2107.07065)) — Mutation-based taxonomy used for category mapping where relevant.

### TLS/SSL Scoring
- **[SSL Labs Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)** v2009r (Qualys, 2025) — The Phase 1 suite uses the same Protocol (30%) + Key Exchange (30%) + Cipher Strength (40%) grading methodology and grade caps.

### Testing Methodology
- **[OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/)** Chapter 9: Testing for Weak Cryptography — Phase 0+1 targets map primarily to `WSTG-CRYP-01`.
- **CWE References** — Each benchmark target is mapped to relevant MITRE CWE entries.

### Output Format
- **[CycloneDX CBOM](https://cyclonedx.org/)** v1.6 — Final output remains a CBOM-style inventory plus benchmark scoring report.

### What's Novel
> No established blackbox crypto inventory benchmark exists in the literature. CamBench and CryptoAPI-Bench target whitebox/static analysis only. This suite adapts their vulnerability taxonomy to a URL-scoped blackbox observation context.

## Phase 0+1 MVP Suite

`phase01` is intentionally narrower than the eventual full suite.

- **Evaluation mode**: URL-scoped. The benchmark assumes the user already supplied the HTTPS edge URL they want to assess.
- **What it scores in Phase 0**: header inspection and certificate-chain extraction on that explicit URL.
- **What it scores in Phase 1**: TLS protocol support, cipher suite posture, PFS, and SSL Labs-style grading.
- **What it does not score yet**: adjacent-port neighborhood discovery, app-layer misuse detection, runtime oracle attacks, or randomness analysis.
- **Why this scope**: it matches the product assumption that the user inputs their own service URL, and it makes the first benchmark dependable before adding Phase 2/3 complexity.

### Positive Targets

| ID | Check | Channel | Target | Expected Result |
|----|-------|---------|--------|-----------------|
| BM-09 | Weak TLS configuration | CH1 | `https://localhost:9443/` | Weak TLS versions, weak cipher posture, no PFS, SSL Labs grade `C` |
| BM-11 | Missing HSTS | Recon | `https://localhost:9443/` | `NoHSTS` finding |
| BM-12 | Weak certificate key length | Recon | `https://localhost:9443/` | `WeakKeyLength` on RSA-1024 |
| BM-13 | Weak certificate signature | Recon | `https://localhost:9443/` | `WeakSignatureAlgorithm` on SHA-1-with-RSA |

### Negative Control

| ID | Check | Target | Expected Result |
|----|-------|--------|-----------------|
| NC-04 | Strong TLS edge | `https://localhost:9444/` | No Phase 0+1 findings, SSL Labs grade `A+` |

### Normative Contract

`phase01` is intentionally strict about what counts as success:

- The unit under test is the **supplied HTTPS URL itself**, not neighboring ports.
- Recon scoring is limited to **headers and certificate metadata** observable from that URL.
- TLS scoring is limited to **protocols, cipher posture, PFS, and grade**.
- The suite records **request budgets, evidence requirements, and normalization rules** in [`ground_truth.yaml`](./ground_truth.yaml) and [`phase01-spec.md`](./phase01-spec.md).
- `NoPFS` is defined as **accepting at least one non-PFS handshake**, not merely "supporting no PFS at all".
- `A+` is reserved for an uncapped `A` posture plus qualifying HSTS.
- A scanner may collect more information, but it does not get extra credit for data outside the suite contract.

## Scoring Methodology

Following CamBench/CryptoAPI-Bench evaluation practice:
- **Precision**: TP / (TP + FP) — Fraction of reported findings that are true positives
- **Recall**: TP / (TP + FN) — Fraction of ground-truth findings detected
- **F1 Score**: Harmonic mean of precision and recall
- **Confidence Calibration**: How well confidence scores match per-target expectations
- **SSL Labs Grade Accuracy**: Compare computed TLS grade against the expected grade for BM-09 and NC-04
- **Detection Latency**: Time to detect each benchmark class

### Comparison Baselines

| Baseline | Scope | Type |
|----------|-------|------|
| testssl.sh | Phase 1 TLS only | Deterministic tool |
| sslyze | Phase 1 TLS only | Deterministic tool |
| Header-only baseline | Phase 0 Recon only | Deterministic heuristic |
| CryptoScope LLM | Static (whitebox) | LLM-based |

## Phase 2 Discovery Suite

`phase02` starts from a supplied application base URL and scores whether the
scanner can discover the crypto-relevant HTTP surfaces needed by later suites.

- **Evaluation mode**: base-URL-scoped same-origin discovery
- **What it scores**: service-index/OpenAPI fetch, candidate extraction,
  endpoint normalization, and crypto-surface classification
- **What it does not score yet**: vulnerability classification, active probing,
  or timing/randomness analysis
- **Classification rule**: explicit descriptor metadata such as `surface_kind`
  or `x-bbci-surface-kind` takes precedence over heuristic inference

### Positive Targets

| ID | Endpoint | Surface Kind |
|----|----------|--------------|
| D-01 | `/api/encrypt` | `encryption_oracle` |
| D-02 | `/api/encrypt-cbc-static` | `encryption_oracle` |
| D-03 | `/api/encrypt-strong` | `encryption_oracle` |
| D-04 | `/api/hash` | `hash_oracle` |
| D-05 | `/api/hash-sha1` | `hash_oracle` |
| D-06 | `/api/hash-strong` | `hash_oracle` |
| D-07 | `/api/token` | `token_issuer` |
| D-08 | `/api/token-secure` | `token_issuer` |
| D-09 | `/api/decrypt` | `decryption_oracle` |
| D-10 | `/api/auth` | `jwt_auth_surface` |
| D-11 | `/api/auth-rsa` | `jwt_auth_surface` |
| D-12 | `/api/verify-hmac` | `hmac_verifier` |
| D-13 | `/api/verify-hmac-secure` | `hmac_verifier` |

### Negative Controls

| ID | Endpoint | Expected Result |
|----|----------|-----------------|
| D-NC-01 | `/health` | Must not be reported as crypto-relevant |
| D-NC-02 | `/api/ping` | Must not be reported as crypto-relevant |
| D-NC-03 | `/api/profile` | Must not be reported as crypto-relevant |

## Phase 3 Classification Suite

`phase03` starts from the same authorized application base URL as `phase02`,
reuses same-origin discovery, and then deterministically probes only the
discovered surfaces that are relevant for misuse classification.

- **Evaluation mode**: base-URL-scoped discovery + bounded classification probes
- **What it scores**: ECB, static IV, weak hash, predictable token generation,
  and JWT algorithm-confusion classification
- **What it does not score**: padding-oracle testing, timing-side-channel
  testing, or network-neighborhood discovery
- **Probe rule**: scoring requires behavioral evidence, not only endpoint names
  or response metadata

### Positive Targets

| ID | Endpoint | Expected Finding |
|----|----------|------------------|
| C-01 | `/api/encrypt` | `ECBMode / AES-128-ECB` |
| C-02 | `/api/encrypt-cbc-static` | `StaticIV / AES-128-CBC` |
| C-03 | `/api/hash` | `WeakHash / MD5` |
| C-04 | `/api/hash-sha1` | `WeakHash / SHA-1` |
| C-05 | `/api/token` | `InsecureRandom / LCG` |
| C-06 | `/api/auth` | `JWTAlgConfusion / JWT-none` |
| C-07 | `/api/auth-rsa` | `JWTAlgConfusion / JWT-RS256-to-HS256` |

### Negative Controls

| ID | Endpoint | Expected Result |
|----|----------|-----------------|
| C-NC-01 | `/api/encrypt-strong` | Must not trigger phase03 findings |
| C-NC-02 | `/api/hash-strong` | Must not trigger phase03 findings |
| C-NC-03 | `/api/token-secure` | Must not trigger phase03 findings |

## Full-Suite Backlog

Draft definitions for later suites remain in the repository, but they are not the first suite to stabilize:

- Phase04 active oracle and timing validation
- later operational robustness suites

Those later suites build on `phase03`; they do not replace it.

## Quick Start

```bash
# Generate weak and strong TLS certificates
cd benchmarks/nginx && bash generate-certs.sh && cd ../..

# Start all benchmark servers
docker compose -f benchmarks/docker-compose.yaml up -d

# Verify servers work correctly
pytest benchmarks/test_servers.py -v

# Run the stabilized Phase 0+1 suite
python -m benchmarks.runner --target http://localhost:9000 --suite phase01

# Run the stabilized Phase 2 discovery suite
python -m benchmarks.runner --target http://localhost:9000 --suite phase02

# Run the stabilized Phase 3 classification suite
python -m benchmarks.runner --target http://localhost:9000 --suite phase03

# Run a single target from that suite
python -m benchmarks.runner --target http://localhost:9000 --suite phase01 --benchmark BM-09

# Save report
python -m benchmarks.runner --target http://localhost:9000 --suite phase01 --report benchmarks/results/
```

## References

1. Schlichtig et al., "CamBench — Cryptographic API Misuse Detection Tool Benchmark Suite", MSR 2022
2. Afrose et al., "CryptoAPI-Bench: A Comprehensive Benchmark on Java Cryptographic API Misuses", IEEE SecDev 2019
3. Ami et al., "Why Crypto-detectors Fail" (MASC taxonomy), USENIX Security 2022
4. Qualys SSL Labs, "SSL Server Rating Guide", v2009r
5. OWASP, "Web Security Testing Guide v4.2", Chapter 9
6. Boehm et al., "Cryptoscope", arXiv:2503.19531
7. CryptoScope LLM, arXiv:2508.11599
