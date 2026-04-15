# Benchmarks

Blackbox cryptographic benchmark suite for evaluating `bbci` detection capabilities.

The first stabilized suite is `phase01`: a URL-scoped benchmark for Recon (Phase 0)
and Protocol Layer testing (Phase 1).

The normative design artifacts are:

- [phase01-spec.md](./phase01-spec.md)
- [phase01-scoring-spec.md](./phase01-scoring-spec.md)
- [phase01-report.schema.json](./phase01-report.schema.json)
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

## Full-Suite Backlog

Draft definitions for later suites remain in the repository, but they are not the first suite to stabilize:

- CH2: ECB mode, static IV
- CH5: MD5, SHA-1, JWT confusion
- CH6: weak randomness
- CH3/CH4: padding oracle, timing leak

Those will become separate suites after the Phase 0+1 benchmark is dependable.

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
