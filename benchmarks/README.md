# Benchmarks

Blackbox cryptographic vulnerability benchmark suite for evaluating `bbci` detection capabilities.

## Standards Alignment

This benchmark suite aligns with established standards and taxonomies from the cryptographic security research community:

### Vulnerability Taxonomy
- **[CamBench](https://github.com/CROSSINGTUD/CamBench)** (MSR 2022, [arXiv:2204.06447](https://arxiv.org/abs/2204.06447)) — The standard benchmark for cryptographic API misuse detection tools. Our vulnerability categories (ECBMode, StaticIV, WeakHash, InsecureRandom, etc.) map to CamBench rules.
- **[CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench)** (IEEE SecDev 2019) — 171 test cases across 16 misuse rules. Our categories include cross-references to CryptoAPI-Bench rule numbers.
- **[MASC](https://dl.acm.org/doi/10.1145/3611643.3613099)** (FSE 2023, [arXiv:2107.07065](https://arxiv.org/abs/2107.07065)) — Mutation-based evaluation taxonomy with 12 operators. Our benchmarks reference corresponding MASC mutation operators where applicable.

### TLS/SSL Scoring
- **[SSL Labs Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)** v2009r (Qualys, 2025) — The de facto standard for TLS configuration assessment. Our TLS benchmarks use the same Protocol (30%) + Key Exchange (30%) + Cipher Strength (40%) scoring methodology with grade caps.

### Testing Methodology
- **[OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/)** Chapter 9: Testing for Weak Cryptography — Our test IDs map to OWASP WSTG identifiers (WSTG-CRYP-01 through WSTG-CRYP-04).
- **CWE References** — Each vulnerability is mapped to relevant [MITRE CWE](https://cwe.mitre.org/) entries.

### Randomness Testing
- **[NIST SP 800-22](https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final)** Rev 1a — Statistical test suite for random number generators. Used for the InsecureRandom (BM-05) benchmark.

### Output Format
- **[CycloneDX CBOM](https://cyclonedx.org/)** v1.6 — Cryptographic Bill of Materials, the emerging standard for crypto asset inventory.

### What's Novel
> **Important**: No established blackbox crypto inventory benchmark exists in the literature. CamBench and CryptoAPI-Bench target whitebox/static analysis only. This benchmark adapts their vulnerability taxonomy to a blackbox observation context — this adaptation itself is an academic contribution (see design doc §4.4).

## Benchmark Targets

| ID | Vulnerability | CamBench Rule | OWASP WSTG | CWE | Channel | Confidence |
|----|--------------|---------------|------------|-----|---------|-----------|
| BM-01 | ECB Mode | Rule 3 | WSTG-CRYP-04 | CWE-327 | CH2 | ~1.0 |
| BM-02 | Static IV | Rule 4 | WSTG-CRYP-04 | CWE-329 | CH2 | High |
| BM-03 | Weak Hash (MD5) | Rule 16 | WSTG-CRYP-04 | CWE-328 | CH5 | High |
| BM-04 | Weak Hash (SHA-1) | Rule 16 | WSTG-CRYP-04 | CWE-328 | CH5 | High |
| BM-05 | Insecure Random (LCG) | Rule 14 | WSTG-CRYP-04 | CWE-330 | CH6 | Medium-High |
| BM-06 | Padding Oracle | N/A (runtime) | WSTG-CRYP-02 | CWE-209 | CH3 | High |
| BM-07 | JWT alg=none | N/A (JWT) | WSTG-CRYP-04 | CWE-347 | CH5 | ~1.0 |
| BM-08 | JWT RS256→HS256 | N/A (JWT) | WSTG-CRYP-04 | CWE-347 | CH5 | High |
| BM-09 | Weak TLS | N/A (config) | WSTG-CRYP-01 | CWE-326 | CH1 | ~1.0 |
| BM-10 | Timing Leak | N/A (runtime) | N/A | CWE-208 | CH4 | Medium |

## Scoring Methodology

Following CamBench/CryptoAPI-Bench evaluation practice:
- **Precision**: TP / (TP + FP) — Fraction of reported findings that are true positives
- **Recall**: TP / (TP + FN) — Fraction of ground-truth vulnerabilities detected
- **F1 Score**: Harmonic mean of precision and recall
- **Confidence Calibration**: How well confidence scores match empirical accuracy
- **SSL Labs Grade Accuracy**: For TLS benchmarks, compare against expected grade
- **Detection Latency**: Time to detect each vulnerability class

### Comparison Baselines
| Baseline | Scope | Type |
|----------|-------|------|
| testssl.sh | TLS/SSL only | Deterministic tool |
| sslyze | TLS/SSL only | Deterministic tool |
| CryptoScope LLM | Static (whitebox) | LLM-based |
| Random baseline | All phases | Random classifier |

## Quick Start

```bash
# Generate TLS certificates
cd benchmarks/nginx && bash generate-certs.sh && cd ../..

# Start all benchmark servers
docker compose -f benchmarks/docker-compose.yaml up -d

# Verify servers work correctly
pytest benchmarks/test_servers.py -v

# Run benchmark suite
python -m benchmarks.runner --target http://localhost:9000

# Run with specific model
python -m benchmarks.runner --target http://localhost:9000 --model gpt-4o

# Save report
python -m benchmarks.runner --target http://localhost:9000 --report benchmarks/results/
```

## References

1. Schlichtig et al., "CamBench — Cryptographic API Misuse Detection Tool Benchmark Suite", MSR 2022
2. Afrose et al., "CryptoAPI-Bench: A Comprehensive Benchmark on Java Cryptographic API Misuses", IEEE SecDev 2019
3. Ami et al., "Why Crypto-detectors Fail" (MASC taxonomy), USENIX Security 2022
4. Qualys SSL Labs, "SSL Server Rating Guide", v2009r
5. OWASP, "Web Security Testing Guide v4.2", Chapter 9
6. NIST SP 800-22 Rev 1a, "Statistical Test Suite for Random Number Generators"
7. Boehm et al., "Cryptoscope", arXiv:2503.19531
8. CryptoScope LLM, arXiv:2508.11599
