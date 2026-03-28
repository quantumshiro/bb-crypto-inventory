# Benchmarks

Blackbox cryptographic vulnerability benchmark suite for evaluating `bbci` detection capabilities.

## Overview

This benchmark provides a set of intentionally vulnerable test servers, each exposing specific cryptographic weaknesses that the bbci tool should detect via blackbox observation only.

### Benchmark Targets

| ID | Vulnerability | Channel | Expected Confidence |
|----|--------------|---------|-------------------|
| BM-01 | ECB Mode Encryption | CH2 | ~1.0 |
| BM-02 | Static IV/Nonce | CH2 | High |
| BM-03 | Weak Hash (MD5) | CH5 | High |
| BM-04 | Weak Hash (SHA-1) | CH5 | High |
| BM-05 | Insecure Random (java.util.Random-style LCG) | CH6 | Medium-High |
| BM-06 | Padding Oracle | CH3 | High |
| BM-07 | JWT alg=none | CH5 | ~1.0 |
| BM-08 | JWT RS256→HS256 confusion | CH5 | High |
| BM-09 | Weak TLS (configured via nginx) | CH1 | ~1.0 |
| BM-10 | Timing side-channel (non-constant-time HMAC) | CH4 | Medium |

## Quick Start

```bash
# Start all benchmark servers
docker compose up -d

# Run benchmark suite
python -m benchmarks.runner --target http://localhost:9000

# Run specific benchmark
python -m benchmarks.runner --target http://localhost:9000 --benchmark BM-01

# Generate report
python -m benchmarks.runner --target http://localhost:9000 --report benchmarks/results/
```

## Architecture

```
benchmarks/
├── servers/
│   ├── vulnerable_app.py      # Flask app with intentional crypto vulns
│   ├── requirements.txt
│   └── Dockerfile
├── nginx/
│   ├── nginx-weak.conf        # Weak TLS config (TLS 1.0, RC4, no PFS)
│   ├── nginx-strong.conf      # Strong TLS config (baseline)
│   └── certs/                 # Self-signed certs (generated at build)
├── ground_truth.yaml          # Expected findings for each benchmark
├── runner.py                  # Benchmark execution and scoring
├── scoring.py                 # Precision/recall/F1 calculation
├── docker-compose.yaml
└── README.md
```

## Scoring

The benchmark measures:
- **Precision**: Fraction of reported findings that are true positives
- **Recall**: Fraction of ground-truth vulnerabilities that were detected
- **F1 Score**: Harmonic mean of precision and recall
- **Confidence Calibration**: How well confidence scores match actual correctness
- **Detection Latency**: Time to detect each vulnerability class
