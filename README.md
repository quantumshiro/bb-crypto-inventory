# bb-crypto-inventory

**Blackbox Cryptographic Inventory Tool**

LLM-agent-driven automated cryptographic asset discovery and vulnerability detection using only endpoint URLs.

## Overview

This tool implements a fully blackbox approach to cryptographic inventory construction for PQC (Post-Quantum Cryptography) migration readiness assessment. Unlike existing SOTA methods that require source code access (whitebox), this tool only needs an endpoint URL as input.

### Key Features

- **Blackbox-only**: No source code, binary, or internal access required
- **LLM-Agent Orchestrated**: Plan-Act-Observe loop driven by LLM reasoning
- **6 Observation Channels**: TLS handshake, ciphertext statistics, error differential, timing side-channel, hash/signature structure, randomness quality
- **4-Phase Analysis**: Recon → Protocol Layer → Application Layer → Oracle/Timing
- **CBOM Output**: CycloneDX Cryptographic Bill of Materials (JSON)
- **PQC Readiness Scoring**: Identifies quantum-vulnerable cryptographic assets

## Architecture

```
┌─────────────────────────────────────────┐
│           LLM Agent (Orchestrator)       │
│         Plan → Act → Observe Loop        │
├─────────────────────────────────────────┤
│  Phase 0: Recon                          │
│  ├── nmap scan                           │
│  ├── HTTP header analysis                │
│  ├── Certificate chain extraction        │
│  └── OpenAPI spec discovery              │
├─────────────────────────────────────────┤
│  Phase 1: Protocol Layer                 │
│  ├── TLS cipher suite enumeration        │
│  ├── Protocol version testing            │
│  ├── PFS verification                    │
│  ├── Downgrade attack resistance         │
│  ├── PQC (ML-KEM/Kyber) support check   │
│  └── SSH algorithm enumeration           │
├─────────────────────────────────────────┤
│  Phase 2: Application Layer              │
│  ├── ECB mode detection                  │
│  ├── Static IV detection                 │
│  ├── Padding scheme estimation           │
│  ├── JWT analysis & alg confusion        │
│  ├── Hash/signature length analysis      │
│  └── Randomness quality (NIST 800-22)    │
├─────────────────────────────────────────┤
│  Phase 3: Oracle & Timing               │
│  ├── Padding Oracle detection            │
│  ├── Bleichenbacher attack testing       │
│  ├── HMAC timing analysis                │
│  └── Constant-time implementation check  │
└─────────────────────────────────────────┘
         │
         ▼
   CBOM (CycloneDX JSON) + Vulnerability Report
```

## Installation

```bash
# Clone the repository
git clone https://github.com/NyxFoundation/bb-crypto-inventory.git
cd bb-crypto-inventory

# Install with pip
pip install -e .

# Or with uv
uv pip install -e .
```

### Prerequisites

- Python 3.11+
- nmap (for port scanning)
- OpenSSL (for TLS testing)
- An OpenAI-compatible API key for the LLM agent

## Quick Start

```bash
# Basic scan
bbci scan https://example.com

# Full scan with all phases
bbci scan --full https://example.com

# Protocol-only scan (Phase 0+1, faster)
bbci scan --phase 0,1 https://example.com

# Output CBOM to file
bbci scan https://example.com -o cbom.json

# Set confidence threshold
bbci scan --min-confidence 0.7 https://example.com
```

## Configuration

```yaml
# bbci.yaml
agent:
  model: "gpt-4o"
  max_iterations: 5
  timeout_minutes: 30

scan:
  phases: [0, 1, 2, 3]
  min_confidence: 0.5
  slow_pace: false  # Enable for WAF/rate-limit evasion

output:
  format: "cyclonedx"  # cyclonedx | json | markdown
  include_evidence: true
  include_remediation: true
```

## Detection Capabilities

### ✅ Detectable (Blackbox)
| Category | Detection Method | Confidence |
|----------|-----------------|------------|
| ECB Mode | Repeated ciphertext block analysis | ~1.0 |
| Static IV/Nonce | Deterministic encryption detection | High |
| Weak Hash (MD5/SHA-1) | Output length analysis | High |
| Insecure Random | NIST SP 800-22 statistical tests | Medium-High |
| Padding Oracle | Error differential analysis | High |
| Insecure Cipher Suite | TLS enumeration | ~1.0 |
| No PFS | Static RSA key exchange detection | ~1.0 |
| JWT alg confusion | Algorithm substitution testing | High |

### ❌ Blackbox Limitations
| Category | Reason |
|----------|--------|
| Hardcoded Key | Internal state, not observable externally |
| Insecure Key Derivation | Internal implementation detail |
| Insecure Key Storage | Server-side storage, no external signal |

## Project Structure

```
bb-crypto-inventory/
├── src/
│   └── bbci/
│       ├── __init__.py
│       ├── cli.py              # CLI entry point
│       ├── agent/
│       │   ├── __init__.py
│       │   ├── orchestrator.py # LLM Plan-Act-Observe loop
│       │   └── prompts.py      # System prompts for the agent
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── recon.py        # Phase 0: Reconnaissance tools
│       │   ├── tls.py          # Phase 1: TLS/SSH probing
│       │   ├── application.py  # Phase 2: App-layer analysis
│       │   ├── oracle.py       # Phase 3: Oracle & timing
│       │   └── common.py       # Shared utilities
│       ├── models/
│       │   ├── __init__.py
│       │   ├── finding.py      # Finding/vulnerability models
│       │   └── cbom.py         # CBOM output models
│       └── config.py           # Configuration management
├── tests/
│   ├── __init__.py
│   ├── test_recon.py
│   ├── test_tls.py
│   ├── test_application.py
│   └── test_oracle.py
├── pyproject.toml
├── bbci.yaml.example
└── README.md
```

## References

- CISA Strategy for Automated PQC Discovery (2024/08)
- AIVD/CWI/TNO PQC Migration Handbook (2024/12)
- PQCC PQC Migration Roadmap (2025/05)
- Hasan et al. IEEE Access 2024 — Dependency graph for migration optimization
- Boehm et al. Cryptoscope arXiv:2503.19531
- CryptoScope LLM arXiv:2508.11599
- Beyond Static Tools arXiv:2411.09772
- KG+LLM Framework arXiv:2601.03504

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or PR.
