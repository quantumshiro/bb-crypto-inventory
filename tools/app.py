#!/usr/bin/env python3
"""Phase 2: Application layer analysis tools.

Usage:
    uv run python tools/app.py ciphertext <url> <payload> [--n 10]
    uv run python tools/app.py jwt <token>
    uv run python tools/app.py tokens <url> [--n 100]
    uv run python tools/app.py randomness <file>     # file: one hex token per line
    uv run python tools/app.py hash-length <hash1> [<hash2> ...]
"""

import base64
import json
import os
import sys
import time
from collections import Counter

import httpx


def send_and_compare_ciphertext(url: str, payload: str, n: int = 10) -> dict:
    """Send same plaintext N times, compare ciphertext."""
    outputs = []
    for i in range(n):
        try:
            resp = httpx.post(url, content=payload.encode(), verify=False, timeout=15)
            outputs.append(resp.content)
        except Exception as e:
            outputs.append(f"ERROR:{e}".encode())

    unique = len(set(outputs))
    # ECB check: look for repeated 16-byte blocks
    ecb_detected = False
    for out in outputs:
        if len(out) >= 32:
            blocks = [out[i:i+16] for i in range(0, len(out), 16)]
            if any(c > 1 for c in Counter(blocks).values()):
                ecb_detected = True
                break

    return {
        "tool": "send_and_compare_ciphertext",
        "url": url, "payload_length": len(payload), "n": n,
        "unique_outputs": unique,
        "static_iv_detected": unique == 1 and len(outputs) > 1,
        "ecb_mode_detected": ecb_detected,
        "output_lengths": [len(o) for o in outputs[:5]],
        "sample_outputs_b64": [base64.b64encode(o).decode() for o in outputs[:3]],
    }


def analyze_jwt(token: str) -> dict:
    """Analyze JWT header and payload."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {"tool": "analyze_jwt", "error": "Invalid JWT format"}

    try:
        def _decode(s: str) -> dict:
            padded = s + "=" * (4 - len(s) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))

        header = _decode(parts[0])
        payload = _decode(parts[1])
        has_sig = len(parts) == 3 and bool(parts[2])

        return {
            "tool": "analyze_jwt",
            "header": header,
            "payload_keys": list(payload.keys()),
            "algorithm": header.get("alg", "unknown"),
            "type": header.get("typ", "unknown"),
            "has_signature": has_sig,
        }
    except Exception as e:
        return {"tool": "analyze_jwt", "error": str(e)}


def collect_tokens(url: str, n: int = 100) -> dict:
    """Collect tokens from repeated requests."""
    tokens = []
    for i in range(n):
        try:
            resp = httpx.get(url, verify=False, timeout=10)
            data = resp.json() if "json" in resp.headers.get("content-type", "") else {}
            # Look for token-like fields
            for key in ["token", "session_id", "csrf_token", "id"]:
                if key in data:
                    tokens.append(data[key])
                    break
            # Also check cookies
            for cookie in resp.headers.get_list("set-cookie"):
                name_val = cookie.split(";")[0]
                if "=" in name_val:
                    tokens.append(name_val.split("=", 1)[1])
                    break
        except Exception:
            pass

    return {
        "tool": "collect_tokens",
        "url": url, "requested": n, "collected": len(tokens),
        "tokens": tokens[:50],
        "unique": len(set(tokens[:50])),
    }


def randomness_test(samples: list[str]) -> dict:
    """Run NIST SP 800-22 inspired statistical tests."""
    if len(samples) < 10:
        return {"tool": "randomness_test", "error": f"Need ≥10 samples, got {len(samples)}"}

    byte_seqs = []
    for s in samples:
        try:
            byte_seqs.append(bytes.fromhex(s.strip()))
        except ValueError:
            byte_seqs.append(s.encode())

    all_bytes = b"".join(byte_seqs)
    bits = "".join(f"{b:08b}" for b in all_bytes)
    total = len(bits)
    tests: dict = {}

    # Frequency test
    if total > 0:
        ones = bits.count("1")
        ratio = ones / total
        tests["frequency"] = {
            "ones_ratio": round(ratio, 4),
            "deviation": round(abs(ratio - 0.5), 4),
            "pass": abs(ratio - 0.5) < 0.05,
        }

    # Runs test
    if total > 1:
        runs = 1 + sum(1 for i in range(1, total) if bits[i] != bits[i-1])
        ones = bits.count("1")
        zeros = total - ones
        expected = (2 * ones * zeros) / total + 1 if total > 0 else 0
        dev = abs(runs - expected) / total if total > 0 else 0
        tests["runs"] = {"observed": runs, "expected": round(expected, 1),
                         "deviation": round(dev, 6), "pass": dev < 0.05}

    # Sequential correlation
    if len(byte_seqs) >= 3:
        diffs = []
        for i in range(1, min(len(byte_seqs), 100)):
            a = int.from_bytes(byte_seqs[i-1][:8], "big") if len(byte_seqs[i-1]) >= 8 else 0
            b = int.from_bytes(byte_seqs[i][:8], "big") if len(byte_seqs[i]) >= 8 else 0
            if a != 0:
                diffs.append(b - a)
        if diffs:
            unique_diffs = len(set(diffs))
            tests["sequential"] = {
                "unique_differences": unique_diffs,
                "is_sequential": unique_diffs <= 3,
                "pass": unique_diffs > 3,
            }

    passed = sum(1 for t in tests.values() if t.get("pass", True))
    return {
        "tool": "randomness_test",
        "total_samples": len(samples), "total_bits": total,
        "tests": tests,
        "passed": passed, "total_tests": len(tests),
        "overall_pass": all(t.get("pass", True) for t in tests.values()),
    }


def analyze_hash_length(hashes: list[str]) -> dict:
    """Identify hash algorithm from output length."""
    length_map = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
    results = []
    for h in hashes:
        h = h.strip().lower()
        algo = length_map.get(len(h), f"Unknown ({len(h)*4}-bit)")
        weak = len(h) in (32, 40)
        results.append({"hash_preview": h[:16] + "...", "hex_length": len(h),
                        "algorithm": algo, "weak": weak})
    return {"tool": "analyze_hash_length", "analyses": results}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "ciphertext":
        url, payload = sys.argv[2], sys.argv[3]
        n = int(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[4] == "--n" else 10
        result = send_and_compare_ciphertext(url, payload, n)
    elif cmd == "jwt":
        result = analyze_jwt(sys.argv[2])
    elif cmd == "tokens":
        url = sys.argv[2]
        n = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[3] == "--n" else 100
        result = collect_tokens(url, n)
    elif cmd == "randomness":
        with open(sys.argv[2]) as f:
            samples = [line.strip() for line in f if line.strip()]
        result = randomness_test(samples)
    elif cmd == "hash-length":
        result = analyze_hash_length(sys.argv[2:])
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

    print(json.dumps(result, indent=2, default=str))
