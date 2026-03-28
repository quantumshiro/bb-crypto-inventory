#!/usr/bin/env python3
"""Phase 3: Oracle and timing analysis tools.

Usage:
    uv run python tools/oracle.py padding <url> <ciphertext_hex_or_b64>
    uv run python tools/oracle.py timing <url> <payload1> <payload2> [--n 100]
"""

import base64
import json
import statistics
import sys
import time
from collections import Counter

import httpx


def padding_oracle_test(url: str, ciphertext: str) -> dict:
    """Test for Padding Oracle by modifying last byte."""
    try:
        ct = bytes.fromhex(ciphertext)
    except ValueError:
        try:
            ct = base64.b64decode(ciphertext + "==")
        except Exception:
            return {"tool": "padding_oracle_test", "error": "Cannot decode ciphertext"}

    if len(ct) < 16:
        return {"tool": "padding_oracle_test", "error": "Ciphertext too short"}

    status_codes: list[int] = []
    bodies: list[str] = []
    times: list[float] = []

    client = httpx.Client(verify=False, follow_redirects=False, timeout=15)
    for byte_val in range(256):
        modified = bytearray(ct)
        modified[-1] = byte_val

        start = time.monotonic()
        try:
            resp = client.post(url, content=bytes(modified).hex(),
                              headers={"Content-Type": "application/octet-stream"})
            elapsed = (time.monotonic() - start) * 1000
            status_codes.append(resp.status_code)
            bodies.append(resp.text[:200])
            times.append(elapsed)
        except Exception:
            elapsed = (time.monotonic() - start) * 1000
            times.append(elapsed)
    client.close()

    status_dist = dict(Counter(status_codes))
    body_dist = len(set(bodies))

    oracle_detected = len(status_dist) >= 2 or (2 <= body_dist <= 10)
    evidence = []
    if len(status_dist) >= 2:
        evidence.append(f"Multiple status codes: {status_dist}")
    if 2 <= body_dist <= 10:
        evidence.append(f"{body_dist} distinct response patterns")
    if times:
        stdev = statistics.stdev(times) if len(times) > 1 else 0
        mean = statistics.mean(times)
        cv = stdev / mean if mean > 0 else 0
        if cv > 0.3:
            oracle_detected = True
            evidence.append(f"High timing variance (CV={cv:.2f})")

    return {
        "tool": "padding_oracle_test",
        "url": url,
        "probes": 256,
        "successful": len(status_codes),
        "status_distribution": status_dist,
        "unique_bodies": body_dist,
        "timing": {
            "mean_ms": round(statistics.mean(times), 2) if times else 0,
            "stdev_ms": round(statistics.stdev(times), 2) if len(times) > 1 else 0,
        },
        "oracle_detected": oracle_detected,
        "evidence": evidence,
    }


def timing_analysis(url: str, payloads: list[str], n: int = 100) -> dict:
    """Measure response timing for different payloads."""
    measurements: dict[str, list[float]] = {p: [] for p in payloads}

    client = httpx.Client(verify=False, follow_redirects=False, timeout=15)
    for _ in range(n):
        for payload in payloads:
            start = time.monotonic()
            try:
                client.post(url, content=payload)
            except Exception:
                pass
            measurements[payload].append((time.monotonic() - start) * 1000)
    client.close()

    stats: dict = {}
    means = []
    for payload, times in measurements.items():
        if len(times) > 1:
            # Remove outliers (3-sigma)
            m, s = statistics.mean(times), statistics.stdev(times)
            filtered = [t for t in times if abs(t - m) < 3 * s]
        else:
            filtered = times
        if filtered:
            mean = statistics.mean(filtered)
            means.append(mean)
            stats[payload[:32]] = {
                "mean_ms": round(mean, 4),
                "median_ms": round(statistics.median(filtered), 4),
                "stdev_ms": round(statistics.stdev(filtered), 4) if len(filtered) > 1 else 0,
                "n": len(filtered),
            }

    result: dict = {
        "tool": "timing_analysis",
        "url": url,
        "payloads_count": len(payloads),
        "measurements_per_payload": n,
        "stats": stats,
    }

    if len(means) >= 2:
        diff = max(means) - min(means)
        avg = statistics.mean(means)
        rel = diff / avg if avg > 0 else 0
        result["max_diff_ms"] = round(diff, 4)
        result["relative_diff"] = round(rel, 6)
        result["timing_leak_detected"] = rel > 0.01

    return result


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "padding":
        result = padding_oracle_test(sys.argv[2], sys.argv[3])
    elif cmd == "timing":
        url = sys.argv[2]
        payloads = sys.argv[3:]
        # Check for --n flag
        n = 100
        if "--n" in payloads:
            idx = payloads.index("--n")
            n = int(payloads[idx + 1])
            payloads = payloads[:idx]
        result = timing_analysis(url, payloads, n)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

    print(json.dumps(result, indent=2, default=str))
