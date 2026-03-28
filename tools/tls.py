#!/usr/bin/env python3
"""Phase 1: TLS/SSH probing tools.

Usage:
    uv run python tools/tls.py ciphers <host> [--port 443]
    uv run python tools/tls.py versions <host> [--port 443]
    uv run python tools/tls.py downgrade <host> [--port 443]
    uv run python tools/tls.py pqc <host> [--port 443]
    uv run python tools/tls.py ssh <host> [--port 22]
    uv run python tools/tls.py all <host> [--port 443]
"""

import json
import re
import subprocess
import sys


def enumerate_cipher_suites(host: str, port: int = 443) -> dict:
    """Enumerate TLS cipher suites via nmap."""
    try:
        result = subprocess.run(
            ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), host],
            capture_output=True, text=True, timeout=60,
        )
        return {
            "tool": "enumerate_cipher_suites",
            "host": host, "port": port,
            "stdout": result.stdout,
            "returncode": result.returncode,
        }
    except Exception as e:
        return {"tool": "enumerate_cipher_suites", "error": str(e)}


def test_protocol_versions(host: str, port: int = 443) -> dict:
    """Test which TLS versions the server accepts."""
    results = {"tool": "test_protocol_versions", "host": host, "port": port, "versions": {}}

    for name, flag in [("tls1", "-tls1"), ("tls1_1", "-tls1_1"),
                        ("tls1_2", "-tls1_2"), ("tls1_3", "-tls1_3")]:
        try:
            r = subprocess.run(
                ["openssl", "s_client", "-connect", f"{host}:{port}",
                 "-servername", host, flag],
                capture_output=True, text=True, timeout=10, input="",
            )
            combined = r.stdout + r.stderr
            cipher_m = re.search(r"Cipher\s*:\s*(\S+)", combined)
            cipher = cipher_m.group(1) if cipher_m else "none"
            accepted = "CONNECTED" in combined and cipher not in ("0000", "(NONE)", "none")
            results["versions"][name] = {
                "accepted": accepted,
                "cipher": cipher if accepted else None,
            }
        except Exception as e:
            results["versions"][name] = {"accepted": False, "error": str(e)}

    return results


def test_downgrade_attack(host: str, port: int = 443) -> dict:
    """Test TLS_FALLBACK_SCSV support."""
    try:
        r = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", host, "-fallback_scsv", "-tls1_2"],
            capture_output=True, text=True, timeout=15, input="",
        )
        combined = r.stdout + r.stderr
        return {
            "tool": "test_downgrade_attack",
            "host": host, "port": port,
            "fallback_scsv": "inappropriate_fallback" in combined.lower(),
            "raw_output": combined[:2000],
        }
    except Exception as e:
        return {"tool": "test_downgrade_attack", "error": str(e)}


def test_pqc_support(host: str, port: int = 443) -> dict:
    """Test PQC hybrid key exchange support."""
    groups = ["X25519Kyber768Draft00", "X25519MLKEM768", "SecP256r1MLKEM768"]
    results = {"tool": "test_pqc_support", "host": host, "port": port, "groups": {}}

    for group in groups:
        try:
            r = subprocess.run(
                ["openssl", "s_client", "-connect", f"{host}:{port}",
                 "-servername", host, "-groups", group],
                capture_output=True, text=True, timeout=10, input="",
            )
            combined = r.stdout + r.stderr
            cipher_m = re.search(r"Cipher\s*:\s*(\S+)", combined)
            cipher = cipher_m.group(1) if cipher_m else "none"
            accepted = "CONNECTED" in combined and cipher not in ("0000", "(NONE)", "none")
            results["groups"][group] = {"accepted": accepted, "cipher": cipher if accepted else None}
        except Exception as e:
            results["groups"][group] = {"accepted": False, "error": str(e)}

    return results


def ssh_probe(host: str, port: int = 22) -> dict:
    """Probe SSH server algorithms."""
    try:
        r = subprocess.run(
            ["ssh", "-vvv", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
             "-o", "StrictHostKeyChecking=no", "-p", str(port), f"probe@{host}", "exit"],
            capture_output=True, text=True, timeout=15,
        )
        return {
            "tool": "ssh_probe",
            "host": host, "port": port,
            "stderr": r.stderr[:5000],
        }
    except Exception as e:
        return {"tool": "ssh_probe", "error": str(e)}


def run_all(host: str, port: int = 443) -> dict:
    """Run all TLS tools."""
    return {
        "target": f"{host}:{port}",
        "cipher_suites": enumerate_cipher_suites(host, port),
        "protocol_versions": test_protocol_versions(host, port),
        "downgrade": test_downgrade_attack(host, port),
        "pqc": test_pqc_support(host, port),
    }


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    cmd, target = sys.argv[1], sys.argv[2]
    port = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[3] == "--port" else (22 if cmd == "ssh" else 443)

    dispatch = {
        "ciphers": lambda: enumerate_cipher_suites(target, port),
        "versions": lambda: test_protocol_versions(target, port),
        "downgrade": lambda: test_downgrade_attack(target, port),
        "pqc": lambda: test_pqc_support(target, port),
        "ssh": lambda: ssh_probe(target, port),
        "all": lambda: run_all(target, port),
    }

    if cmd not in dispatch:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

    print(json.dumps(dispatch[cmd](), indent=2, default=str))
