#!/usr/bin/env python3
"""Phase 0: Reconnaissance tools.

Usage:
    uv run python tools/recon.py nmap <host> [--ports 22,80,443,8443]
    uv run python tools/recon.py headers <url>
    uv run python tools/recon.py cert <host> [--port 443]
    uv run python tools/recon.py openapi <base_url>
    uv run python tools/recon.py all <url>
"""

import json
import re
import subprocess
import sys
from urllib.parse import urlparse

import httpx


def nmap_scan(host: str, ports: str = "22,80,443,8080,8443,993,995,587") -> dict:
    """Run nmap port scan."""
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--open", "-p", ports, host],
            capture_output=True, text=True, timeout=30,
        )
        return {
            "tool": "nmap_scan",
            "host": host,
            "ports": ports,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except Exception as e:
        return {"tool": "nmap_scan", "error": str(e)}


def fetch_http_headers(url: str) -> dict:
    """Fetch HTTP response headers."""
    try:
        resp = httpx.head(url, verify=False, follow_redirects=True, timeout=15)
        headers = dict(resp.headers)
        return {
            "tool": "fetch_http_headers",
            "url": url,
            "status_code": resp.status_code,
            "headers": headers,
            "security_headers": {
                k: headers.get(k) for k in [
                    "server", "x-powered-by", "strict-transport-security",
                    "content-security-policy", "x-content-type-options",
                ] if headers.get(k)
            },
            "has_hsts": "strict-transport-security" in headers,
        }
    except Exception as e:
        return {"tool": "fetch_http_headers", "error": str(e)}


def fetch_certificate_chain(host: str, port: int = 443) -> dict:
    """Fetch TLS certificate chain via openssl."""
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", host, "-showcerts"],
            capture_output=True, text=True, timeout=15,
            input="",
        )
        combined = result.stdout + result.stderr

        info: dict = {}
        for pattern, key in [
            (r"subject=(.+)", "subject"),
            (r"issuer=(.+)", "issuer"),
            (r"Signature Algorithm:\s*(\S+)", "signature_algorithm"),
            (r"Server public key is (\d+) bit", "key_length_bits"),
            (r"Protocol\s*:\s*(\S+)", "negotiated_protocol"),
            (r"Cipher\s*:\s*(\S+)", "negotiated_cipher"),
        ]:
            m = re.search(pattern, combined)
            if m:
                val = m.group(1).strip()
                info[key] = int(val) if key == "key_length_bits" else val

        info["chain_length"] = combined.count("-----BEGIN CERTIFICATE-----")

        return {
            "tool": "fetch_certificate_chain",
            "host": host,
            "port": port,
            "certificate": info,
            "raw_output": combined[:3000],
        }
    except Exception as e:
        return {"tool": "fetch_certificate_chain", "error": str(e)}


def probe_openapi_spec(base_url: str) -> dict:
    """Probe for OpenAPI/Swagger specs."""
    paths = [
        "/swagger.json", "/openapi.json", "/api-docs",
        "/v1/swagger.json", "/v2/swagger.json", "/v3/api-docs",
    ]
    found = []
    for path in paths:
        url = base_url.rstrip("/") + path
        try:
            resp = httpx.get(url, verify=False, follow_redirects=True, timeout=10)
            if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
                spec = resp.json()
                endpoints = []
                for p, methods in spec.get("paths", {}).items():
                    for m in methods:
                        if m.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                            endpoints.append(f"{m.upper()} {p}")
                found.append({
                    "path": path,
                    "title": spec.get("info", {}).get("title", ""),
                    "endpoints": endpoints[:30],
                })
        except Exception:
            continue

    return {
        "tool": "probe_openapi_spec",
        "base_url": base_url,
        "specs_found": len(found),
        "specs": found,
    }


def run_all(url: str) -> dict:
    """Run all recon tools against a URL."""
    parsed = urlparse(url)
    host = parsed.hostname or url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    results = {
        "target": url,
        "host": host,
        "nmap": nmap_scan(host),
        "headers": fetch_http_headers(url),
        "certificate": fetch_certificate_chain(host, port),
        "openapi": probe_openapi_spec(url),
    }
    return results


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    target = sys.argv[2]

    if cmd == "nmap":
        ports = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == "--ports" else "22,80,443,8080,8443"
        result = nmap_scan(target, ports)
    elif cmd == "headers":
        result = fetch_http_headers(target)
    elif cmd == "cert":
        port = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[3] == "--port" else 443
        result = fetch_certificate_chain(target, port)
    elif cmd == "openapi":
        result = probe_openapi_spec(target)
    elif cmd == "all":
        result = run_all(target)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

    print(json.dumps(result, indent=2, default=str))
