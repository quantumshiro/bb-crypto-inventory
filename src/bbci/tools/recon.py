"""Phase 0: Reconnaissance tools."""

from __future__ import annotations

import json
import logging
import re
from urllib.parse import urlparse

import httpx

from bbci.tools.common import ToolResult, run_command, timed

logger = logging.getLogger("bbci")


class ReconTools:
    """Phase 0 reconnaissance tools for initial endpoint discovery."""

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    @timed
    async def nmap_scan(self, host: str, ports: str = "22,80,443,8080,8443,993,995,587") -> ToolResult:
        """Run nmap port scan to identify open ports and services.

        Tool: nmap_scan(host, ports)
        """
        stdout, stderr, rc = await run_command(
            ["nmap", "-sV", "--open", "-p", ports, host, "-oX", "-"],
            timeout=self.timeout,
        )

        if rc != 0:
            return ToolResult(
                tool_name="nmap_scan",
                success=False,
                error=f"nmap failed (rc={rc}): {stderr[:500]}",
            )

        # Parse XML output for port info
        open_ports = []
        for match in re.finditer(
            r'<port protocol="(\w+)" portid="(\d+)">'
            r'.*?<state state="open".*?/>'
            r'.*?<service name="([^"]*)".*?product="([^"]*)".*?version="([^"]*)"',
            stdout,
            re.DOTALL,
        ):
            proto, port, service, product, version = match.groups()
            open_ports.append({
                "protocol": proto,
                "port": int(port),
                "service": service,
                "product": product,
                "version": version,
            })

        # Simpler fallback parsing
        if not open_ports:
            for match in re.finditer(
                r'<port protocol="(\w+)" portid="(\d+)">.*?<state state="open"',
                stdout,
                re.DOTALL,
            ):
                proto, port = match.groups()
                open_ports.append({
                    "protocol": proto,
                    "port": int(port),
                    "service": "unknown",
                })

        return ToolResult(
            tool_name="nmap_scan",
            success=True,
            data={
                "host": host,
                "open_ports": open_ports,
                "crypto_ports": [
                    p for p in open_ports
                    if p["port"] in (22, 443, 8443, 993, 995, 587, 636, 989, 990)
                ],
            },
        )

    @timed
    async def fetch_http_headers(self, url: str) -> ToolResult:
        """Fetch HTTP response headers for server/framework fingerprinting.

        Tool: fetch_http_headers(url)
        """
        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=self.timeout
            ) as client:
                resp = await client.head(url)

            headers = dict(resp.headers)

            # Extract security-relevant headers
            security_headers = {
                "server": headers.get("server"),
                "x-powered-by": headers.get("x-powered-by"),
                "strict-transport-security": headers.get("strict-transport-security"),
                "content-security-policy": headers.get("content-security-policy"),
                "x-content-type-options": headers.get("x-content-type-options"),
                "x-frame-options": headers.get("x-frame-options"),
            }
            # Remove None values
            security_headers = {k: v for k, v in security_headers.items() if v is not None}

            return ToolResult(
                tool_name="fetch_http_headers",
                success=True,
                data={
                    "url": url,
                    "status_code": resp.status_code,
                    "headers": headers,
                    "security_headers": security_headers,
                    "has_hsts": "strict-transport-security" in headers,
                },
            )
        except Exception as e:
            return ToolResult(
                tool_name="fetch_http_headers",
                success=False,
                error=str(e),
            )

    @timed
    async def fetch_certificate_chain(self, host: str, port: int = 443) -> ToolResult:
        """Fetch and analyze the server's TLS certificate chain.

        Tool: fetch_certificate_chain(host, port)
        """
        stdout, stderr, rc = await run_command(
            [
                "openssl", "s_client",
                "-connect", f"{host}:{port}",
                "-servername", host,
                "-showcerts",
            ],
            timeout=self.timeout,
        )

        if rc != 0 and not stdout:
            return ToolResult(
                tool_name="fetch_certificate_chain",
                success=False,
                error=f"openssl failed: {stderr[:500]}",
            )

        # Parse certificate info
        cert_info: dict = {}

        # Extract subject
        subject_match = re.search(r"subject=(.+)", stdout)
        if subject_match:
            cert_info["subject"] = subject_match.group(1).strip()

        # Extract issuer
        issuer_match = re.search(r"issuer=(.+)", stdout)
        if issuer_match:
            cert_info["issuer"] = issuer_match.group(1).strip()

        # Get detailed cert info with x509
        cert_pem_match = re.search(
            r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
            stdout,
            re.DOTALL,
        )

        if cert_pem_match:
            cert_pem = cert_pem_match.group(1)
            x509_out, _, _ = await run_command(
                ["openssl", "x509", "-noout", "-text"],
                timeout=10,
            )
            # Parse from the full openssl output instead
            detail_stdout, _, _ = await run_command(
                [
                    "openssl", "s_client",
                    "-connect", f"{host}:{port}",
                    "-servername", host,
                ],
                timeout=self.timeout,
            )

            # Extract signature algorithm
            sig_match = re.search(r"Signature Algorithm:\s*(\S+)", stdout)
            if sig_match:
                cert_info["signature_algorithm"] = sig_match.group(1)

            # Extract key info
            key_match = re.search(r"Server public key is (\d+) bit", stdout + stderr)
            if key_match:
                cert_info["key_length_bits"] = int(key_match.group(1))

            # Extract protocol and cipher from connection info
            proto_match = re.search(r"Protocol\s*:\s*(\S+)", stdout + stderr)
            if proto_match:
                cert_info["negotiated_protocol"] = proto_match.group(1)

            cipher_match = re.search(r"Cipher\s*:\s*(\S+)", stdout + stderr)
            if cipher_match:
                cert_info["negotiated_cipher"] = cipher_match.group(1)

        # Count certificates in chain
        cert_count = stdout.count("-----BEGIN CERTIFICATE-----")
        cert_info["chain_length"] = cert_count

        # Determine key type and PQ vulnerability
        sig_alg = cert_info.get("signature_algorithm", "")
        key_len = cert_info.get("key_length_bits", 0)

        if "rsa" in sig_alg.lower():
            cert_info["key_type"] = "RSA"
            cert_info["pq_vulnerable"] = True
        elif "ecdsa" in sig_alg.lower() or "ec" in sig_alg.lower():
            cert_info["key_type"] = "ECDSA"
            cert_info["pq_vulnerable"] = True
        elif "ed25519" in sig_alg.lower():
            cert_info["key_type"] = "Ed25519"
            cert_info["pq_vulnerable"] = True
        elif "dilithium" in sig_alg.lower() or "ml-dsa" in sig_alg.lower():
            cert_info["key_type"] = "ML-DSA"
            cert_info["pq_vulnerable"] = False
        else:
            cert_info["key_type"] = "unknown"
            cert_info["pq_vulnerable"] = True  # Assume vulnerable if unknown

        return ToolResult(
            tool_name="fetch_certificate_chain",
            success=True,
            data={
                "host": host,
                "port": port,
                "certificate": cert_info,
            },
        )

    @timed
    async def probe_openapi_spec(self, base_url: str) -> ToolResult:
        """Attempt to discover OpenAPI/Swagger specification.

        Tool: probe_openapi_spec(base_url)
        """
        known_paths = [
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
            "/v1/swagger.json",
            "/v2/swagger.json",
            "/v3/api-docs",
            "/api/swagger.json",
            "/api/openapi.json",
            "/.well-known/openapi.json",
        ]

        found_specs: list[dict] = []

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=self.timeout
        ) as client:
            for path in known_paths:
                url = base_url.rstrip("/") + path
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        content_type = resp.headers.get("content-type", "")
                        if "json" in content_type or "yaml" in content_type:
                            try:
                                spec = resp.json()
                                endpoints = []
                                if "paths" in spec:
                                    for p, methods in spec["paths"].items():
                                        for method in methods:
                                            if method.upper() in (
                                                "GET", "POST", "PUT", "DELETE", "PATCH"
                                            ):
                                                endpoints.append(f"{method.upper()} {p}")
                                found_specs.append({
                                    "path": path,
                                    "title": spec.get("info", {}).get("title", ""),
                                    "version": spec.get("info", {}).get("version", ""),
                                    "endpoint_count": len(endpoints),
                                    "endpoints": endpoints[:50],  # Cap at 50
                                })
                            except (json.JSONDecodeError, ValueError):
                                pass
                except httpx.RequestError:
                    continue

        return ToolResult(
            tool_name="probe_openapi_spec",
            success=True,
            data={
                "base_url": base_url,
                "specs_found": len(found_specs),
                "specs": found_specs,
            },
        )

    def get_tool_definitions(self) -> list[dict]:
        """Return OpenAI function-calling tool definitions for Phase 0."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "nmap_scan",
                    "description": "Run nmap port scan to identify open ports and services on the target host.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "host": {
                                "type": "string",
                                "description": "Target hostname or IP address",
                            },
                            "ports": {
                                "type": "string",
                                "description": "Comma-separated port list (default: 22,80,443,8080,8443,993,995,587)",
                            },
                        },
                        "required": ["host"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "fetch_http_headers",
                    "description": "Fetch HTTP response headers for server/framework fingerprinting. Checks for security headers like HSTS.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "Target URL to fetch headers from",
                            },
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "fetch_certificate_chain",
                    "description": "Fetch and analyze the server's TLS certificate chain including signature algorithm, key length, issuer, and PQ vulnerability status.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "host": {
                                "type": "string",
                                "description": "Target hostname",
                            },
                            "port": {
                                "type": "integer",
                                "description": "TLS port (default: 443)",
                            },
                        },
                        "required": ["host"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "probe_openapi_spec",
                    "description": "Attempt to discover OpenAPI/Swagger specification at common paths to enumerate API endpoints.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "base_url": {
                                "type": "string",
                                "description": "Base URL of the target service",
                            },
                        },
                        "required": ["base_url"],
                    },
                },
            },
        ]

    async def execute_tool(self, name: str, args: dict) -> ToolResult:
        """Execute a tool by name with given arguments."""
        tools = {
            "nmap_scan": self.nmap_scan,
            "fetch_http_headers": self.fetch_http_headers,
            "fetch_certificate_chain": self.fetch_certificate_chain,
            "probe_openapi_spec": self.probe_openapi_spec,
        }
        if name not in tools:
            return ToolResult(
                tool_name=name, success=False, error=f"Unknown tool: {name}"
            )
        return await tools[name](**args)
