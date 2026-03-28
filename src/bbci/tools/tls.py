"""Phase 1: TLS/SSH protocol layer probing tools."""

from __future__ import annotations

import logging
import re

from bbci.tools.common import ToolResult, run_command, timed

logger = logging.getLogger("bbci")

# Known weak cipher suites
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
    "DES-CBC3", "RC4-SHA", "RC4-MD5", "DES-CBC-SHA",
}

# TLS versions considered insecure
INSECURE_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


class TLSTools:
    """Phase 1 TLS/SSH protocol layer probing tools."""

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    @timed
    async def enumerate_cipher_suites(self, host: str, port: int = 443) -> ToolResult:
        """Enumerate all TLS cipher suites accepted by the server.

        Tool: enumerate_cipher_suites(host, port)
        """
        results: dict = {
            "host": host,
            "port": port,
            "accepted_suites": [],
            "weak_suites": [],
            "strong_suites": [],
            "has_pfs": False,
            "has_non_pfs": False,
        }

        # Use nmap's ssl-enum-ciphers script for comprehensive enumeration
        stdout, stderr, rc = await run_command(
            ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), host],
            timeout=60,
        )

        if rc == 0 and stdout:
            # Parse cipher suites from nmap output
            current_version = ""
            for line in stdout.split("\n"):
                line = line.strip()

                # Detect TLS version sections
                if "TLSv1.0" in line:
                    current_version = "TLSv1.0"
                elif "TLSv1.1" in line:
                    current_version = "TLSv1.1"
                elif "TLSv1.2" in line:
                    current_version = "TLSv1.2"
                elif "TLSv1.3" in line:
                    current_version = "TLSv1.3"

                # Parse cipher suite lines
                cipher_match = re.match(r".*?(TLS_\S+|SSL_\S+)", line)
                if cipher_match:
                    suite = cipher_match.group(1)
                    entry = {"suite": suite, "version": current_version}
                    results["accepted_suites"].append(entry)

                    # Check for weak ciphers
                    is_weak = any(w in suite for w in WEAK_CIPHERS)
                    if is_weak:
                        results["weak_suites"].append(entry)
                    else:
                        results["strong_suites"].append(entry)

                    # Check PFS
                    if "ECDHE" in suite or "DHE" in suite:
                        results["has_pfs"] = True
                    elif "RSA" in suite and "ECDHE" not in suite and "DHE" not in suite:
                        results["has_non_pfs"] = True

        # Fallback: use openssl to test common suites
        if not results["accepted_suites"]:
            for cipher_group in ["ALL", "HIGH", "MEDIUM", "LOW", "EXPORT"]:
                stdout, _, rc = await run_command(
                    [
                        "openssl", "s_client",
                        "-connect", f"{host}:{port}",
                        "-servername", host,
                        "-cipher", cipher_group,
                    ],
                    timeout=10,
                )
                if rc == 0:
                    cipher_match = re.search(r"Cipher\s*:\s*(\S+)", stdout)
                    if cipher_match and cipher_match.group(1) != "0000":
                        suite = cipher_match.group(1)
                        entry = {"suite": suite, "source": "openssl_fallback"}
                        results["accepted_suites"].append(entry)

                        is_weak = any(w in suite for w in WEAK_CIPHERS)
                        if is_weak:
                            results["weak_suites"].append(entry)

        return ToolResult(
            tool_name="enumerate_cipher_suites",
            success=True,
            data=results,
        )

    @timed
    async def test_protocol_versions(self, host: str, port: int = 443) -> ToolResult:
        """Test which TLS protocol versions the server accepts.

        Tool: test_protocol_versions(host, port)
        """
        versions_to_test = {
            "tls1": "-tls1",
            "tls1_1": "-tls1_1",
            "tls1_2": "-tls1_2",
            "tls1_3": "-tls1_3",
        }

        results: dict = {
            "host": host,
            "port": port,
            "supported_versions": [],
            "insecure_versions": [],
        }

        for version_name, flag in versions_to_test.items():
            stdout, stderr, rc = await run_command(
                [
                    "openssl", "s_client",
                    "-connect", f"{host}:{port}",
                    "-servername", host,
                    flag,
                ],
                timeout=10,
            )

            combined = stdout + stderr
            # Check if connection succeeded
            if "CONNECTED" in combined and "error" not in combined.lower():
                cipher_match = re.search(r"Cipher\s*:\s*(\S+)", combined)
                cipher = cipher_match.group(1) if cipher_match else "unknown"
                if cipher != "0000" and cipher != "(NONE)":
                    version_label = version_name.replace("_", ".").upper().replace("TLS", "TLSv")
                    results["supported_versions"].append({
                        "version": version_label,
                        "cipher": cipher,
                    })
                    if version_label in INSECURE_TLS_VERSIONS:
                        results["insecure_versions"].append(version_label)

        return ToolResult(
            tool_name="test_protocol_versions",
            success=True,
            data=results,
        )

    @timed
    async def test_downgrade_attack(self, host: str, port: int = 443) -> ToolResult:
        """Test for TLS downgrade attack resistance (FALLBACK_SCSV).

        Tool: test_downgrade_attack(host, port)
        """
        # Test by attempting connection with TLS 1.2 and fallback flag
        stdout, stderr, rc = await run_command(
            [
                "openssl", "s_client",
                "-connect", f"{host}:{port}",
                "-servername", host,
                "-fallback_scsv",
                "-tls1_2",
            ],
            timeout=15,
        )

        combined = stdout + stderr
        supports_fallback_scsv = "inappropriate_fallback" in combined.lower()
        connection_succeeded = "CONNECTED" in combined

        return ToolResult(
            tool_name="test_downgrade_attack",
            success=True,
            data={
                "host": host,
                "port": port,
                "fallback_scsv_supported": supports_fallback_scsv,
                "connection_with_fallback": connection_succeeded,
                "downgrade_resistant": supports_fallback_scsv,
            },
        )

    @timed
    async def test_pqc_support(self, host: str, port: int = 443) -> ToolResult:
        """Test if the server supports PQC hybrid key exchange (ML-KEM/Kyber).

        Tool: test_pqc_support(host, port)
        """
        # Try connecting with PQC groups if OpenSSL supports it
        pqc_groups = [
            "X25519Kyber768Draft00",
            "X25519MLKEM768",
            "SecP256r1MLKEM768",
        ]

        results: dict = {
            "host": host,
            "port": port,
            "pqc_supported": False,
            "supported_groups": [],
            "tested_groups": [],
        }

        for group in pqc_groups:
            stdout, stderr, rc = await run_command(
                [
                    "openssl", "s_client",
                    "-connect", f"{host}:{port}",
                    "-servername", host,
                    "-groups", group,
                ],
                timeout=10,
            )

            combined = stdout + stderr
            tested = {"group": group, "accepted": False}

            if "CONNECTED" in combined:
                cipher_match = re.search(r"Cipher\s*:\s*(\S+)", combined)
                if cipher_match and cipher_match.group(1) not in ("0000", "(NONE)"):
                    tested["accepted"] = True
                    tested["cipher"] = cipher_match.group(1)
                    results["pqc_supported"] = True
                    results["supported_groups"].append(group)

            results["tested_groups"].append(tested)

        return ToolResult(
            tool_name="test_pqc_support",
            success=True,
            data=results,
        )

    @timed
    async def ssh_probe(self, host: str, port: int = 22) -> ToolResult:
        """Probe SSH server for supported algorithms.

        Tool: ssh_probe(host, port)
        """
        stdout, stderr, rc = await run_command(
            ["ssh", "-vvv", "-o", "BatchMode=yes", "-o", f"ConnectTimeout=5",
             "-o", "StrictHostKeyChecking=no",
             "-p", str(port), f"probe@{host}", "exit"],
            timeout=15,
        )

        combined = stderr  # SSH debug output goes to stderr

        results: dict = {
            "host": host,
            "port": port,
            "kex_algorithms": [],
            "host_key_algorithms": [],
            "encryption_algorithms": [],
            "mac_algorithms": [],
            "weak_algorithms": [],
        }

        # Parse key exchange algorithms
        kex_match = re.search(r"kex_algorithms.*?:\s*(.+)", combined)
        if kex_match:
            results["kex_algorithms"] = [a.strip() for a in kex_match.group(1).split(",")]

        # Parse host key algorithms
        hk_match = re.search(r"server host key algorithms.*?:\s*(.+)", combined)
        if hk_match:
            results["host_key_algorithms"] = [a.strip() for a in hk_match.group(1).split(",")]

        # Parse encryption algorithms
        enc_match = re.search(r"encryption.*?server.*?:\s*(.+)", combined)
        if enc_match:
            results["encryption_algorithms"] = [a.strip() for a in enc_match.group(1).split(",")]

        # Parse MAC algorithms
        mac_match = re.search(r"mac.*?server.*?:\s*(.+)", combined)
        if mac_match:
            results["mac_algorithms"] = [a.strip() for a in mac_match.group(1).split(",")]

        # Identify weak algorithms
        weak_ssh = {"ssh-rsa", "ssh-dss", "diffie-hellman-group1-sha1",
                     "diffie-hellman-group14-sha1", "aes128-cbc", "aes256-cbc",
                     "3des-cbc", "hmac-sha1", "hmac-md5"}

        all_algos = (
            results["kex_algorithms"]
            + results["host_key_algorithms"]
            + results["encryption_algorithms"]
            + results["mac_algorithms"]
        )
        results["weak_algorithms"] = [a for a in all_algos if a in weak_ssh]

        return ToolResult(
            tool_name="ssh_probe",
            success=True,
            data=results,
        )

    def get_tool_definitions(self) -> list[dict]:
        """Return OpenAI function-calling tool definitions for Phase 1."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "enumerate_cipher_suites",
                    "description": "Enumerate all TLS cipher suites accepted by the server. Identifies weak suites and PFS support.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "host": {"type": "string", "description": "Target hostname"},
                            "port": {"type": "integer", "description": "TLS port (default: 443)"},
                        },
                        "required": ["host"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "test_protocol_versions",
                    "description": "Test which TLS versions (1.0, 1.1, 1.2, 1.3) the server accepts. Flags insecure versions.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "host": {"type": "string", "description": "Target hostname"},
                            "port": {"type": "integer", "description": "TLS port (default: 443)"},
                        },
                        "required": ["host"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "test_downgrade_attack",
                    "description": "Test for TLS downgrade attack resistance via TLS_FALLBACK_SCSV.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "host": {"type": "string", "description": "Target hostname"},
                            "port": {"type": "integer", "description": "TLS port (default: 443)"},
                        },
                        "required": ["host"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "test_pqc_support",
                    "description": "Test if the server supports PQC hybrid key exchange (ML-KEM/Kyber, X25519Kyber768).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "host": {"type": "string", "description": "Target hostname"},
                            "port": {"type": "integer", "description": "TLS port (default: 443)"},
                        },
                        "required": ["host"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "ssh_probe",
                    "description": "Probe SSH server for supported key exchange, host key, encryption, and MAC algorithms.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "host": {"type": "string", "description": "Target hostname"},
                            "port": {"type": "integer", "description": "SSH port (default: 22)"},
                        },
                        "required": ["host"],
                    },
                },
            },
        ]

    async def execute_tool(self, name: str, args: dict) -> ToolResult:
        """Execute a tool by name with given arguments."""
        tools = {
            "enumerate_cipher_suites": self.enumerate_cipher_suites,
            "test_protocol_versions": self.test_protocol_versions,
            "test_downgrade_attack": self.test_downgrade_attack,
            "test_pqc_support": self.test_pqc_support,
            "ssh_probe": self.ssh_probe,
        }
        if name not in tools:
            return ToolResult(tool_name=name, success=False, error=f"Unknown tool: {name}")
        return await tools[name](**args)
