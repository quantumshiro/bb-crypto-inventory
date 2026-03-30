"""Phase 2: Application layer analysis tools."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import statistics
from collections import Counter

import httpx

from bbci.tools.common import ToolResult, timed
from bbci.tools.randomness import run_randomness_tests

logger = logging.getLogger("bbci")


class ApplicationTools:
    """Phase 2 application layer analysis tools."""

    def __init__(
        self,
        timeout: int = 30,
        slow_pace: bool = False,
        delay: float = 0.0,
        max_tokens: int = 200,
        max_randomness_tier: int = 2,
    ) -> None:
        self.timeout = timeout
        self.slow_pace = slow_pace
        self.delay = delay
        self.max_tokens = max_tokens
        self.max_randomness_tier = max_randomness_tier

    @timed
    async def send_and_compare_ciphertext(
        self, url: str, payload: str, n: int = 10
    ) -> ToolResult:
        """Send the same plaintext N times and compare ciphertext outputs.

        Detects:
        - ECB mode (repeated blocks in output)
        - Static IV/nonce (identical outputs for identical inputs)
        - Block size estimation from output length patterns

        Tool: send_and_compare_ciphertext(url, payload, n)
        """
        import asyncio

        outputs: list[bytes] = []
        errors: list[str] = []

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=self.timeout
        ) as client:
            for i in range(n):
                try:
                    resp = await client.post(url, content=payload)
                    outputs.append(resp.content)
                except Exception as e:
                    errors.append(str(e))
                if self.slow_pace:
                    await asyncio.sleep(self.delay)

        if not outputs:
            return ToolResult(
                tool_name="send_and_compare_ciphertext",
                success=False,
                error=f"No successful requests. Errors: {errors[:3]}",
            )

        # Analysis
        analysis: dict = {
            "total_requests": n,
            "successful": len(outputs),
            "errors": len(errors),
        }

        # Check for static IV (identical outputs)
        unique_outputs = len(set(outputs))
        analysis["unique_outputs"] = unique_outputs
        analysis["static_iv_detected"] = unique_outputs == 1 and len(outputs) > 1

        # Check for ECB mode (repeated 16-byte blocks within each output)
        ecb_detected = False
        for output in outputs:
            if len(output) >= 32:
                block_size = 16
                blocks = [output[i:i + block_size] for i in range(0, len(output), block_size)]
                counter = Counter(blocks)
                if any(count > 1 for count in counter.values()):
                    ecb_detected = True
                    break

        analysis["ecb_mode_detected"] = ecb_detected

        # Estimate block size from output lengths
        output_lengths = [len(o) for o in outputs]
        analysis["output_lengths"] = output_lengths
        if output_lengths:
            analysis["consistent_length"] = len(set(output_lengths)) == 1
            length = output_lengths[0]
            if length % 16 == 0:
                analysis["estimated_block_size"] = 16
                analysis["likely_algorithm"] = "AES (128-bit block)"
            elif length % 8 == 0:
                analysis["estimated_block_size"] = 8
                analysis["likely_algorithm"] = "3DES/Blowfish (64-bit block)"

        return ToolResult(
            tool_name="send_and_compare_ciphertext",
            success=True,
            data=analysis,
        )

    @timed
    async def analyze_jwt(self, token: str) -> ToolResult:
        """Analyze a JWT token's header and payload.

        Detects:
        - Algorithm used (RS256, HS256, ES256, none)
        - Key type and estimated strength
        - alg confusion vulnerability indicators

        Tool: analyze_jwt(token)
        """
        parts = token.strip().split(".")
        if len(parts) < 2:
            return ToolResult(
                tool_name="analyze_jwt",
                success=False,
                error="Invalid JWT format (expected at least 2 dot-separated parts)",
            )

        try:
            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Analyze signature
            has_signature = len(parts) == 3 and bool(parts[2])
            sig_length = len(base64.urlsafe_b64decode(parts[2] + "==")) if has_signature else 0

        except Exception as e:
            return ToolResult(
                tool_name="analyze_jwt",
                success=False,
                error=f"Failed to decode JWT: {e}",
            )

        alg = header.get("alg", "unknown")
        typ = header.get("typ", "unknown")

        analysis: dict = {
            "header": header,
            "payload_keys": list(payload.keys()),
            "algorithm": alg,
            "type": typ,
            "has_signature": has_signature,
            "signature_bytes": sig_length,
        }

        # Algorithm analysis
        if alg == "none":
            analysis["vulnerability"] = "CRITICAL: alg=none means no signature verification"
            analysis["severity"] = "critical"
        elif alg == "HS256":
            analysis["key_type"] = "symmetric"
            analysis["note"] = "HMAC-SHA256. Check for alg confusion (RS256→HS256)"
            analysis["pq_vulnerable"] = False  # Symmetric
        elif alg == "HS384":
            analysis["key_type"] = "symmetric"
            analysis["pq_vulnerable"] = False
        elif alg == "HS512":
            analysis["key_type"] = "symmetric"
            analysis["pq_vulnerable"] = False
        elif alg == "RS256":
            analysis["key_type"] = "RSA"
            analysis["estimated_key_length"] = sig_length * 8 if sig_length else None
            analysis["pq_vulnerable"] = True
        elif alg == "RS384" or alg == "RS512":
            analysis["key_type"] = "RSA"
            analysis["pq_vulnerable"] = True
        elif alg == "ES256":
            analysis["key_type"] = "ECDSA"
            analysis["curve"] = "P-256"
            analysis["pq_vulnerable"] = True
        elif alg == "ES384":
            analysis["key_type"] = "ECDSA"
            analysis["curve"] = "P-384"
            analysis["pq_vulnerable"] = True
        elif alg == "EdDSA":
            analysis["key_type"] = "Ed25519"
            analysis["pq_vulnerable"] = True
        else:
            analysis["key_type"] = "unknown"
            analysis["pq_vulnerable"] = True

        return ToolResult(
            tool_name="analyze_jwt",
            success=True,
            data=analysis,
        )

    @timed
    async def collect_tokens(self, url: str, n: int | None = None) -> ToolResult:
        """Collect session tokens/IDs for randomness analysis.

        Tool: collect_tokens(url, n)
        """
        import asyncio

        if n is None:
            n = self.max_tokens

        tokens: list[dict] = []
        errors: list[str] = []

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=self.timeout
        ) as client:
            for i in range(n):
                try:
                    resp = await client.get(url)

                    # Extract tokens from various sources
                    token_data: dict = {"request_index": i}

                    # Set-Cookie headers
                    cookies = resp.headers.get_list("set-cookie")
                    if cookies:
                        for cookie in cookies:
                            name_val = cookie.split(";")[0]
                            if "=" in name_val:
                                name, val = name_val.split("=", 1)
                                token_data[f"cookie_{name.strip()}"] = val.strip()

                    # CSRF tokens in response body
                    body = resp.text
                    import re
                    csrf_match = re.search(
                        r'name=["\']?csrf[_-]?token["\']?\s+value=["\']?([^"\'>\s]+)',
                        body, re.IGNORECASE,
                    )
                    if csrf_match:
                        token_data["csrf_token"] = csrf_match.group(1)

                    # Authorization header in redirects
                    auth = resp.headers.get("authorization")
                    if auth:
                        token_data["authorization"] = auth

                    tokens.append(token_data)
                except Exception as e:
                    errors.append(str(e))

                if self.slow_pace:
                    await asyncio.sleep(self.delay)

        return ToolResult(
            tool_name="collect_tokens",
            success=True,
            data={
                "url": url,
                "requested": n,
                "collected": len(tokens),
                "errors": len(errors),
                "tokens": tokens[:50],  # Cap for LLM context
                "sample_keys": list(tokens[0].keys()) if tokens else [],
            },
        )

    @timed
    async def randomness_test(
        self, samples: list[str], max_tier: int | None = None, early_stop: bool = True
    ) -> ToolResult:
        """Run tiered statistical tests on collected token samples.

        Uses the small-sample approach from docs/07-small-sample-randomness.md:
        - Tier 1 (N≥20):  Diff analysis, Permutation Entropy
        - Tier 2 (N≥100): SHR Entropy, Anderson-Darling, χ², Collision
        - Tier 3 (N≥200): SPRT, Min-Entropy, Maurer's Universal Test

        Tool: randomness_test(samples, max_tier, early_stop)
        """
        if len(samples) < 10:
            return ToolResult(
                tool_name="randomness_test",
                success=False,
                error=f"Need at least 10 samples, got {len(samples)}",
            )

        if max_tier is None:
            max_tier = self.max_randomness_tier

        report = run_randomness_tests(
            samples=samples,
            max_tier=max_tier,
            early_stop=early_stop,
        )

        return ToolResult(
            tool_name="randomness_test",
            success=True,
            data=report.to_dict(),
        )

    @timed
    async def analyze_hash_length(self, hash_values: list[str]) -> ToolResult:
        """Analyze hash value lengths to determine the hash algorithm.

        Tool: analyze_hash_length(hash_values)
        """
        length_map = {
            32: "MD5 (128-bit)",
            40: "SHA-1 (160-bit)",
            56: "SHA-224 (224-bit)",
            64: "SHA-256 (256-bit)",
            96: "SHA-384 (384-bit)",
            128: "SHA-512 (512-bit)",
        }

        analyses: list[dict] = []
        for hv in hash_values:
            clean = hv.strip().lower()
            hex_len = len(clean)
            bit_len = hex_len * 4

            analysis = {
                "value_preview": clean[:16] + "..." if len(clean) > 16 else clean,
                "hex_length": hex_len,
                "bit_length": bit_len,
                "likely_algorithm": length_map.get(hex_len, f"Unknown ({bit_len}-bit)"),
            }

            # Check if it looks like hex
            try:
                bytes.fromhex(clean)
                analysis["is_hex"] = True
            except ValueError:
                analysis["is_hex"] = False
                # Try base64
                try:
                    decoded = base64.b64decode(clean + "==")
                    analysis["base64_decoded_bytes"] = len(decoded)
                    analysis["base64_bit_length"] = len(decoded) * 8
                except Exception:
                    pass

            # Weakness assessment
            if hex_len == 32:  # MD5
                analysis["weak"] = True
                analysis["severity"] = "high"
                analysis["pq_note"] = "MD5 is cryptographically broken regardless of quantum"
            elif hex_len == 40:  # SHA-1
                analysis["weak"] = True
                analysis["severity"] = "medium"
                analysis["pq_note"] = "SHA-1 has known collision attacks"
            else:
                analysis["weak"] = False

            analyses.append(analysis)

        return ToolResult(
            tool_name="analyze_hash_length",
            success=True,
            data={
                "hash_count": len(hash_values),
                "analyses": analyses,
            },
        )

    def get_tool_definitions(self) -> list[dict]:
        """Return OpenAI function-calling tool definitions for Phase 2."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "send_and_compare_ciphertext",
                    "description": "Send the same plaintext N times via the encryption endpoint and compare outputs. Detects ECB mode, static IV, and estimates block size.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Encryption endpoint URL"},
                            "payload": {"type": "string", "description": "Plaintext payload to send"},
                            "n": {"type": "integer", "description": "Number of repetitions (default: 10)"},
                        },
                        "required": ["url", "payload"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_jwt",
                    "description": "Analyze a JWT token's header and payload. Identifies algorithm, key type, and alg confusion vulnerabilities.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "token": {"type": "string", "description": "JWT token string"},
                        },
                        "required": ["token"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "collect_tokens",
                    "description": "Collect session tokens/IDs/CSRF tokens from repeated requests for randomness analysis. Uses small-sample approach to minimize WAF/BAN risk.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Target URL to collect tokens from"},
                            "n": {"type": "integer", "description": "Number of tokens to collect (default: 200, fast: 100, deep: 2000)"},
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "randomness_test",
                    "description": (
                        "Run tiered statistical tests on collected token samples. "
                        "Tier 1 (N≥20): diff analysis + permutation entropy for immediate pattern detection. "
                        "Tier 2 (N≥100): SHR entropy, Anderson-Darling, chi-square, collision test. "
                        "Tier 3 (N≥200): SPRT sequential test, min-entropy estimation, Maurer's universal test. "
                        "Uses early stopping: obvious failures detected with fewer samples."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "samples": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of token/random value samples (hex or base64)",
                            },
                            "max_tier": {
                                "type": "integer",
                                "description": "Maximum tier to run (1, 2, or 3). Default: 2",
                                "enum": [1, 2, 3],
                            },
                            "early_stop": {
                                "type": "boolean",
                                "description": "Stop early if definitive failure is detected. Default: true",
                            },
                        },
                        "required": ["samples"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_hash_length",
                    "description": "Analyze hash value lengths to determine the hash algorithm (MD5, SHA-1, SHA-256, etc.).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "hash_values": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of hash values to analyze",
                            },
                        },
                        "required": ["hash_values"],
                    },
                },
            },
        ]

    async def execute_tool(self, name: str, args: dict) -> ToolResult:
        """Execute a tool by name with given arguments."""
        tools = {
            "send_and_compare_ciphertext": self.send_and_compare_ciphertext,
            "analyze_jwt": self.analyze_jwt,
            "collect_tokens": self.collect_tokens,
            "randomness_test": self.randomness_test,
            "analyze_hash_length": self.analyze_hash_length,
        }
        if name not in tools:
            return ToolResult(tool_name=name, success=False, error=f"Unknown tool: {name}")
        return await tools[name](**args)
