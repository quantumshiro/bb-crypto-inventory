"""Phase 3: Oracle and timing analysis tools."""

from __future__ import annotations

import asyncio
import logging
import statistics
import time
from collections import Counter

import httpx

from bbci.tools.common import ToolResult, timed

logger = logging.getLogger("bbci")


class OracleTools:
    """Phase 3 oracle and timing side-channel analysis tools."""

    def __init__(
        self,
        timeout: int = 30,
        timing_measurements: int = 5000,
        slow_pace: bool = False,
        delay: float = 0.0,
    ) -> None:
        self.timeout = timeout
        self.timing_measurements = timing_measurements
        self.slow_pace = slow_pace
        self.delay = delay

    @timed
    async def padding_oracle_test(self, url: str, ciphertext: str) -> ToolResult:
        """Test for Padding Oracle vulnerability.

        Modifies the last byte of the ciphertext (0x00-0xFF) and analyzes
        server response patterns to detect differential error handling.

        Tool: padding_oracle_test(url, ciphertext)
        """
        try:
            ct_bytes = bytes.fromhex(ciphertext)
        except ValueError:
            import base64
            try:
                ct_bytes = base64.b64decode(ciphertext + "==")
            except Exception:
                return ToolResult(
                    tool_name="padding_oracle_test",
                    success=False,
                    error="Cannot decode ciphertext (expected hex or base64)",
                )

        if len(ct_bytes) < 16:
            return ToolResult(
                tool_name="padding_oracle_test",
                success=False,
                error="Ciphertext too short (need at least 16 bytes)",
            )

        responses: list[dict] = []
        status_codes: list[int] = []
        response_times: list[float] = []
        response_bodies: list[str] = []

        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=self.timeout
        ) as client:
            for byte_val in range(256):
                # Modify last byte
                modified = bytearray(ct_bytes)
                modified[-1] = byte_val
                modified_hex = modified.hex()

                start = time.monotonic()
                try:
                    resp = await client.post(
                        url,
                        content=modified_hex,
                        headers={"Content-Type": "application/octet-stream"},
                    )
                    elapsed = (time.monotonic() - start) * 1000

                    status_codes.append(resp.status_code)
                    response_times.append(elapsed)
                    body_preview = resp.text[:200]
                    response_bodies.append(body_preview)

                    responses.append({
                        "byte": byte_val,
                        "status": resp.status_code,
                        "time_ms": round(elapsed, 2),
                        "body_length": len(resp.content),
                        "body_preview": body_preview[:50],
                    })
                except Exception as e:
                    elapsed = (time.monotonic() - start) * 1000
                    responses.append({
                        "byte": byte_val,
                        "error": str(e),
                        "time_ms": round(elapsed, 2),
                    })

                if self.slow_pace:
                    await asyncio.sleep(self.delay)

        # Analyze response patterns
        analysis: dict = {
            "total_probes": 256,
            "successful_probes": len(status_codes),
        }

        # Status code clustering
        status_counter = Counter(status_codes)
        analysis["status_code_distribution"] = dict(status_counter)
        analysis["unique_status_codes"] = len(status_counter)

        # Body clustering
        body_counter = Counter(response_bodies)
        analysis["unique_response_bodies"] = len(body_counter)

        # Timing analysis
        if response_times:
            analysis["timing"] = {
                "mean_ms": round(statistics.mean(response_times), 2),
                "median_ms": round(statistics.median(response_times), 2),
                "stdev_ms": round(statistics.stdev(response_times), 2) if len(response_times) > 1 else 0,
                "min_ms": round(min(response_times), 2),
                "max_ms": round(max(response_times), 2),
            }

            # Check for timing bimodality
            sorted_times = sorted(response_times)
            q1 = sorted_times[len(sorted_times) // 4]
            q3 = sorted_times[3 * len(sorted_times) // 4]
            iqr = q3 - q1
            analysis["timing"]["iqr_ms"] = round(iqr, 2)

        # Padding Oracle verdict
        oracle_detected = False
        evidence = []

        # Criterion 1: Multiple distinct status codes
        if len(status_counter) >= 2:
            oracle_detected = True
            evidence.append(
                f"Multiple status codes detected: {dict(status_counter)}"
            )

        # Criterion 2: Multiple distinct response bodies
        if len(body_counter) >= 2 and len(body_counter) <= 10:
            oracle_detected = True
            evidence.append(
                f"{len(body_counter)} distinct response patterns detected"
            )

        # Criterion 3: Significant timing differences
        if response_times and len(response_times) > 10:
            stdev = statistics.stdev(response_times)
            mean = statistics.mean(response_times)
            cv = stdev / mean if mean > 0 else 0
            if cv > 0.3:
                oracle_detected = True
                evidence.append(
                    f"High timing variance (CV={cv:.2f}), suggesting differential processing"
                )

        analysis["padding_oracle_detected"] = oracle_detected
        analysis["evidence"] = evidence
        analysis["confidence"] = min(len(evidence) * 0.4, 1.0)

        return ToolResult(
            tool_name="padding_oracle_test",
            success=True,
            data=analysis,
        )

    @timed
    async def timing_analysis(
        self, url: str, payloads: list[str], n: int = 100
    ) -> ToolResult:
        """Measure response timing for different payloads to detect timing side-channels.

        Used for:
        - HMAC verification timing leaks
        - Non-constant-time comparison detection
        - Bleichenbacher-style timing attacks

        Tool: timing_analysis(url, payloads, n)
        """
        if len(payloads) < 2:
            return ToolResult(
                tool_name="timing_analysis",
                success=False,
                error="Need at least 2 payloads for comparison",
            )

        measurements: dict[str, list[float]] = {p: [] for p in payloads}

        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=self.timeout
        ) as client:
            for _ in range(n):
                for payload in payloads:
                    start = time.monotonic()
                    try:
                        await client.post(url, content=payload)
                    except Exception:
                        pass
                    elapsed = (time.monotonic() - start) * 1000
                    measurements[payload].append(elapsed)

                    if self.slow_pace:
                        await asyncio.sleep(self.delay)

        # Statistical analysis
        analysis: dict = {
            "total_measurements_per_payload": n,
            "payloads": {},
        }

        all_means = []
        for payload, times in measurements.items():
            if not times:
                continue

            # Remove outliers (beyond 3 sigma)
            if len(times) > 10:
                mean = statistics.mean(times)
                stdev = statistics.stdev(times)
                filtered = [t for t in times if abs(t - mean) < 3 * stdev]
            else:
                filtered = times

            if filtered:
                payload_stats = {
                    "mean_ms": round(statistics.mean(filtered), 4),
                    "median_ms": round(statistics.median(filtered), 4),
                    "stdev_ms": round(statistics.stdev(filtered), 4) if len(filtered) > 1 else 0,
                    "measurements": len(filtered),
                    "outliers_removed": len(times) - len(filtered),
                }
                analysis["payloads"][payload[:32]] = payload_stats
                all_means.append(statistics.mean(filtered))

        # Compare timing differences
        if len(all_means) >= 2:
            max_diff = max(all_means) - min(all_means)
            avg_time = statistics.mean(all_means)
            relative_diff = max_diff / avg_time if avg_time > 0 else 0

            analysis["comparison"] = {
                "max_difference_ms": round(max_diff, 4),
                "relative_difference": round(relative_diff, 6),
                "average_time_ms": round(avg_time, 4),
            }

            # Timing leak detection
            # A difference > 1% of average time is suspicious
            timing_leak = relative_diff > 0.01
            analysis["timing_leak_detected"] = timing_leak
            analysis["confidence"] = min(relative_diff * 10, 1.0) if timing_leak else 0.1

            if timing_leak:
                analysis["assessment"] = (
                    f"POTENTIAL TIMING LEAK: {max_diff:.4f}ms difference "
                    f"({relative_diff*100:.2f}% of average response time). "
                    f"Non-constant-time implementation suspected."
                )
            else:
                analysis["assessment"] = (
                    f"No significant timing difference detected "
                    f"({max_diff:.4f}ms, {relative_diff*100:.4f}% of average)."
                )

        return ToolResult(
            tool_name="timing_analysis",
            success=True,
            data=analysis,
        )

    def get_tool_definitions(self) -> list[dict]:
        """Return OpenAI function-calling tool definitions for Phase 3."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "padding_oracle_test",
                    "description": "Test for Padding Oracle vulnerability by modifying ciphertext bytes and analyzing differential server responses (status codes, error messages, timing).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Decryption endpoint URL"},
                            "ciphertext": {"type": "string", "description": "Ciphertext to test (hex or base64)"},
                        },
                        "required": ["url", "ciphertext"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "timing_analysis",
                    "description": "Measure response timing for different payloads to detect timing side-channels (HMAC verification, non-constant-time comparison).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Target endpoint URL"},
                            "payloads": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of payloads to compare timing for",
                            },
                            "n": {"type": "integer", "description": "Measurements per payload (default: 100)"},
                        },
                        "required": ["url", "payloads"],
                    },
                },
            },
        ]

    async def execute_tool(self, name: str, args: dict) -> ToolResult:
        """Execute a tool by name with given arguments."""
        tools = {
            "padding_oracle_test": self.padding_oracle_test,
            "timing_analysis": self.timing_analysis,
        }
        if name not in tools:
            return ToolResult(tool_name=name, success=False, error=f"Unknown tool: {name}")
        return await tools[name](**args)
