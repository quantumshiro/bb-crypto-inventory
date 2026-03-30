"""LLM Agent orchestrator implementing the Plan-Act-Observe loop."""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any
from urllib.parse import urlparse

from openai import AsyncOpenAI

from bbci.agent.prompts import REPORT_FINDING_TOOL, SYSTEM_PROMPT
from bbci.config import Config
from bbci.models.cbom import CBOMReport
from bbci.models.finding import (
    DetectionChannel,
    Finding,
    Severity,
    VulnerabilityCategory,
)
from bbci.tools.application import ApplicationTools
from bbci.tools.common import ToolResult
from bbci.tools.oracle import OracleTools
from bbci.tools.recon import ReconTools
from bbci.tools.tls import TLSTools

logger = logging.getLogger("bbci")


class AgentOrchestrator:
    """Orchestrates the LLM agent's Plan-Act-Observe loop."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.client = AsyncOpenAI(
            api_key=config.agent.api_key or None,
            base_url=config.agent.api_base,
        )

        # Initialize tool sets
        self.recon = ReconTools(timeout=30)
        self.tls = TLSTools(timeout=30)
        self.application = ApplicationTools(
            timeout=30,
            slow_pace=config.scan.slow_pace,
            delay=config.scan.slow_pace_delay,
            max_tokens=config.scan.max_tokens,
            max_randomness_tier=config.scan.max_randomness_tier,
        )
        self.oracle = OracleTools(
            timeout=30,
            timing_measurements=config.scan.timing_measurements,
            slow_pace=config.scan.slow_pace,
            delay=config.scan.slow_pace_delay,
        )

        # Findings collected during the scan
        self.findings: list[Finding] = []
        self.messages: list[dict[str, Any]] = []
        self.iteration = 0

    def _get_tools(self) -> list[dict]:
        """Get all tool definitions based on configured phases."""
        tools: list[dict] = [REPORT_FINDING_TOOL]

        phases = self.config.scan.phases
        if 0 in phases:
            tools.extend(self.recon.get_tool_definitions())
        if 1 in phases:
            tools.extend(self.tls.get_tool_definitions())
        if 2 in phases:
            tools.extend(self.application.get_tool_definitions())
        if 3 in phases:
            tools.extend(self.oracle.get_tool_definitions())

        return tools

    async def _execute_tool(self, name: str, args: dict) -> ToolResult | dict:
        """Route tool execution to the appropriate tool set."""
        # Special handling for report_finding
        if name == "report_finding":
            return self._record_finding(args)

        # Try each tool set
        for tool_set in [self.recon, self.tls, self.application, self.oracle]:
            try:
                result = await tool_set.execute_tool(name, args)
                if result.error != f"Unknown tool: {name}":
                    return result
            except Exception:
                continue

        return ToolResult(
            tool_name=name, success=False, error=f"Tool '{name}' not found in any phase"
        )

    def _record_finding(self, args: dict) -> dict:
        """Record a finding from the LLM agent."""
        try:
            # Map category string to enum
            cat_str = args.get("category", "")
            try:
                category = VulnerabilityCategory(cat_str)
            except ValueError:
                category = VulnerabilityCategory.INSECURE_CIPHER_SUITE

            # Map severity
            sev_str = args.get("severity", "info")
            try:
                severity = Severity(sev_str)
            except ValueError:
                severity = Severity.INFO

            # Map detection channel based on category
            channel_map = {
                VulnerabilityCategory.ECB_MODE: DetectionChannel.CIPHERTEXT_STATS,
                VulnerabilityCategory.STATIC_IV: DetectionChannel.CIPHERTEXT_STATS,
                VulnerabilityCategory.WEAK_HASH: DetectionChannel.HASH_SIGNATURE,
                VulnerabilityCategory.INSECURE_RANDOM: DetectionChannel.RANDOMNESS,
                VulnerabilityCategory.PADDING_ORACLE: DetectionChannel.ERROR_DIFFERENTIAL,
                VulnerabilityCategory.INSECURE_CIPHER_SUITE: DetectionChannel.TLS_HANDSHAKE,
                VulnerabilityCategory.NO_PFS: DetectionChannel.TLS_HANDSHAKE,
                VulnerabilityCategory.WEAK_PROTOCOL_VERSION: DetectionChannel.TLS_HANDSHAKE,
                VulnerabilityCategory.JWT_ALG_CONFUSION: DetectionChannel.HASH_SIGNATURE,
                VulnerabilityCategory.TIMING_LEAK: DetectionChannel.TIMING_SIDE_CHANNEL,
                VulnerabilityCategory.WEAK_KEY_LENGTH: DetectionChannel.TLS_HANDSHAKE,
                VulnerabilityCategory.NO_HSTS: DetectionChannel.RECON,
                VulnerabilityCategory.EXPIRED_CERTIFICATE: DetectionChannel.TLS_HANDSHAKE,
                VulnerabilityCategory.WEAK_SIGNATURE_ALGORITHM: DetectionChannel.TLS_HANDSHAKE,
            }

            finding = Finding(
                id=f"BBCI-{uuid.uuid4().hex[:8].upper()}",
                category=category,
                severity=severity,
                algorithm=args.get("algorithm", "unknown"),
                key_length=args.get("key_length"),
                pq_vulnerable=args.get("pq_vulnerable", False),
                detection_channel=channel_map.get(category, DetectionChannel.RECON),
                confidence=args.get("confidence", 0.5),
                evidence=args.get("evidence", {}),
                remediation=args.get("remediation", ""),
                endpoint=self._target_url,
            )

            self.findings.append(finding)
            logger.info(
                f"Finding recorded: {finding.id} | {finding.category.value} | "
                f"{finding.severity.value} | {finding.algorithm} | "
                f"confidence={finding.confidence}"
            )

            return {
                "success": True,
                "finding_id": finding.id,
                "message": f"Finding recorded: {finding.category.value} ({finding.severity.value})",
            }

        except Exception as e:
            logger.error(f"Error recording finding: {e}")
            return {"success": False, "error": str(e)}

    async def scan(self, target_url: str) -> CBOMReport:
        """Run the full blackbox cryptographic inventory scan.

        Args:
            target_url: The target endpoint URL to scan.

        Returns:
            CBOMReport with all discovered cryptographic assets.
        """
        self._target_url = target_url
        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        logger.info(f"Starting blackbox crypto inventory scan of {target_url}")
        start_time = time.monotonic()

        # Initialize conversation
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Scan the following endpoint for cryptographic assets and vulnerabilities:\n\n"
                    f"Target URL: {target_url}\n"
                    f"Host: {host}\n"
                    f"Port: {port}\n"
                    f"Scheme: {parsed.scheme or 'https'}\n\n"
                    f"Configured phases: {self.config.scan.phases}\n"
                    f"Min confidence threshold: {self.config.scan.min_confidence}\n\n"
                    f"Begin with Phase 0 (Reconnaissance) and proceed through all configured phases. "
                    f"Report every cryptographic finding you discover using the report_finding tool."
                ),
            },
        ]

        tools = self._get_tools()
        max_iterations = self.config.agent.max_iterations
        timeout_seconds = self.config.agent.timeout_minutes * 60

        # Plan-Act-Observe loop
        for iteration in range(max_iterations):
            self.iteration = iteration + 1
            elapsed = time.monotonic() - start_time

            if elapsed > timeout_seconds:
                logger.warning(f"Timeout reached after {elapsed:.0f}s")
                break

            logger.info(f"=== Iteration {self.iteration}/{max_iterations} ===")

            try:
                response = await self.client.chat.completions.create(
                    model=self.config.agent.model,
                    messages=self.messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=self.config.agent.temperature,
                )
            except Exception as e:
                logger.error(f"LLM API error: {e}")
                break

            message = response.choices[0].message

            # Add assistant message to history
            self.messages.append(message.model_dump())

            # Check if the agent wants to call tools
            if message.tool_calls:
                for tool_call in message.tool_calls:
                    fn_name = tool_call.function.name
                    try:
                        fn_args = json.loads(tool_call.function.arguments)
                    except json.JSONDecodeError:
                        fn_args = {}

                    logger.info(f"Tool call: {fn_name}({json.dumps(fn_args)[:200]})")

                    result = await self._execute_tool(fn_name, fn_args)

                    # Convert ToolResult to dict
                    if isinstance(result, ToolResult):
                        result_dict = result.to_dict()
                    else:
                        result_dict = result

                    # Add tool result to conversation
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(result_dict, default=str),
                    })
            else:
                # Agent finished (no more tool calls)
                if message.content:
                    logger.info(f"Agent summary: {message.content[:500]}")
                break

        # Build final report
        scan_duration = time.monotonic() - start_time

        # Filter by minimum confidence
        qualified_findings = [
            f for f in self.findings
            if f.confidence >= self.config.scan.min_confidence
        ]

        report = CBOMReport.from_findings(
            findings=qualified_findings,
            target=target_url,
            scan_duration_seconds=scan_duration,
        )

        logger.info(
            f"Scan complete: {len(qualified_findings)} findings "
            f"({len(self.findings)} total, {len(self.findings) - len(qualified_findings)} "
            f"below confidence threshold) in {scan_duration:.1f}s"
        )

        return report
