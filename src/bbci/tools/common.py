"""Shared utilities for scan tools."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("bbci")


@dataclass
class ToolResult:
    """Result from a tool execution."""

    tool_name: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for LLM consumption."""
        result: dict[str, Any] = {
            "tool": self.tool_name,
            "success": self.success,
            "duration_ms": round(self.duration_ms, 2),
        }
        if self.success:
            result["data"] = self.data
        else:
            result["error"] = self.error
        return result


async def run_command(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a shell command asynchronously with timeout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        proc.kill()  # type: ignore[union-attr]
        return "", f"Command timed out after {timeout}s", -1
    except Exception as e:
        return "", str(e), -1


def timed(func):  # type: ignore[no-untyped-def]
    """Decorator to time async function execution."""

    async def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
        start = time.monotonic()
        result = await func(*args, **kwargs)
        elapsed = (time.monotonic() - start) * 1000
        if isinstance(result, ToolResult):
            result.duration_ms = elapsed
        return result

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper
