"""Configuration management for bbci."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class AgentConfig:
    """LLM agent configuration."""

    model: str = "gpt-4o"
    api_base: str | None = None
    api_key: str | None = None
    max_iterations: int = 5
    timeout_minutes: int = 30
    temperature: float = 0.1


@dataclass
class ScanConfig:
    """Scan configuration."""

    phases: list[int] = field(default_factory=lambda: [0, 1, 2, 3])
    min_confidence: float = 0.5
    slow_pace: bool = False
    slow_pace_delay: float = 2.0
    randomness_samples: int = 10000
    timing_measurements: int = 5000


@dataclass
class OutputConfig:
    """Output configuration."""

    format: str = "cyclonedx"
    include_evidence: bool = True
    include_remediation: bool = True
    pretty: bool = True


@dataclass
class Config:
    """Top-level configuration."""

    agent: AgentConfig = field(default_factory=AgentConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    @classmethod
    def from_file(cls, path: str | Path) -> Config:
        """Load configuration from a YAML file."""
        path = Path(path)
        if not path.exists():
            return cls()

        with open(path) as f:
            raw = yaml.safe_load(f) or {}

        config = cls()

        if "agent" in raw:
            for k, v in raw["agent"].items():
                if hasattr(config.agent, k):
                    setattr(config.agent, k, v)

        if "scan" in raw:
            for k, v in raw["scan"].items():
                if hasattr(config.scan, k):
                    setattr(config.scan, k, v)

        if "output" in raw:
            for k, v in raw["output"].items():
                if hasattr(config.output, k):
                    setattr(config.output, k, v)

        return config

    @classmethod
    def load(cls) -> Config:
        """Load configuration from default locations."""
        for candidate in ["bbci.yaml", "bbci.yml", ".bbci.yaml"]:
            if Path(candidate).exists():
                return cls.from_file(candidate)
        return cls()
