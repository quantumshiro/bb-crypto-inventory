"""Tests for configuration management."""

import tempfile
from pathlib import Path

from bbci.config import Config


class TestConfig:
    def test_default_config(self) -> None:
        config = Config()
        assert config.agent.model == "gpt-4o"
        assert config.agent.max_iterations == 5
        assert config.scan.phases == [0, 1, 2, 3]
        assert config.scan.min_confidence == 0.5
        assert config.output.format == "cyclonedx"

    def test_load_from_file(self) -> None:
        yaml_content = """
agent:
  model: "claude-3.5-sonnet"
  max_iterations: 10
scan:
  phases: [0, 1]
  min_confidence: 0.8
output:
  format: "markdown"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()

            config = Config.from_file(f.name)

        assert config.agent.model == "claude-3.5-sonnet"
        assert config.agent.max_iterations == 10
        assert config.scan.phases == [0, 1]
        assert config.scan.min_confidence == 0.8
        assert config.output.format == "markdown"

        # Non-overridden values should keep defaults
        assert config.agent.timeout_minutes == 30
        assert config.output.include_evidence is True

    def test_missing_file(self) -> None:
        config = Config.from_file("/nonexistent/path.yaml")
        assert config.agent.model == "gpt-4o"
