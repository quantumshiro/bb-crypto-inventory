"""Data models for bbci."""

from bbci.models.cbom import CBOMReport
from bbci.models.finding import Finding, Severity

__all__ = ["CBOMReport", "Finding", "Severity"]
