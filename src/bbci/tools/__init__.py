"""Scan tools for the bbci agent."""

from __future__ import annotations

from typing import Any

__all__ = ["ReconTools", "TLSTools", "ApplicationTools", "OracleTools"]


def __getattr__(name: str) -> Any:
    if name == "ReconTools":
        from bbci.tools.recon import ReconTools

        return ReconTools
    if name == "TLSTools":
        from bbci.tools.tls import TLSTools

        return TLSTools
    if name == "ApplicationTools":
        from bbci.tools.application import ApplicationTools

        return ApplicationTools
    if name == "OracleTools":
        from bbci.tools.oracle import OracleTools

        return OracleTools
    raise AttributeError(name)
