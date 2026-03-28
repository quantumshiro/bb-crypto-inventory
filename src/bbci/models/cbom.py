"""CycloneDX CBOM output model."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from bbci.models.finding import Finding


class CryptoAsset(BaseModel):
    """A single cryptographic asset in the CBOM."""

    bom_ref: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str = Field(default="crypto-asset")
    name: str = Field(description="Algorithm or protocol name")
    algorithm: str = Field(description="Detected algorithm")
    key_length: int | None = Field(default=None)
    key_length_estimated: bool = Field(default=False)
    pq_vulnerable: bool = Field(default=False)
    detection_channel: str = Field(description="Observation channel")
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = Field(default="")
    vulnerabilities: list[str] = Field(default_factory=list)

    @classmethod
    def from_finding(cls, finding: Finding) -> CryptoAsset:
        """Create a CryptoAsset from a Finding."""
        return cls(
            name=finding.algorithm,
            algorithm=finding.algorithm,
            key_length=finding.key_length,
            key_length_estimated=finding.key_length_estimated,
            pq_vulnerable=finding.pq_vulnerable,
            detection_channel=finding.detection_channel.value,
            confidence=finding.confidence,
            evidence=finding.evidence,
            remediation=finding.remediation,
            vulnerabilities=[finding.category.value],
        )


class CBOMReport(BaseModel):
    """CycloneDX Cryptographic Bill of Materials report."""

    bom_format: str = Field(default="CycloneDX", alias="bomFormat")
    spec_version: str = Field(default="1.6", alias="specVersion")
    serial_number: str = Field(
        default_factory=lambda: f"urn:uuid:{uuid.uuid4()}", alias="serialNumber"
    )
    version: int = 1
    metadata: dict[str, Any] = Field(default_factory=dict)
    components: list[CryptoAsset] = Field(default_factory=list)
    vulnerabilities_summary: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}

    @classmethod
    def from_findings(
        cls,
        findings: list[Finding],
        target: str,
        scan_duration_seconds: float | None = None,
    ) -> CBOMReport:
        """Build a CBOM report from a list of findings."""
        now = datetime.now(timezone.utc).isoformat()

        metadata = {
            "timestamp": now,
            "tool": {
                "name": "bb-crypto-inventory",
                "version": "0.1.0",
                "vendor": "NyxFoundation",
            },
            "target": target,
        }
        if scan_duration_seconds is not None:
            metadata["scan_duration_seconds"] = scan_duration_seconds

        components = [CryptoAsset.from_finding(f) for f in findings]

        # Build summary
        severity_counts: dict[str, int] = {}
        pq_vulnerable_count = 0
        for f in findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            if f.pq_vulnerable:
                pq_vulnerable_count += 1

        summary = {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "pq_vulnerable_count": pq_vulnerable_count,
            "unique_algorithms": list({f.algorithm for f in findings}),
        }

        return cls(
            metadata=metadata,
            components=components,
            vulnerabilities_summary=summary,
        )

    def to_json(self, pretty: bool = True) -> str:
        """Serialize to JSON string."""
        indent = 2 if pretty else None
        return json.dumps(
            self.model_dump(by_alias=True, exclude_none=True),
            indent=indent,
            default=str,
        )
