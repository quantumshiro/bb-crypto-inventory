"""Tests for data models."""

from datetime import datetime, timezone

from bbci.models.cbom import CBOMReport, CryptoAsset
from bbci.models.finding import (
    DetectionChannel,
    Finding,
    Severity,
    VulnerabilityCategory,
)


def _make_finding(**overrides) -> Finding:
    """Helper to create a Finding with defaults."""
    defaults = {
        "id": "BBCI-TEST0001",
        "category": VulnerabilityCategory.INSECURE_CIPHER_SUITE,
        "severity": Severity.HIGH,
        "algorithm": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "pq_vulnerable": True,
        "detection_channel": DetectionChannel.TLS_HANDSHAKE,
        "confidence": 0.95,
        "endpoint": "https://example.com",
        "remediation": "Upgrade to TLS 1.3 cipher suites",
    }
    defaults.update(overrides)
    return Finding(**defaults)


class TestFinding:
    def test_create_finding(self) -> None:
        f = _make_finding()
        assert f.id == "BBCI-TEST0001"
        assert f.category == VulnerabilityCategory.INSECURE_CIPHER_SUITE
        assert f.severity == Severity.HIGH
        assert f.pq_vulnerable is True
        assert f.confidence == 0.95

    def test_is_pq_critical(self) -> None:
        f = _make_finding(pq_vulnerable=True, severity=Severity.HIGH)
        assert f.is_pq_critical is True

        f2 = _make_finding(pq_vulnerable=True, severity=Severity.LOW)
        assert f2.is_pq_critical is False

        f3 = _make_finding(pq_vulnerable=False, severity=Severity.CRITICAL)
        assert f3.is_pq_critical is False

    def test_key_length_estimated(self) -> None:
        f = _make_finding(key_length=2048, key_length_estimated=True)
        assert f.key_length == 2048
        assert f.key_length_estimated is True


class TestCBOMReport:
    def test_from_findings(self) -> None:
        findings = [
            _make_finding(
                id="BBCI-001",
                algorithm="RSA-2048",
                severity=Severity.INFO,
                pq_vulnerable=True,
            ),
            _make_finding(
                id="BBCI-002",
                algorithm="AES-128-ECB",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.ECB_MODE,
                pq_vulnerable=False,
            ),
        ]

        report = CBOMReport.from_findings(findings, target="https://example.com", scan_duration_seconds=42.0)

        assert report.bom_format == "CycloneDX"
        assert report.spec_version == "1.6"
        assert len(report.components) == 2
        assert report.metadata["target"] == "https://example.com"
        assert report.metadata["scan_duration_seconds"] == 42.0
        assert report.vulnerabilities_summary["total_findings"] == 2
        assert report.vulnerabilities_summary["pq_vulnerable_count"] == 1

    def test_to_json(self) -> None:
        report = CBOMReport.from_findings(
            [_make_finding()], target="https://example.com"
        )
        json_str = report.to_json()
        assert '"bomFormat": "CycloneDX"' in json_str
        assert '"specVersion": "1.6"' in json_str

    def test_empty_findings(self) -> None:
        report = CBOMReport.from_findings([], target="https://empty.com")
        assert len(report.components) == 0
        assert report.vulnerabilities_summary["total_findings"] == 0
