"""Finding and vulnerability models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DetectionChannel(str, Enum):
    """Observation channels used for detection."""

    TLS_HANDSHAKE = "CH1:TLS_HANDSHAKE"
    CIPHERTEXT_STATS = "CH2:CIPHERTEXT_STATS"
    ERROR_DIFFERENTIAL = "CH3:ERROR_DIFFERENTIAL"
    TIMING_SIDE_CHANNEL = "CH4:TIMING_SIDE_CHANNEL"
    HASH_SIGNATURE = "CH5:HASH_SIGNATURE"
    RANDOMNESS = "CH6:RANDOMNESS"
    RECON = "RECON"


class VulnerabilityCategory(str, Enum):
    """Categories of detectable vulnerabilities."""

    ECB_MODE = "ECBMode"
    STATIC_IV = "StaticIV"
    WEAK_HASH = "WeakHash"
    INSECURE_RANDOM = "InsecureRandom"
    PADDING_ORACLE = "PaddingOracle"
    INSECURE_CIPHER_SUITE = "InsecureCipherSuite"
    NO_PFS = "NoPFS"
    WEAK_PROTOCOL_VERSION = "WeakProtocolVersion"
    JWT_ALG_CONFUSION = "JWTAlgConfusion"
    TIMING_LEAK = "TimingLeak"
    WEAK_KEY_LENGTH = "WeakKeyLength"
    NO_HSTS = "NoHSTS"
    EXPIRED_CERTIFICATE = "ExpiredCertificate"
    WEAK_SIGNATURE_ALGORITHM = "WeakSignatureAlgorithm"


class Finding(BaseModel):
    """A single cryptographic finding from the scan."""

    id: str = Field(description="Unique finding identifier")
    category: VulnerabilityCategory = Field(description="Vulnerability category")
    severity: Severity = Field(description="Severity level")
    algorithm: str = Field(description="Detected cryptographic algorithm")
    key_length: int | None = Field(default=None, description="Key length in bits")
    key_length_estimated: bool = Field(default=False, description="Whether key_length is estimated")
    pq_vulnerable: bool = Field(
        default=False, description="Whether vulnerable to quantum computers"
    )
    detection_channel: DetectionChannel = Field(description="Which observation channel detected this")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence score")
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Raw evidence data"
    )
    remediation: str = Field(default="", description="Remediation recommendation")
    endpoint: str = Field(description="The endpoint where this was found")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_pq_critical(self) -> bool:
        """Whether this finding is critical for PQC migration."""
        return self.pq_vulnerable and self.severity in (Severity.CRITICAL, Severity.HIGH)
