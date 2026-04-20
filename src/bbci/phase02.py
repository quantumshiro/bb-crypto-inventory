"""Deterministic Phase02 application-surface discovery."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import metadata
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

PHASE02_SCANNER_NAME = "bbci-phase02"
PHASE02_SCHEMA_VERSION = "phase02-report/v1"
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")
SURFACE_KINDS = {
    "encryption_oracle",
    "hash_oracle",
    "token_issuer",
    "decryption_oracle",
    "jwt_auth_surface",
    "hmac_verifier",
}


@dataclass
class CandidateEndpoint:
    endpoint_url: str
    endpoint_path: str
    methods: set[str] = field(default_factory=set)
    surface_kind: str | None = None
    sources: set[str] = field(default_factory=set)
    observation_ids: set[str] = field(default_factory=set)
    source_urls: set[str] = field(default_factory=set)
    descriptor_formats: set[str] = field(default_factory=set)
    classification_bases: set[str] = field(default_factory=set)
    declared_surface_kinds: set[str] = field(default_factory=set)
    same_origin: bool = True


@dataclass
class DescriptorAttempt:
    source_hint: str
    requested_url: str
    fetch_status: str
    status_code: int | None = None
    final_url: str | None = None
    redirected_to: str | None = None
    same_origin: bool = True
    descriptor_format: str | None = None
    payload: dict[str, Any] | None = None
    error: str | None = None


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _scanner_version() -> str:
    try:
        return metadata.version("bb-crypto-inventory")
    except metadata.PackageNotFoundError:
        from bbci import __version__

        return __version__


def canonicalize_base_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    return f"{scheme}://{host}:{port}{path}"


def normalize_endpoint_path(path: str) -> str:
    parsed = urlparse(path)
    normalized = parsed.path or path or "/"
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


def canonicalize_endpoint_url(base_url: str, endpoint_path: str) -> str:
    normalized_path = normalize_endpoint_path(endpoint_path)
    parsed = urlparse(canonicalize_base_url(base_url))
    return f"{parsed.scheme}://{parsed.hostname}:{parsed.port}{normalized_path}"


def normalize_methods(methods: list[str] | set[str] | tuple[str, ...] | str | None) -> list[str]:
    if methods is None:
        return []
    raw_methods = [methods] if isinstance(methods, str) else list(methods)
    return sorted({method.upper() for method in raw_methods if method})


def _same_origin(base_url: str, candidate_url: str) -> bool:
    base = urlparse(canonicalize_base_url(base_url))
    other = urlparse(canonicalize_base_url(candidate_url))
    return (
        base.scheme == other.scheme
        and base.hostname == other.hostname
        and base.port == other.port
    )


def _normalized_declared_surface_kind(value: Any) -> str | None:
    if not value:
        return None
    normalized = str(value).strip()
    if normalized == "non_crypto":
        return normalized
    return normalized if normalized in SURFACE_KINDS else None


def classify_surface_kind(path: str, *texts: str) -> str | None:
    haystack = " ".join((path, *texts)).lower()
    if "verify-hmac" in haystack or ("hmac" in haystack and "verify" in haystack):
        return "hmac_verifier"
    if "/auth" in path.lower() or "jwt" in haystack or "bearer" in haystack:
        return "jwt_auth_surface"
    if "decrypt" in haystack:
        return "decryption_oracle"
    if "encrypt" in haystack:
        return "encryption_oracle"
    if "hash" in haystack:
        return "hash_oracle"
    if "token" in haystack:
        return "token_issuer"
    return None


def _choose_surface_kind(
    path: str,
    texts: list[str],
    declared_surface_kind: Any = None,
    crypto_relevant: Any = None,
) -> tuple[str | None, str, str | None]:
    normalized_declared = _normalized_declared_surface_kind(declared_surface_kind)
    if crypto_relevant is False or normalized_declared == "non_crypto":
        return None, "declared_non_crypto", normalized_declared
    if normalized_declared in SURFACE_KINDS:
        return normalized_declared, "declared", normalized_declared
    heuristic = classify_surface_kind(path, *texts)
    if heuristic is not None:
        return heuristic, "heuristic", normalized_declared
    return None, "unclassified", normalized_declared


def _candidate_from_entry(
    *,
    base_url: str,
    path: str,
    methods: list[str],
    texts: list[str],
    source_name: str,
    source_url: str,
    descriptor_format: str,
    declared_surface_kind: Any = None,
    crypto_relevant: Any = None,
) -> CandidateEndpoint:
    endpoint_url = canonicalize_endpoint_url(base_url, path)
    surface_kind, classification_basis, normalized_declared = _choose_surface_kind(
        normalize_endpoint_path(path),
        texts,
        declared_surface_kind=declared_surface_kind,
        crypto_relevant=crypto_relevant,
    )
    candidate = CandidateEndpoint(
        endpoint_url=endpoint_url,
        endpoint_path=normalize_endpoint_path(path),
        methods=set(normalize_methods(methods)),
        surface_kind=surface_kind,
        sources={source_name},
        source_urls={source_url},
        descriptor_formats={descriptor_format},
        classification_bases={classification_basis},
        declared_surface_kinds={normalized_declared} if normalized_declared else set(),
        same_origin=_same_origin(base_url, endpoint_url),
    )
    return candidate


def _extract_from_service_index_payload(
    payload: dict[str, Any], base_url: str, source_url: str, descriptor_format: str
) -> list[CandidateEndpoint]:
    entries = payload.get("endpoints")
    if not isinstance(entries, list):
        entries = payload.get("routes")
    if not isinstance(entries, list):
        return []

    candidates: list[CandidateEndpoint] = []
    for entry in entries:
        if not isinstance(entry, dict) or "path" not in entry:
            continue
        methods = normalize_methods(entry.get("methods") or entry.get("method")) or ["GET"]
        texts = [
            str(entry.get("benchmark", "")),
            str(entry.get("vuln", "")),
            str(entry.get("summary", "")),
            str(entry.get("description", "")),
        ]
        candidates.append(
            _candidate_from_entry(
                base_url=base_url,
                path=str(entry["path"]),
                methods=methods,
                texts=texts,
                source_name="service_index",
                source_url=source_url,
                descriptor_format=descriptor_format,
                declared_surface_kind=entry.get("surface_kind") or entry.get("x-bbci-surface-kind"),
                crypto_relevant=entry.get("crypto_relevant", entry.get("x-bbci-crypto-relevant")),
            )
        )
    return candidates


def _extract_from_openapi_payload(
    payload: dict[str, Any], base_url: str, source_url: str, descriptor_format: str
) -> list[CandidateEndpoint]:
    paths = payload.get("paths", {})
    if not isinstance(paths, dict):
        return []

    candidates: list[CandidateEndpoint] = []
    for path, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        methods: set[str] = set()
        texts: list[str] = []
        declared_surface_kind = None
        crypto_relevant = None
        for method, operation in operations.items():
            upper_method = method.upper()
            if upper_method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            methods.add(upper_method)
            texts.extend(
                [
                    str(operation.get("summary", "")),
                    str(operation.get("description", "")),
                    " ".join(str(tag) for tag in operation.get("tags", [])),
                    str(operation.get("operationId", "")),
                ]
            )
            declared_surface_kind = (
                operation.get("x-bbci-surface-kind") or declared_surface_kind
            )
            if "x-bbci-crypto-relevant" in operation:
                crypto_relevant = operation["x-bbci-crypto-relevant"]
        if not methods:
            continue
        candidates.append(
            _candidate_from_entry(
                base_url=base_url,
                path=str(path),
                methods=sorted(methods),
                texts=texts,
                source_name="openapi",
                source_url=source_url,
                descriptor_format=descriptor_format,
                declared_surface_kind=declared_surface_kind,
                crypto_relevant=crypto_relevant,
            )
        )
    return candidates


def extract_service_index_candidates(
    payload: dict[str, Any], base_url: str
) -> list[CandidateEndpoint]:
    return _extract_from_service_index_payload(
        payload,
        base_url=base_url,
        source_url=canonicalize_base_url(base_url),
        descriptor_format="service_index",
    )


def extract_openapi_candidates(payload: dict[str, Any], base_url: str) -> list[CandidateEndpoint]:
    return _extract_from_openapi_payload(
        payload,
        base_url=base_url,
        source_url=urljoin(canonicalize_base_url(base_url), "/openapi.json"),
        descriptor_format="openapi",
    )


def _descriptor_format(payload: dict[str, Any]) -> str:
    has_endpoints = (
        isinstance(payload.get("endpoints"), list)
        or isinstance(payload.get("routes"), list)
    )
    has_paths = isinstance(payload.get("paths"), dict)
    if has_endpoints and has_paths:
        return "hybrid"
    if has_paths:
        return "openapi"
    if has_endpoints:
        return "service_index"
    return "unknown"


def _discovery_id(endpoint_url: str, surface_kind: str, methods: list[str]) -> str:
    digest = hashlib.sha1(
        f"{endpoint_url}:{surface_kind}:{','.join(methods)}".encode()
    ).hexdigest()
    return f"PHASE02-{digest[:10].upper()}"


class Phase02Scanner:
    """Deterministic phase02 scanner for a single application base URL."""

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    async def scan_target(self, base_url: str) -> dict[str, Any]:
        canonical_base_url = canonicalize_base_url(base_url)
        started_at = _utcnow()
        started_monotonic = time.monotonic()

        request_accounting = {
            "total_actions": 0,
            "descriptor_fetches": 0,
            "redirect_hops_followed": 0,
            "budget_compliant": True,
        }
        observations: list[dict[str, Any]] = []
        discoveries: list[dict[str, Any]] = []

        descriptor_specs = [
            ("service_index", canonical_base_url),
            ("openapi", urljoin(canonical_base_url, "/openapi.json")),
            ("openapi", urljoin(canonical_base_url, "/swagger.json")),
        ]

        merged_candidates: dict[tuple[str, str], CandidateEndpoint] = {}
        descriptor_sources: set[str] = set()
        descriptor_urls: set[str] = set()
        raw_candidate_count = 0
        non_crypto_candidate_count = 0
        successful_descriptor_fetches = 0
        failed_descriptor_fetches = 0
        time_to_first_relevant_seconds: float | None = None

        for source_hint, descriptor_url in descriptor_specs:
            attempt = await self._fetch_descriptor(
                base_url=canonical_base_url,
                descriptor_url=descriptor_url,
                source_hint=source_hint,
                request_accounting=request_accounting,
            )
            observation_id = f"{source_hint}:{urlparse(descriptor_url).path or '/'}"
            extracted_candidates: list[CandidateEndpoint] = []
            if attempt.payload is not None:
                successful_descriptor_fetches += 1
                descriptor_sources.add(source_hint)
                descriptor_urls.add(descriptor_url)
                descriptor_format = attempt.descriptor_format or "unknown"
                extracted_candidates.extend(
                    _extract_from_service_index_payload(
                        attempt.payload,
                        base_url=canonical_base_url,
                        source_url=attempt.final_url or descriptor_url,
                        descriptor_format=descriptor_format,
                    )
                )
                extracted_candidates.extend(
                    _extract_from_openapi_payload(
                        attempt.payload,
                        base_url=canonical_base_url,
                        source_url=attempt.final_url or descriptor_url,
                        descriptor_format=descriptor_format,
                    )
                )
            else:
                failed_descriptor_fetches += 1

            descriptor_candidate_summaries: list[dict[str, Any]] = []
            for candidate in extracted_candidates:
                raw_candidate_count += 1
                candidate.observation_ids.add(observation_id)
                if not candidate.same_origin:
                    descriptor_candidate_summaries.append(
                        {
                            "endpoint_url": candidate.endpoint_url,
                            "endpoint_path": candidate.endpoint_path,
                            "methods": sorted(candidate.methods),
                            "surface_kind": candidate.surface_kind,
                            "same_origin": False,
                            "classification_bases": sorted(candidate.classification_bases),
                        }
                    )
                    continue
                if candidate.surface_kind is None:
                    non_crypto_candidate_count += 1
                    descriptor_candidate_summaries.append(
                        {
                            "endpoint_url": candidate.endpoint_url,
                            "endpoint_path": candidate.endpoint_path,
                            "methods": sorted(candidate.methods),
                            "surface_kind": None,
                            "same_origin": True,
                            "classification_bases": sorted(candidate.classification_bases),
                        }
                    )
                    continue

                key = (candidate.endpoint_url, candidate.surface_kind)
                merged = merged_candidates.setdefault(
                    key,
                    CandidateEndpoint(
                        endpoint_url=candidate.endpoint_url,
                        endpoint_path=candidate.endpoint_path,
                        methods=set(),
                        surface_kind=candidate.surface_kind,
                    ),
                )
                merged.methods.update(candidate.methods)
                merged.sources.update(candidate.sources)
                merged.observation_ids.update(candidate.observation_ids)
                merged.source_urls.update(candidate.source_urls)
                merged.descriptor_formats.update(candidate.descriptor_formats)
                merged.classification_bases.update(candidate.classification_bases)
                merged.declared_surface_kinds.update(candidate.declared_surface_kinds)
                merged.same_origin = merged.same_origin and candidate.same_origin
                descriptor_candidate_summaries.append(
                    {
                        "endpoint_url": candidate.endpoint_url,
                        "endpoint_path": candidate.endpoint_path,
                        "methods": sorted(candidate.methods),
                        "surface_kind": candidate.surface_kind,
                        "same_origin": True,
                        "classification_bases": sorted(candidate.classification_bases),
                    }
                )
                if time_to_first_relevant_seconds is None:
                    time_to_first_relevant_seconds = round(
                        max(time.monotonic() - started_monotonic, 0.001),
                        4,
                    )

            observations.append(
                {
                    "id": observation_id,
                    "type": source_hint,
                    "target_url": descriptor_url,
                    "captured_at": _utcnow(),
                    "data": {
                        "source_url": descriptor_url,
                        "fetch_status": attempt.fetch_status,
                        "status_code": attempt.status_code,
                        "same_origin": attempt.same_origin,
                        "final_url": attempt.final_url,
                        "redirected_to": attempt.redirected_to,
                        "format": attempt.descriptor_format,
                        "error": attempt.error,
                    },
                }
            )
            observations.append(
                {
                    "id": f"candidate_inventory:{observation_id}",
                    "type": "candidate_inventory",
                    "target_url": descriptor_url,
                    "captured_at": _utcnow(),
                    "data": {
                        "descriptor_observation_id": observation_id,
                        "candidate_count": len(descriptor_candidate_summaries),
                        "relevant_candidate_count": sum(
                            1
                            for candidate in descriptor_candidate_summaries
                            if candidate["surface_kind"]
                        ),
                        "candidates": descriptor_candidate_summaries,
                    },
                }
            )

        benchmark_verdicts: list[dict[str, Any]] = []
        for endpoint_url, surface_kind in sorted(merged_candidates):
            candidate = merged_candidates[(endpoint_url, surface_kind)]
            methods = sorted(candidate.methods)
            classification_basis = (
                "declared"
                if "declared" in candidate.classification_bases
                else sorted(candidate.classification_bases)[0]
            )
            source_count = len(candidate.sources)
            confidence = 0.90
            if classification_basis == "declared":
                confidence += 0.05
            confidence += min(source_count * 0.02, 0.04)
            discoveries.append(
                {
                    "id": _discovery_id(endpoint_url, surface_kind, methods),
                    "endpoint_url": endpoint_url,
                    "endpoint_path": candidate.endpoint_path,
                    "methods": methods,
                    "surface_kind": surface_kind,
                    "confidence": round(min(confidence, 0.99), 2),
                    "evidence": {
                        "observation_ids": sorted(candidate.observation_ids),
                        "base_url": canonical_base_url,
                        "collected_via": PHASE02_SCANNER_NAME,
                        "captured_at": _utcnow(),
                        "sources": sorted(candidate.sources),
                        "source_urls": sorted(candidate.source_urls),
                        "endpoint_url": endpoint_url,
                        "endpoint_path": candidate.endpoint_path,
                        "methods": methods,
                        "surface_kind": surface_kind,
                        "same_origin": True,
                        "classification_basis": classification_basis,
                        "descriptor_formats": sorted(candidate.descriptor_formats),
                        "declared_surface_kind": sorted(candidate.declared_surface_kinds)[0]
                        if candidate.declared_surface_kinds
                        else None,
                        "source_count": source_count,
                    },
                }
            )

        request_accounting["budget_compliant"] = request_accounting["total_actions"] <= 6

        return {
            "schema_version": PHASE02_SCHEMA_VERSION,
            "suite_id": "phase02",
            "scanner": {
                "name": PHASE02_SCANNER_NAME,
                "version": _scanner_version(),
            },
            "execution": {
                "base_url": base_url,
                "canonical_base_url": canonical_base_url,
                "evaluation_mode": "base_url_discovery",
                "started_at": started_at,
                "finished_at": _utcnow(),
            },
            "request_accounting": request_accounting,
            "observations": observations,
            "discoveries": discoveries,
            "benchmark_verdicts": benchmark_verdicts,
            "summary": {
                "candidate_count": len(merged_candidates),
                "candidate_count_before_filter": raw_candidate_count,
                "non_crypto_candidate_count": non_crypto_candidate_count,
                "relevant_discovery_count": len(discoveries),
                "descriptor_attempts": len(descriptor_specs),
                "successful_descriptor_fetches": successful_descriptor_fetches,
                "failed_descriptor_fetches": failed_descriptor_fetches,
                "descriptor_sources": sorted(descriptor_sources),
                "descriptor_urls": sorted(descriptor_urls),
                "matched_discovery_count": 0,
                "false_positive_discovery_count": 0,
                "missed_expected_count": 0,
                "time_to_first_relevant_seconds": time_to_first_relevant_seconds,
            },
        }

    async def _fetch_descriptor(
        self,
        *,
        base_url: str,
        descriptor_url: str,
        source_hint: str,
        request_accounting: dict[str, Any],
    ) -> DescriptorAttempt:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=self.timeout,
        ) as client:
            try:
                response = await client.get(descriptor_url)
            except httpx.HTTPError as exc:
                return DescriptorAttempt(
                    source_hint=source_hint,
                    requested_url=descriptor_url,
                    fetch_status="transport_error",
                    error=str(exc),
                )

            request_accounting["descriptor_fetches"] += 1
            request_accounting["total_actions"] += 1

            final_url = str(response.request.url)
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    return DescriptorAttempt(
                        source_hint=source_hint,
                        requested_url=descriptor_url,
                        fetch_status="redirect_without_location",
                        status_code=response.status_code,
                        final_url=final_url,
                    )
                redirected = str(response.request.url.join(location))
                if not _same_origin(base_url, redirected):
                    return DescriptorAttempt(
                        source_hint=source_hint,
                        requested_url=descriptor_url,
                        fetch_status="cross_origin_redirect_blocked",
                        status_code=response.status_code,
                        final_url=final_url,
                        redirected_to=redirected,
                        same_origin=False,
                    )
                try:
                    response = await client.get(redirected)
                except httpx.HTTPError as exc:
                    return DescriptorAttempt(
                        source_hint=source_hint,
                        requested_url=descriptor_url,
                        fetch_status="redirect_target_error",
                        status_code=response.status_code,
                        final_url=final_url,
                        redirected_to=redirected,
                        error=str(exc),
                    )
                request_accounting["descriptor_fetches"] += 1
                request_accounting["total_actions"] += 1
                request_accounting["redirect_hops_followed"] += 1
                final_url = str(response.request.url)

            if response.status_code >= 400:
                return DescriptorAttempt(
                    source_hint=source_hint,
                    requested_url=descriptor_url,
                    fetch_status="http_error",
                    status_code=response.status_code,
                    final_url=final_url,
                )

            try:
                payload = response.json()
            except ValueError as exc:
                return DescriptorAttempt(
                    source_hint=source_hint,
                    requested_url=descriptor_url,
                    fetch_status="parse_error",
                    status_code=response.status_code,
                    final_url=final_url,
                    error=str(exc),
                )
            if not isinstance(payload, dict):
                return DescriptorAttempt(
                    source_hint=source_hint,
                    requested_url=descriptor_url,
                    fetch_status="unexpected_payload",
                    status_code=response.status_code,
                    final_url=final_url,
                )

            return DescriptorAttempt(
                source_hint=source_hint,
                requested_url=descriptor_url,
                fetch_status="fetched",
                status_code=response.status_code,
                final_url=final_url,
                descriptor_format=_descriptor_format(payload),
                payload=payload,
            )
