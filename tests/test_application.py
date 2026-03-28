"""Tests for Phase 2 application layer tools."""

import base64
import json

import pytest

from bbci.tools.application import ApplicationTools


@pytest.fixture
def app_tools() -> ApplicationTools:
    return ApplicationTools(timeout=10)


class TestAnalyzeJWT:
    @pytest.mark.asyncio
    async def test_rs256_jwt(self, app_tools: ApplicationTools) -> None:
        # Create a minimal RS256 JWT
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "1234567890", "name": "Test"}).encode()
        ).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b"\x00" * 256).rstrip(b"=").decode()

        token = f"{header}.{payload}.{sig}"
        result = await app_tools.analyze_jwt(token)

        assert result.success is True
        assert result.data["algorithm"] == "RS256"
        assert result.data["key_type"] == "RSA"
        assert result.data["pq_vulnerable"] is True

    @pytest.mark.asyncio
    async def test_none_alg_jwt(self, app_tools: ApplicationTools) -> None:
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "1234567890"}).encode()
        ).rstrip(b"=").decode()

        token = f"{header}.{payload}."
        result = await app_tools.analyze_jwt(token)

        assert result.success is True
        assert result.data["algorithm"] == "none"
        assert "CRITICAL" in result.data.get("vulnerability", "")

    @pytest.mark.asyncio
    async def test_hs256_jwt(self, app_tools: ApplicationTools) -> None:
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "test"}).encode()
        ).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode()

        token = f"{header}.{payload}.{sig}"
        result = await app_tools.analyze_jwt(token)

        assert result.success is True
        assert result.data["algorithm"] == "HS256"
        assert result.data["key_type"] == "symmetric"
        assert result.data["pq_vulnerable"] is False

    @pytest.mark.asyncio
    async def test_invalid_jwt(self, app_tools: ApplicationTools) -> None:
        result = await app_tools.analyze_jwt("not-a-jwt")
        assert result.success is False


class TestRandomnessTest:
    @pytest.mark.asyncio
    async def test_good_randomness(self, app_tools: ApplicationTools) -> None:
        import os
        samples = [os.urandom(32).hex() for _ in range(50)]
        result = await app_tools.randomness_test(samples)

        assert result.success is True
        assert "tests" in result.data
        # Good random data should pass frequency test
        assert result.data["tests"]["frequency"]["pass"] is True

    @pytest.mark.asyncio
    async def test_weak_randomness(self, app_tools: ApplicationTools) -> None:
        # Sequential counter — clearly non-random
        samples = [f"{i:064x}" for i in range(50)]
        result = await app_tools.randomness_test(samples)

        assert result.success is True
        # Sequential data should fail at least one test
        assert result.data["tests"]["sequential_correlation"]["is_sequential"] is True

    @pytest.mark.asyncio
    async def test_too_few_samples(self, app_tools: ApplicationTools) -> None:
        result = await app_tools.randomness_test(["aabb", "ccdd"])
        assert result.success is False


class TestAnalyzeHashLength:
    @pytest.mark.asyncio
    async def test_md5_detection(self, app_tools: ApplicationTools) -> None:
        result = await app_tools.analyze_hash_length(
            ["d41d8cd98f00b204e9800998ecf8427e"]
        )
        assert result.success is True
        assert "MD5" in result.data["analyses"][0]["likely_algorithm"]
        assert result.data["analyses"][0]["weak"] is True

    @pytest.mark.asyncio
    async def test_sha256_detection(self, app_tools: ApplicationTools) -> None:
        result = await app_tools.analyze_hash_length(
            ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        )
        assert result.success is True
        assert "SHA-256" in result.data["analyses"][0]["likely_algorithm"]
        assert result.data["analyses"][0]["weak"] is False

    @pytest.mark.asyncio
    async def test_sha1_detection(self, app_tools: ApplicationTools) -> None:
        result = await app_tools.analyze_hash_length(
            ["da39a3ee5e6b4b0d3255bfef95601890afd80709"]
        )
        assert result.success is True
        assert "SHA-1" in result.data["analyses"][0]["likely_algorithm"]
        assert result.data["analyses"][0]["weak"] is True
