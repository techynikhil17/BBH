import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from collector.sources.github_writeups import GitHubWriteupsCollector

SAMPLE_RESPONSE = {
    "items": [
        {
            "full_name": "hunter/ssrf-writeup",
            "html_url": "https://github.com/hunter/ssrf-writeup",
            "description": "SSRF vulnerability in Acme Corp disclosed",
            "stargazers_count": 42,
            "topics": ["ssrf", "bugbounty"],
            "language": "Python",
            "updated_at": "2024-11-01T10:00:00Z",
        },
        {
            "full_name": "researcher/xss-chain",
            "html_url": "https://github.com/researcher/xss-chain",
            "description": "XSS to account takeover chain",
            "stargazers_count": 15,
            "topics": ["xss"],
            "language": None,
            "updated_at": "2024-10-15T08:00:00Z",
        },
    ]
}

EMPTY_RESPONSE = {"items": []}


def make_mock_response(data, status=200):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


async def test_collects_repos():
    responses = [make_mock_response(SAMPLE_RESPONSE), make_mock_response(EMPTY_RESPONSE)]

    with patch.dict("os.environ", {}, clear=True):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=responses)
            mock_client_cls.return_value = mock_client

            collector = GitHubWriteupsCollector()
            collector.rate_limit_seconds = 0
            reports = [r async for r in collector.collect(10)]

    assert len(reports) == 2
    assert reports[0].source == "github"
    assert reports[0].url == "https://github.com/hunter/ssrf-writeup"
    assert reports[0].source_metadata["stars"] == 42
    assert "ssrf" in reports[0].vuln_type_tags


async def test_uses_token_when_env_set():
    with patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"}):
        collector = GitHubWriteupsCollector()
    assert "Authorization" in collector._headers
    assert collector._headers["Authorization"] == "Bearer ghp_test123"
    assert collector.rate_limit_seconds == 2.0


async def test_no_token_warns_and_slower():
    with patch.dict("os.environ", {}, clear=True):
        collector = GitHubWriteupsCollector()
    assert "Authorization" not in collector._headers
    assert collector.rate_limit_seconds == 6.0


async def test_respects_limit():
    big = {"items": [
        {
            "full_name": f"u/r{i}",
            "html_url": f"https://github.com/u/r{i}",
            "description": "desc",
            "stargazers_count": 0,
            "topics": [],
            "language": None,
            "updated_at": "2024-01-01T00:00:00Z",
        }
        for i in range(20)
    ]}

    with patch.dict("os.environ", {}, clear=True):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=make_mock_response(big))
            mock_client_cls.return_value = mock_client

            collector = GitHubWriteupsCollector()
            collector.rate_limit_seconds = 0
            reports = [r async for r in collector.collect(3)]

    assert len(reports) == 3
