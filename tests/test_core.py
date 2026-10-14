from __future__ import annotations

import asyncio

import httpx
import pytest

from app.core import AuditContext, CheckResult, Finding
from app.registry import CHECKS, run_audit


def test_url_normalization():
    ctx = AuditContext(url="example.com")
    assert ctx.url.startswith("https://example.com")
    assert ctx.base.startswith("https://example.com")
    assert ctx.host == "example.com"

    ctx2 = AuditContext(url="http://example.com/path")
    assert ctx2.url == "http://example.com/path"
    assert ctx2.base == "http://example.com"
    assert ctx2.host == "example.com"

    ctx3 = AuditContext(url="https://example.com/")
    assert ctx3.url == "https://example.com"
    assert ctx3.base == "https://example.com"
    assert ctx3.host == "example.com"


@pytest.mark.asyncio
async def test_run_audit_error_wrapping(monkeypatch):
    # Create a failing dummy check
    async def failing_check(ctx):
        raise ValueError("boom")

    # Attach metadata
    failing_check._check_meta = {"id": "fail_check", "title": "Failing check", "category": "Test"}

    # Replace CHECKS with just this failing check
    monkeypatch.setattr("app.registry.CHECKS", [failing_check])

    # Mock transport to avoid real network
    def handler(request: httpx.Request) -> httpx.Response:
        # Shouldn't be called if checks don't use network, but just in case
        return httpx.Response(200, content=b"ok")

    transport = httpx.MockTransport(handler)

    result = await run_audit("example.com", transport=transport)
    assert result["overall_score"] == 0
    checks = result["checks"]
    assert len(checks) == 1
    assert checks[0]["status"] == "error"
    # exception text should be in findings
    findings_text = " ".join(f["text"] for f in checks[0]["findings"])
    assert "boom" in findings_text


@pytest.mark.asyncio
async def test_run_audit_stops_on_antibot_challenge():
    page = b"<html><head><title>One moment, please...</title></head><body></body></html>"
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=page))
    result = await run_audit("example.com", transport=transport)
    assert result["blocked"] is True
    assert [c["id"] for c in result["checks"]] == ["anti_bot_challenge"]


@pytest.mark.asyncio
async def test_gentle_transport_paces_requests_to_audited_host():
    import asyncio
    from app.core import ThrottledTransport

    times = []

    def handler(request):
        times.append(asyncio.get_running_loop().time())
        return httpx.Response(200, text="ok")

    transport = ThrottledTransport(httpx.MockTransport(handler), limit=2, paced_host="example.com", min_interval=0.2)
    async with httpx.AsyncClient(transport=transport) as client:
        await asyncio.gather(*[client.get(f"https://www.example.com/{i}") for i in range(3)])
        await client.get("https://other.org/")  # чужой хост не тормозим
    gaps = [b - a for a, b in zip(times, times[1:3])]
    assert all(g >= 0.18 for g in gaps)
