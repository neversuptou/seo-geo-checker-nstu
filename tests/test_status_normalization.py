from __future__ import annotations

import asyncio

import httpx
import pytest

from app.core import CheckResult, Finding
from app.registry import normalize_check, normalize_result, run_audit


def _check(status: str, levels: list[str], score: int = 90, cid: str = "c") -> CheckResult:
    return CheckResult(
        id=cid, title=cid, category="Test", status=status, score=score,
        findings=[Finding(level=lvl, text=f"{lvl} finding", fix="fix") for lvl in levels], raw={},
    )


def test_manual_warning_with_critical_findings_becomes_critical():
    # Регресс: ai_bot_access вернул status="warning" при двух critical-проблемах (аудит 773)
    r = normalize_check(_check("warning", ["critical", "critical"], score=90))
    assert r.status == "critical"
    assert r.score == 40


def test_mixed_priorities_take_the_worst():
    assert normalize_check(_check("ok", ["warning", "critical", "info"])).status == "critical"


def test_only_warning_findings_give_warning_and_cap_score():
    r = normalize_check(_check("ok", ["warning"], score=95))
    assert r.status == "warning"
    assert r.score == 80


def test_no_problems_stays_ok():
    r = normalize_check(_check("ok", ["ok"], score=100))
    assert r.status == "ok"
    assert r.score == 100


def test_info_does_not_raise_status():
    assert normalize_check(_check("ok", ["info", "info"], score=100)).status == "ok"


def test_status_is_never_lowered():
    assert normalize_check(_check("critical", ["warning"])).status == "critical"


@pytest.mark.parametrize("status", ["skipped", "error"])
def test_skipped_and_error_are_untouched(status):
    r = normalize_check(_check(status, ["critical"], score=0))
    assert r.status == status
    assert r.score == 0


@pytest.mark.asyncio
async def test_run_audit_summary_counts_checks_with_critical_findings(monkeypatch):
    async def under_reported(ctx):
        return _check("warning", ["critical", "critical"], cid="bots")

    async def fine(ctx):
        return _check("ok", ["ok"], score=100, cid="fine")

    under_reported._check_meta = {"id": "bots", "title": "bots", "category": "Test"}
    fine._check_meta = {"id": "fine", "title": "fine", "category": "Test"}
    monkeypatch.setattr("app.registry.CHECKS", [under_reported, fine])

    transport = httpx.MockTransport(lambda req: httpx.Response(200, text="<html><title>t</title></html>"))
    result = await asyncio.wait_for(run_audit("example.com", transport=transport), 10)

    by_id = {c["id"]: c for c in result["checks"]}
    assert by_id["bots"]["status"] == "critical"
    with_critical = sum(1 for c in result["checks"] if any(f["level"] == "critical" for f in c["findings"]))
    assert result["summary"]["critical"] == with_critical == 1
    assert result["overall_score"] == 70  # (40 + 100) / 2: критичная проверка не тянет балл вверх


def _stored(status: str, levels: list[str], score: int) -> dict:
    return {
        "url": "https://example.com", "overall_score": 95,
        "summary": {"critical": 0, "warning": 1, "ok": 0, "skipped": 0},
        "checks": [{"id": "bots", "title": "bots", "category": "Test", "status": status, "score": score,
                    "findings": [{"level": lvl, "text": lvl, "fix": ""} for lvl in levels], "raw": {}}],
    }


def test_normalize_result_fixes_stored_audit():
    out = normalize_result(_stored("warning", ["critical", "critical"], 95))
    assert out["checks"][0]["status"] == "critical"
    assert out["summary"] == {"critical": 1, "warning": 0, "ok": 0, "skipped": 0}
    assert out["overall_score"] == 40


def test_normalize_result_leaves_blocked_audit_alone():
    blocked = {**_stored("critical", ["critical"], 0), "blocked": True, "overall_score": 0}
    assert normalize_result(blocked) is blocked
    assert blocked["summary"]["critical"] == 0


def test_get_audit_normalizes_audits_saved_before_the_rule():
    # Аудиты в БД сохранены до правила: веб, PDF, Markdown и MCP читают их через get_audit
    from app import storage

    audit_id = storage.save_audit(_stored("warning", ["critical", "critical"], 95))
    loaded = storage.get_audit(audit_id)["result"]
    assert loaded["summary"]["critical"] == 1, "get_audit отдал summary без нормализации"
    assert loaded["checks"][0]["status"] == "critical"


def test_renormalize_all_updates_history_score():
    from app import storage

    audit_id = storage.save_audit(_stored("warning", ["critical", "critical"], 95))
    storage.renormalize_all()
    row = next(a for a in storage.list_audits(limit=500) if a["id"] == audit_id)
    assert row["score"] == 40, "балл в истории не пересчитан"
