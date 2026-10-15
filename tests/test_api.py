from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from app import registry, storage
from app.main import app, render_report_html

client = TestClient(app)


def test_api_checks_returns_non_empty_list():
    resp = client.get("/api/checks")
    assert resp.status_code == 200
    checks = resp.json()["checks"]
    assert isinstance(checks, list)
    assert len(checks) > 0
    for c in checks:
        assert {"id", "title", "category"} <= set(c.keys())


def test_list_checks_ids_unique():
    ids = [c["id"] for c in registry.list_checks()]
    assert len(ids) == len(set(ids))


@pytest.mark.asyncio
async def test_run_audit_only_selected_check():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="<!doctype html><html><head><title>Test</title></head><body><h1>Test page</h1></body></html>",
        )

    transport = httpx.MockTransport(handler)
    result = await registry.run_audit(
        "https://example.com", transport=transport, only=["http_status"]
    )

    assert [c["id"] for c in result["checks"]] == ["http_status"]
    assert result["selected"] == ["http_status"]
    assert result["summary"] == {"critical": 0, "warning": 0, "ok": 1, "skipped": 0}
    assert isinstance(result["created_at"], str)
    assert "T" in result["created_at"]  # ISO-метка времени


def _fake_result() -> dict:
    def chk(id_: str, status: str, findings: list) -> dict:
        return {
            "id": id_,
            "title": f"Проверка {id_}",
            "category": "Тестовая категория",
            "status": status,
            "score": 50,
            "findings": [
                {"level": lvl, "text": txt, "fix": fix, "hours": 1.5}
                for lvl, txt, fix in findings
            ],
            "raw": {},
        }

    checks = [
        chk("crit", "critical", [("critical", "Найдена критическая проблема", "Устранить критическую проблему")]),
        chk("warn", "warning", [("warning", "Найдено предупреждение", "Исправить предупреждение")]),
        chk("info", "warning", [("info", "Есть рекомендация по улучшению", "Применить рекомендацию")]),
        chk("good", "ok", [("ok", "Всё хорошо", "")]),
        chk("skip", "skipped", [("critical", "Проверка пропущена по условию", "")]),
    ]
    return {
        "url": "https://example.com",
        "base": "https://example.com",
        "host": "example.com",
        "overall_score": 55,
        "blocked": False,
        "created_at": "2026-01-01T12:00:00",
        "selected": ["crit", "warn", "info", "good", "skip"],
        "summary": {"critical": 1, "warning": 2, "ok": 1, "skipped": 1},
        "checks": checks,
    }


def test_render_report_html():
    html = render_report_html(_fake_result())
    assert "Что нужно <span class=\"accent\">исправить</span>" in html
    assert "Что в порядке" not in html
    assert "Не проверено" not in html
    assert "Часы" not in html
    assert "hours" not in html.lower()


def test_render_report_html_blocked():
    result = _fake_result()
    result["blocked"] = True
    result["overall_score"] = 0
    html = render_report_html(result)
    assert "Найдена критическая проблема" in html
    assert "Часы" not in html
    assert "hours" not in html.lower()


def test_report_pdf_endpoint():
    try:
        import weasyprint  # noqa: F401
    except (ImportError, OSError):
        pytest.skip("WeasyPrint или его нативные библиотеки недоступны")
    audit_id = storage.save_audit(_fake_result())
    resp = client.get(f"/api/audits/{audit_id}/report.pdf")
    if resp.status_code == 503:
        pytest.skip("WeasyPrint установлен, но нативные зависимости недоступны")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"
    disposition = resp.headers["content-disposition"]
    assert "attachment" in disposition
    assert "seo-geo-audit-example.com-" in disposition


def test_service_is_closed_from_indexing():
    resp = client.get("/robots.txt")
    assert resp.text.strip().endswith("Disallow: /")
    assert "noindex" in resp.headers["x-robots-tag"]
    page = client.get("/")
    assert "noindex" in page.headers["x-robots-tag"]
    assert '<meta name="robots" content="noindex' in page.text
