from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

from app.registry import list_checks, run_audit
from app import storage

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="SEO/GEO Audit Service", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Отдельное окружение для PDF-отчёта: autoescape обязателен (в шаблон попадают данные аудита)
_pdf_env = Environment(loader=FileSystemLoader(str(BASE_DIR / "templates")), autoescape=True)


def _status_emoji(status: str) -> str:
    if status == "ok":
        return "✅"
    if status in ("warning", "skipped"):
        return "⚠️"
    if status in ("critical", "error"):
        return "❌"
    return "❓"


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", {})


@app.get("/api/checks")
async def api_checks() -> JSONResponse:
    return JSONResponse({"checks": list_checks()})


@app.post("/api/audit")
async def api_audit(payload: Dict[str, Any]) -> JSONResponse:
    url = payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="url required")

    keywords_raw = payload.get("keywords") or ""
    if isinstance(keywords_raw, str):
        keywords = [k.strip() for k in keywords_raw.split(",") if k.strip()]
    elif isinstance(keywords_raw, list):
        keywords = [str(k).strip() for k in keywords_raw if str(k).strip()]
    else:
        keywords = []

    competitor = payload.get("competitor") or None
    if isinstance(competitor, str) and not competitor.strip():
        competitor = None

    # Выбранные проверки: пустой список или отсутствие поля = все
    checks_raw = payload.get("checks") or []
    if isinstance(checks_raw, list):
        only_checks = [str(c).strip() for c in checks_raw if str(c).strip()]
    else:
        only_checks = []

    # Run main audit
    result = await run_audit(url=url, keywords=keywords, only=only_checks or None)

    # Run competitor if provided
    competitor_result = None
    if competitor:
        try:
            competitor_result = await run_audit(url=competitor, keywords=keywords, only=only_checks or None)
        except Exception as e:
            competitor_result = {"error": str(e)}

    audit_id = storage.save_audit(result)

    return JSONResponse(
        {
            "id": audit_id,
            "result": result,
            "competitor": competitor_result,
        }
    )


@app.get("/api/audits")
async def api_audits() -> JSONResponse:
    return JSONResponse(storage.list_audits())


@app.get("/api/audits/{id}")
async def api_audit_get(id: int) -> JSONResponse:
    data = storage.get_audit(id)
    if not data:
        raise HTTPException(status_code=404, detail="not found")
    return JSONResponse(data)


@app.get("/api/audits/{id}/export.md")
async def api_audit_export_md(id: int) -> PlainTextResponse:
    data = storage.get_audit(id)
    if not data:
        raise HTTPException(status_code=404, detail="not found")
    result = data.get("result", {})

    lines: List[str] = []
    lines.append(f"# Аудит {result.get('url')}")
    lines.append(f"Общий балл: {result.get('overall_score')}/100")
    lines.append("")

    # Group by category
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for c in result.get("checks", []):
        by_cat.setdefault(c.get("category", "Прочее"), []).append(c)

    lines.append("## Результаты по категориям")
    for cat, checks in by_cat.items():
        lines.append(f"### {cat}")
        lines.append("| Проверка | Статус | Балл |")
        lines.append("|---|---|---|")
        for c in checks:
            lines.append(f"| {c.get('title')} | {_status_emoji(c.get('status'))} {c.get('status')} | {c.get('score')} |")
        lines.append("")

    # Findings
    lines.append("## Найденные проблемы")
    for cat, checks in by_cat.items():
        for c in checks:
            for f in c.get("findings", []):
                if f.get("level") in ("ok",):
                    continue
                lines.append(f"- [{c.get('title')}] {f.get('text')} (уровень: {f.get('level')})")
                if f.get("fix"):
                    lines.append(f"  Как исправить: {f.get('fix')}")
    lines.append("")

    # Plan
    plan = result.get("plan", {})
    lines.append("## План работ")
    lines.append("| Проверка | Проблема | Как исправить | Часы |")
    lines.append("|---|---|---|---|")
    for p in plan.get("findings", []):
        lines.append(f"| {p.get('check_title')} | {p.get('text')} | {p.get('fix')} | {p.get('hours')} |")
    lines.append(f"| **Итого** | | | **{plan.get('total_hours')}** |")
    lines.append("")

    return PlainTextResponse("\n".join(lines), media_type="text/markdown; charset=utf-8")


def render_report_html(result: dict) -> str:
    """Собрать данные клиентского отчёта и отрендерить HTML (тестируемо без PDF)."""
    checks = result.get("checks") or []

    critical_items: List[Dict[str, Any]] = []
    warning_items: List[Dict[str, Any]] = []
    info_items: List[Dict[str, Any]] = []
    ok_items: List[Dict[str, Any]] = []
    skipped_items: List[Dict[str, Any]] = []

    for c in checks:
        status = c.get("status")
        base = {"check_id": c.get("id"), "title": c.get("title", ""), "category": c.get("category", "")}
        findings = c.get("findings") or []

        if status in ("skipped", "error"):
            reason = ""
            for f in findings:
                if f.get("level") != "ok" and f.get("text"):
                    reason = f["text"]
                    break
            if not reason and findings:
                reason = findings[0].get("text", "")
            if not reason:
                reason = (c.get("raw") or {}).get("error") or "Проверка не выполнена"
            skipped_items.append({**base, "status": status, "reason": reason})
            continue

        if status == "ok":
            text = ""
            for f in findings:
                if f.get("level") == "ok":
                    text = f.get("text", "")
                    break
            ok_items.append({**base, "text": text or "Проверка пройдена"})
            continue

        # critical / warning: группируем находки по уровню (info уходит в рекомендации)
        grouped: Dict[str, List[Dict[str, str]]] = {"critical": [], "warning": [], "info": []}
        for f in findings:
            level = f.get("level")
            if level in grouped:
                grouped[level].append({"text": f.get("text", ""), "fix": f.get("fix", "")})
        if not any(grouped.values()) and status in ("critical", "warning"):
            grouped[status].append({"text": "Проверка не пройдена", "fix": ""})
        for level, target in (("critical", critical_items), ("warning", warning_items), ("info", info_items)):
            for g in grouped[level]:
                target.append({**base, **g})

    summary = result.get("summary")
    if not isinstance(summary, dict):
        summary = {"critical": 0, "warning": 0, "ok": 0, "skipped": 0}
        for c in checks:
            s = c.get("status")
            if s in summary:
                summary[s] += 1
            else:
                summary["skipped"] += 1

    created_at = result.get("created_at") or datetime.now().isoformat(timespec="seconds")

    template = _pdf_env.get_template("report_pdf.html")
    return template.render(
        result=result,
        report_date=str(created_at)[:10],
        summary=summary,
        critical_items=critical_items,
        warning_items=warning_items,
        info_items=info_items,
        ok_items=ok_items,
        skipped_items=skipped_items,
    )


@app.get("/api/audits/{id}/report.pdf")
async def api_audit_report_pdf(id: int) -> Response:
    data = storage.get_audit(id)
    if not data:
        raise HTTPException(status_code=404, detail="not found")
    result = data.get("result", {})

    html = render_report_html(result)
    try:
        # Ленивый импорт: WeasyPrint тянет нативные зависимости (Pango) и может отсутствовать
        from weasyprint import HTML  # noqa: PLC0415

        pdf_bytes = HTML(string=html, base_url=str(STATIC_DIR)).write_pdf()
    except (ImportError, OSError) as e:
        raise HTTPException(
            status_code=503,
            detail=f'PDF недоступен: не установлен "WeasyPrint" ({e})',
        ) from e

    host = "".join(ch for ch in str(result.get("host") or "site") if ch.isalnum() or ch in ".-_")
    filename = f"seo-geo-audit-{host}-{datetime.now().strftime('%Y-%m-%d')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
