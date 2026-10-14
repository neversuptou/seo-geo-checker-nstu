from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from app.registry import run_audit
from app import storage

app = FastAPI(title="SEO/GEO Audit Service", version="0.1.0")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


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

    # Run main audit
    result = await run_audit(url=url, keywords=keywords)

    # Run competitor if provided
    competitor_result = None
    if competitor:
        try:
            competitor_result = await run_audit(url=competitor, keywords=keywords)
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
