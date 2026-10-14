"""MCP-сервер (Streamable HTTP): запуск аудитов и получение отчётов из Claude без веб-интерфейса.

Монтируется в FastAPI по адресу /mcp/<MCP_TOKEN> (см. app/main.py).
"""
from __future__ import annotations

import base64
import os
from typing import Any, Dict, List

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from app import storage
from app.registry import list_checks as _list_checks
from app.registry import run_audit as _run_audit

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://check-seo-geo.evapps.ru").rstrip("/")
MAX_INLINE_PDF = 4 * 1024 * 1024

LEVEL_ORDER = {"critical": 0, "warning": 1, "info": 2}

mcp = FastMCP(
    "seo-geo-checker",
    instructions=(
        "Аудит сайтов для SEO и GEO (видимость в ИИ-поиске): 50+ проверок — robots/llms.txt, "
        "Schema.org, sitemap, краулинг, мета-теги, скорость, безопасность, E-E-A-T, DNS/SSL. "
        "Сначала run_audit, затем при необходимости get_report для PDF клиенту."
    ),
    stateless_http=True,
    json_response=True,
    streamable_http_path="/",
    # За обратным прокси Host — публичный домен; доступ и так закрыт секретным токеном в пути
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


def _links(audit_id: int) -> Dict[str, str]:
    return {
        "web": f"{PUBLIC_BASE_URL}/?audit={audit_id}",
        "pdf": f"{PUBLIC_BASE_URL}/api/audits/{audit_id}/report.pdf",
        "markdown": f"{PUBLIC_BASE_URL}/api/audits/{audit_id}/export.md",
    }


def compact_result(result: Dict[str, Any], audit_id: int, base: str = PUBLIC_BASE_URL) -> Dict[str, Any]:
    """Сжатое представление аудита для LLM: проблемы по приоритету, без часов и сырых данных."""
    problems: List[Dict[str, str]] = []
    passed: List[str] = []
    skipped: List[Dict[str, str]] = []
    for c in result.get("checks") or []:
        status = c.get("status")
        findings = c.get("findings") or []
        if status == "ok":
            passed.append(c.get("title", ""))
            continue
        if status in ("skipped", "error"):
            reason = next((f.get("text", "") for f in findings if f.get("text")), "")
            skipped.append({"check": c.get("title", ""), "reason": reason})
            continue
        for f in findings:
            level = f.get("level")
            if level not in LEVEL_ORDER:
                continue
            problems.append(
                {
                    "priority": level,
                    "check": c.get("title", ""),
                    "category": c.get("category", ""),
                    "problem": f.get("text", ""),
                    "fix": f.get("fix", ""),
                }
            )
    problems.sort(key=lambda p: LEVEL_ORDER[p["priority"]])
    links = {k: v.replace(PUBLIC_BASE_URL, base.rstrip("/"), 1) for k, v in _links(audit_id).items()}
    return {
        "audit_id": audit_id,
        "url": result.get("url"),
        "created_at": result.get("created_at"),
        "overall_score": result.get("overall_score"),
        "blocked": bool(result.get("blocked")),
        "summary": result.get("summary"),
        "problems": problems,
        "passed": passed,
        "skipped": skipped,
        "links": links,
    }


def resolve_check_ids(checks: List[str] | None, categories: List[str] | None) -> List[str]:
    """id проверок из явного списка и/или названий категорий (без учёта регистра). Пусто = все."""
    ids: List[str] = list(checks or [])
    if categories:
        wanted = {c.strip().lower() for c in categories}
        ids += [c["id"] for c in _list_checks() if c["category"].lower() in wanted]
    return list(dict.fromkeys(ids))


@mcp.tool()
def list_checks() -> Dict[str, Any]:
    """Список всех проверок (id, название, категория) и категорий.

    List all available audit checks and categories. Use ids/categories to run a subset in run_audit.
    """
    checks = _list_checks()
    return {"checks": checks, "categories": sorted({c["category"] for c in checks})}


@mcp.tool()
async def run_audit(
    url: str,
    checks: List[str] | None = None,
    categories: List[str] | None = None,
    gentle: bool = True,
    keywords: List[str] | None = None,
) -> Dict[str, Any]:
    """Запустить SEO/GEO-аудит сайта (30–180 с) и сохранить его в историю.

    Run an SEO/GEO audit of a website. By default runs all checks; pass `checks` (ids) or
    `categories` to run a subset. `gentle=True` paces requests to avoid anti-bot blocks.
    `keywords` enables BM25 relevance check. Returns problems sorted by priority with fixes,
    passed checks and links to the web view, client PDF and Markdown.
    """
    only = resolve_check_ids(checks, categories)
    result = await _run_audit(url=url, keywords=keywords or [], only=only or None, gentle=gentle)
    audit_id = storage.save_audit(result)
    return compact_result(result, audit_id)


def _load(audit_id: int) -> Dict[str, Any] | None:
    data = storage.get_audit(audit_id)
    if not data:
        return None
    return data.get("result", data)


@mcp.tool()
def get_audit(audit_id: int, include_raw: bool = False) -> Dict[str, Any]:
    """Получить сохранённый аудит по id. include_raw=True — полный результат со всеми данными.

    Get a stored audit by id (compact by default, full raw result with include_raw=True).
    """
    result = _load(audit_id)
    if result is None:
        return {"error": f"Аудит {audit_id} не найден"}
    if include_raw:
        return {"audit_id": audit_id, "result": result, "links": _links(audit_id)}
    return compact_result(result, audit_id)


@mcp.tool()
def list_audits(limit: int = 20, url_contains: str | None = None) -> Dict[str, Any]:
    """История аудитов (id, url, балл, дата), опционально с фильтром по части URL.

    List past audits, newest first, optionally filtered by URL substring.
    """
    items = storage.list_audits(limit=500 if url_contains else limit)
    if url_contains:
        needle = url_contains.lower()
        items = [a for a in items if needle in str(a.get("url", "")).lower()][:limit]
    return {"audits": items}


@mcp.tool()
def get_report(audit_id: int, format: str = "pdf") -> Dict[str, Any]:
    """Отчёт по аудиту: format="pdf" — клиентский PDF (только проблемы, без часов), "markdown" — текст.

    Get a report for an audit. PDF returns a download URL plus base64 content; markdown returns text.
    """
    from app.main import build_markdown, build_pdf  # noqa: PLC0415 — main импортирует этот модуль

    result = _load(audit_id)
    if result is None:
        return {"error": f"Аудит {audit_id} не найден"}
    if format == "markdown":
        return {"markdown": build_markdown(result)}
    try:
        pdf = build_pdf(result)
    except (ImportError, OSError) as e:
        return {"error": f"PDF недоступен: {e}", "url": _links(audit_id)["pdf"]}
    out: Dict[str, Any] = {"url": _links(audit_id)["pdf"], "size_bytes": len(pdf)}
    if len(pdf) <= MAX_INLINE_PDF:
        out["base64"] = base64.b64encode(pdf).decode("ascii")
    return out


@mcp.tool()
async def compare_sites(url: str, competitor_url: str, gentle: bool = True) -> Dict[str, Any]:
    """Сравнить сайт с конкурентом по всем проверкам: статусы и разница баллов.

    Audit a site and a competitor, return per-check status comparison and score difference.
    """
    ours = await _run_audit(url=url, gentle=gentle)
    theirs = await _run_audit(url=competitor_url, gentle=gentle)
    ours_id, theirs_id = storage.save_audit(ours), storage.save_audit(theirs)
    their_status = {c["id"]: c["status"] for c in theirs.get("checks", [])}
    rows = [
        {"check": c["title"], "category": c["category"], "ours": c["status"], "competitor": their_status.get(c["id"])}
        for c in ours.get("checks", [])
    ]
    return {
        "ours": {"audit_id": ours_id, "url": ours.get("url"), "score": ours.get("overall_score")},
        "competitor": {"audit_id": theirs_id, "url": theirs.get("url"), "score": theirs.get("overall_score")},
        "score_diff": (ours.get("overall_score") or 0) - (theirs.get("overall_score") or 0),
        "checks": rows,
    }
