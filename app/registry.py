from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Awaitable

import httpx
from urllib.parse import urlparse

from app.core import AuditContext, CheckResult, Finding, BROWSER_UA, ThrottledTransport

GENTLE_INTERVAL = 0.8  # секунд между запросами к проверяемому сайту в бережном режиме

CHALLENGE_MARKERS = (
    "one moment, please",      # Imunify360 / LiteSpeed
    "just a moment...",        # Cloudflare
    "cf-chl-",                 # Cloudflare challenge
    "checking your browser",
    "ddos-guard",
    "verify you are human",
    "attention required! | cloudflare",
)


def detect_challenge(html: str) -> str | None:
    """Вернуть маркер, если вместо сайта отдана антибот-заглушка."""
    head = (html or "")[:20000].lower()
    for marker in CHALLENGE_MARKERS:
        if marker in head:
            return marker
    return None


CHECKS: List[Callable[[AuditContext], Awaitable[CheckResult]]] = []


def check(id: str, title: str, category: str):
    def decorator(fn: Callable[[AuditContext], Awaitable[CheckResult]]):
        async def wrapper(ctx: AuditContext) -> CheckResult:
            return await fn(ctx)

        # attach metadata
        wrapper._check_meta = {"id": id, "title": title, "category": category}
        CHECKS.append(wrapper)
        return wrapper

    return decorator


def list_checks() -> list[dict]:
    """Все зарегистрированные проверки в порядке регистрации."""
    return [dict(fn._check_meta) for fn in CHECKS if hasattr(fn, "_check_meta")]


# Итоговый статус проверки = максимальный уровень её проблем (critical > warning; info/ok статус не
# повышают). Статус, выставленный проверкой вручную, только повышается, никогда не понижается;
# skipped/error не трогаем. Балл проверки ограничен потолком её статуса (critical ≤ 40, warning ≤ 80),
# чтобы повышенная до critical проверка не тянула общий балл вверх. Общий балл = среднее баллов
# проверок без skipped/error. Нормализация централизована: проверки могут не следить за статусом сами.
STATUS_RANK = {"ok": 0, "warning": 1, "critical": 2}
SCORE_CAP = {"ok": 100, "warning": 80, "critical": 40}
UNRATED = ("skipped", "error")


def _final_status(status: str, levels: List[str]) -> str:
    if status in UNRATED:
        return status
    worst = max((lvl for lvl in levels if lvl in ("warning", "critical")), key=STATUS_RANK.get, default="ok")
    return worst if STATUS_RANK[worst] > STATUS_RANK.get(status, 0) else status


def normalize_check(r: CheckResult) -> CheckResult:
    """Поднять статус проверки до худшей её проблемы и ограничить балл потолком статуса."""
    r.status = _final_status(r.status, [f.level for f in r.findings])
    if r.status in SCORE_CAP:
        r.score = min(r.score, SCORE_CAP[r.status])
    return r


def _overall_score(scored: List[tuple[str, int]]) -> int:
    scores = [score for status, score in scored if status not in UNRATED]
    return int(round(sum(scores) / len(scores))) if scores else 0


def normalize_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """То же для сохранённого результата: статусы, summary и общий балл (старые аудиты в БД)."""
    if result.get("blocked"):
        return result
    summary = {"critical": 0, "warning": 0, "ok": 0, "skipped": 0}
    for c in result.get("checks", []):
        c["status"] = _final_status(c.get("status", "ok"), [f.get("level") for f in c.get("findings", [])])
        if c["status"] in SCORE_CAP and isinstance(c.get("score"), (int, float)):
            c["score"] = min(c["score"], SCORE_CAP[c["status"]])
        summary[c["status"] if c["status"] in summary else "skipped"] += 1
    result["summary"] = summary
    result["overall_score"] = _overall_score([(c["status"], c.get("score", 0)) for c in result.get("checks", [])])
    return result


def _summarize(results: List[CheckResult]) -> Dict[str, int]:
    """Сводка по статусам: error считается как skipped."""
    summary = {"critical": 0, "warning": 0, "ok": 0, "skipped": 0}
    for r in results:
        if r.status == "critical":
            summary["critical"] += 1
        elif r.status == "warning":
            summary["warning"] += 1
        elif r.status == "ok":
            summary["ok"] += 1
        else:  # skipped / error
            summary["skipped"] += 1
    return summary


async def run_audit(
    url: str,
    keywords: List[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    only: list[str] | None = None,
    gentle: bool = True,
) -> Dict[str, Any]:
    # Выбор проверок: непустой `only` — запускаем только указанные id
    if only:
        only_set = set(only)
        selected = [fn for fn in CHECKS if getattr(fn, "_check_meta", {}).get("id") in only_set]
    else:
        selected = list(CHECKS)
    selected_ids = [getattr(fn, "_check_meta", {}).get("id", "unknown") for fn in selected]

    # Create client
    client = httpx.AsyncClient(
        headers={"User-Agent": BROWSER_UA},
        http2=False,
        verify=True,
        transport=ThrottledTransport(
            transport,
            limit=2 if gentle else 6,
            paced_host=urlparse(url if "://" in url else "https://" + url).hostname if gentle else None,
            min_interval=GENTLE_INTERVAL,
        ),
        timeout=20.0,
    )

    ctx = AuditContext(url=url, keywords=keywords, client=client, gentle=gentle)

    # Антибот-заглушка делает все остальные проверки недостоверными — останавливаемся
    home = await ctx.home()
    marker = detect_challenge(home.text) if home is not None else None
    if marker:
        await client.aclose()
        finding = Finding(
            level="critical",
            text=f"Сайт отдаёт антибот-заглушку вместо контента (маркер: «{marker}»). "
                 "Аудит остановлен: результаты проверок были бы недостоверны. "
                 "Так же сайт видят и AI-краулеры с этого IP.",
            fix="Повторить проверку позже или с другого IP; добавить IP сканера в белый список WAF/Imunify/Cloudflare. "
                "Если заглушку получают и поисковые/AI-боты — ослабить правила антибот-защиты.",
            hours=1.0,
        )
        blocked = CheckResult(id="anti_bot_challenge", title="Антибот-защита сайта", category="Доступность",
                              status="critical", score=0, findings=[finding], raw={"marker": marker})
        return {
            "url": ctx.url, "base": ctx.base, "host": ctx.host, "overall_score": 0, "blocked": True,
            "checks": [blocked.to_dict()],
            "selected": ["anti_bot_challenge"],
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "summary": _summarize([blocked]),
            "plan": {"findings": [{"check_id": blocked.id, "check_title": blocked.title, "level": "critical",
                                   "text": finding.text, "fix": finding.fix, "hours": finding.hours}],
                     "total_hours": finding.hours},
        }
    semaphore = asyncio.Semaphore(8)

    async def run_one(fn: Callable[[AuditContext], Awaitable[CheckResult]]) -> CheckResult:
        async with semaphore:
            try:
                return normalize_check(await fn(ctx))
            except Exception as e:
                meta = getattr(fn, "_check_meta", {})
                return CheckResult(
                    id=meta.get("id", "unknown"),
                    title=meta.get("title", "unknown"),
                    category=meta.get("category", "unknown"),
                    status="error",
                    score=0,
                    findings=[Finding(level="critical", text=str(e), fix="")],
                    raw={"error": str(e)},
                )

    results = await asyncio.gather(*[run_one(fn) for fn in selected])

    await client.aclose()

    overall_score = _overall_score([(r.status, r.score) for r in results])

    # build plan
    plan_findings: List[Dict[str, Any]] = []
    level_order = {"critical": 0, "warning": 1, "info": 2}
    for r in results:
        for f in r.findings:
            if f.level in ("ok",):
                continue
            # include non-ok
            plan_findings.append(
                {
                    "check_id": r.id,
                    "check_title": r.title,
                    "level": f.level,
                    "text": f.text,
                    "fix": f.fix,
                    "hours": float(f.hours),
                }
            )
    plan_findings.sort(key=lambda x: (level_order.get(x["level"], 99), x["check_title"]))

    total_hours = round(sum(p["hours"] for p in plan_findings), 2)

    return {
        "url": ctx.url,
        "base": ctx.base,
        "host": ctx.host,
        "overall_score": overall_score,
        "checks": [r.to_dict() for r in results],
        "selected": selected_ids,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "summary": _summarize(results),
        "plan": {
            "findings": plan_findings,
            "total_hours": total_hours,
        },
    }


# Import checks so they auto-register (after `check` is defined)
import app.checks  # noqa: E402,F401
