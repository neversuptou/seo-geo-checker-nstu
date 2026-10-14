from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, List, Optional, Awaitable

import httpx

from app.core import AuditContext, CheckResult, Finding, BROWSER_UA, ThrottledTransport

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


async def run_audit(
    url: str,
    keywords: List[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Dict[str, Any]:
    # Create client
    client = httpx.AsyncClient(
        headers={"User-Agent": BROWSER_UA},
        http2=False,
        verify=True,
        transport=ThrottledTransport(transport),
        timeout=20.0,
    )

    ctx = AuditContext(url=url, keywords=keywords, client=client)
    semaphore = asyncio.Semaphore(8)

    async def run_one(fn: Callable[[AuditContext], Awaitable[CheckResult]]) -> CheckResult:
        async with semaphore:
            try:
                res = await fn(ctx)
                return res
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

    results = await asyncio.gather(*[run_one(fn) for fn in CHECKS])

    await client.aclose()

    # compute overall score
    scores = []
    for r in results:
        if r.status in ("skipped", "error"):
            continue
        scores.append(r.score)
    if scores:
        overall_score = int(round(sum(scores) / len(scores)))
    else:
        overall_score = 0

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
        "plan": {
            "findings": plan_findings,
            "total_hours": total_hours,
        },
    }


# Import checks so they auto-register (after `check` is defined)
import app.checks  # noqa: E402,F401
