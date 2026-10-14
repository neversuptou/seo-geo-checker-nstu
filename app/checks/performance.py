"""Проверки производительности.

Проверки:
- pagespeed — Google PageSpeed Insights (mobile + desktop): оценка, LCP, CLS,
  INP/TBT и топ-5 возможностей оптимизации.

Чистая логика разбора вынесена в функцию без сети `extract_psi_metrics`,
поэтому её можно покрывать юнит-тестами.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from app.core import AuditContext, CheckResult, Finding
from app.registry import check

CATEGORY = "Производительность"

PSI_ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"

# Метрики Lighthouse, которые выводим в отчёт.
_METRIC_AUDITS = [
    ("largest-contentful-paint", "LCP"),
    ("cumulative-layout-shift", "CLS"),
    ("interaction-to-next-paint", "INP"),
    ("experimental-interaction-to-next-paint", "INP"),
    ("total-blocking-time", "TBT"),
    ("first-contentful-paint", "FCP"),
    ("speed-index", "Speed Index"),
]


def extract_psi_metrics(data: Any) -> Dict[str, Any]:
    """Разобрать ответ PageSpeed Insights в плоскую структуру.

    Возвращает score (0..100), метрики и топ-5 возможностей оптимизации.
    Никогда не бросает исключений.
    """
    result: Dict[str, Any] = {
        "score": None,
        "lcp": None,
        "cls": None,
        "inp": None,
        "tbt": None,
        "fcp": None,
        "speed_index": None,
        "opportunities": [],
        "final_url": None,
    }
    if not isinstance(data, dict):
        return result

    lighthouse = data.get("lighthouseResult") or {}
    if not isinstance(lighthouse, dict):
        return result

    result["final_url"] = lighthouse.get("finalUrl") or lighthouse.get("requestedUrl")

    categories = lighthouse.get("categories") or {}
    perf = categories.get("performance") or {}
    score = perf.get("score")
    if isinstance(score, (int, float)):
        result["score"] = int(round(float(score) * 100))

    audits = lighthouse.get("audits") or {}

    def metric(audit_id: str) -> Optional[str]:
        audit = audits.get(audit_id)
        if not isinstance(audit, dict):
            return None
        return audit.get("displayValue")

    for audit_id, label in _METRIC_AUDITS:
        value = metric(audit_id)
        if value is None:
            continue
        key = {
            "LCP": "lcp",
            "CLS": "cls",
            "INP": "inp",
            "TBT": "tbt",
            "FCP": "fcp",
            "Speed Index": "speed_index",
        }.get(label)
        if key and result.get(key) is None:
            result[key] = value

    opportunities: List[Dict[str, Any]] = []
    for audit_id, audit in audits.items():
        if not isinstance(audit, dict):
            continue
        details = audit.get("details") or {}
        if not isinstance(details, dict) or details.get("type") != "opportunity":
            continue
        savings = details.get("overallSavingsMs")
        if not isinstance(savings, (int, float)) or savings <= 0:
            continue
        opportunities.append(
            {
                "id": audit_id,
                "title": audit.get("title") or audit_id,
                "savings_ms": int(savings),
                "display": audit.get("displayValue") or f"{int(savings)} мс",
            }
        )

    opportunities.sort(key=lambda item: item["savings_ms"], reverse=True)
    result["opportunities"] = opportunities[:5]
    return result


def _findings_from_metrics(
    parsed: Dict[str, Any], strategy: str
) -> tuple[List[Finding], str, int]:
    """Построить находки по метрикам одного прогона (mobile/desktop)."""
    label = "мобильная" if strategy == "mobile" else "десктопная"
    findings: List[Finding] = []
    status = "ok"
    score = 100

    psi_score = parsed.get("score")
    if psi_score is None:
        return findings, status, score

    score = psi_score
    if psi_score < 50:
        status = "critical"
        findings.append(
            Finding(
                level="critical",
                text=f"Оценка производительности ({label} версия) — {psi_score}/100, критически низкая",
                fix="Переработать загрузку ресурсов: сжать изображения, отложить JS, включить кеширование и CDN",
                hours=8.0,
            )
        )
    elif psi_score < 90:
        status = "warning"
        findings.append(
            Finding(
                level="warning",
                text=f"Оценка производительности ({label} версия) — {psi_score}/100, есть что улучшить",
                fix="Оптимизировать LCP и время блокировки: предзагрузка ключевых ресурсов, ленивая загрузка, минификация",
                hours=4.0,
            )
        )
    else:
        findings.append(
            Finding(level="ok", text=f"Оценка производительности ({label} версия) — {psi_score}/100", fix="")
        )

    lcp = parsed.get("lcp")
    if lcp:
        findings.append(
            Finding(
                level="info",
                text=f"LCP ({label}): {lcp}, CLS: {parsed.get('cls') or '—'}, "
                f"INP: {parsed.get('inp') or '—'}, TBT: {parsed.get('tbt') or '—'}",
                fix="",
            )
        )

    for opp in parsed.get("opportunities", []):
        findings.append(
            Finding(
                level="info",
                text=f"[{label}] {opp['title']}: экономия ~{opp['display']}",
                fix=f"Устранить проблему «{opp['title']}» по рекомендации Lighthouse",
                hours=1.0,
            )
        )

    return findings, status, score


async def _fetch_psi(ctx: AuditContext, strategy: str) -> Optional[Dict[str, Any]]:
    params = [f"url={quote(ctx.url, safe='')}", f"strategy={strategy}"]
    api_key = os.environ.get("PSI_API_KEY")
    if api_key:
        params.append(f"key={quote(api_key, safe='')}")
    url = f"{PSI_ENDPOINT}?{'&'.join(params)}"

    resp = await ctx.get(url, timeout=90.0)
    if resp is None or resp.status_code != 200:
        return None
    try:
        return resp.json()
    except Exception:
        return None


@check(id="pagespeed", title="PageSpeed Insights (mobile и desktop)", category=CATEGORY)
async def pagespeed(ctx: AuditContext) -> CheckResult:
    check_id = "pagespeed"
    title = "PageSpeed Insights (mobile и desktop)"

    mobile_raw, desktop_raw = await _fetch_psi(ctx, "mobile"), await _fetch_psi(ctx, "desktop")

    if mobile_raw is None and desktop_raw is None:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=[
                Finding(
                    level="info",
                    text="PageSpeed Insights недоступен (ошибка сети или исчерпана квота API) — проверка пропущена",
                    fix="Повторить позже или указать PSI_API_KEY для увеличения квоты",
                    hours=0.0,
                )
            ],
            raw={"error": "psi_unavailable_or_quota"},
        )

    findings: List[Finding] = []
    status = "ok"
    score = 100
    runs: Dict[str, Any] = {}

    for strategy, raw in (("mobile", mobile_raw), ("desktop", desktop_raw)):
        if raw is None:
            findings.append(
                Finding(
                    level="warning",
                    text=f"Не удалось получить данные PageSpeed для стратегии {strategy}",
                    fix="Повторить проверку позже",
                    hours=0.25,
                )
            )
            continue
        parsed = extract_psi_metrics(raw)
        runs[strategy] = parsed
        run_findings, run_status, run_score = _findings_from_metrics(parsed, strategy)
        findings.extend(run_findings)
        if run_status == "critical":
            status = "critical"
        elif run_status == "warning" and status == "ok":
            status = "warning"
        score = min(score, run_score)

    if not runs:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=findings
            or [Finding(level="info", text="Нет данных PageSpeed Insights", fix="", hours=0.0)],
            raw={"error": "no_psi_data"},
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={"strategies": list(runs.keys()), "runs": runs},
    )
