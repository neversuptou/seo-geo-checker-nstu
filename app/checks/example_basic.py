from __future__ import annotations

from app.core import AuditContext, CheckResult, Finding
from app.registry import check


@check(id="http_status", title="HTTP-статус главной страницы", category="Технический SEO")
async def http_status(ctx: AuditContext) -> CheckResult:
    resp = await ctx.home()
    if resp is None:
        return CheckResult(
            id="http_status",
            title="HTTP-статус главной страницы",
            category="Технический SEO",
            status="error",
            score=0,
            findings=[Finding(level="critical", text="Не удалось получить ответ от сервера", fix="Проверить доступность сайта")],
            raw={"status": None, "url": ctx.url, "history": []},
        )

    status = resp.status_code
    final_url = str(resp.url)
    history = []
    for h in resp.history:
        history.append({"status": h.status_code, "url": str(h.url)})

    redirect_count = len(history)

    findings: list[Finding] = []
    if status == 200:
        status_res = "ok"
        score = 100
        findings.append(Finding(level="ok", text=f"Статус {status}, редиректов: {redirect_count}", fix=""))
    elif 200 < status < 300:
        status_res = "warning"
        score = 80
        findings.append(Finding(level="warning", text=f"Неожиданный статус {status}", fix="Проверить редиректы"))
    elif 300 <= status < 400:
        status_res = "warning"
        score = 60
        findings.append(Finding(level="warning", text=f"Редирект {status} (итоговый: {final_url})", fix="Упростить цепочку редиректов"))
    elif 400 <= status < 500:
        status_res = "critical"
        score = 0
        findings.append(Finding(level="critical", text=f"Ошибка клиента {status}", fix="Исправить страницу"))
    else:
        status_res = "critical"
        score = 0
        findings.append(Finding(level="critical", text=f"Ошибка сервера {status}", fix="Проверить сервер"))

    return CheckResult(
        id="http_status",
        title="HTTP-статус главной страницы",
        category="Технический SEO",
        status=status_res,
        score=score,
        findings=findings,
        raw={"status": status, "url": final_url, "redirect_count": redirect_count, "history": history},
    )
