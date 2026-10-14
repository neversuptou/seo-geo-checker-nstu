# SEO/GEO Website Audit Service

Локальный сервис для аудита SEO/GEO сайтов на Python.

## Установка

```bash
pip install -r requirements.txt
```

## Запуск

```bash
uvicorn app.main:app --port 8077
```

После запуска откройте [http://localhost:8077](http://localhost:8077) в браузере.

## Как добавить новый чек

1. Создайте новый модуль в папке `app/checks/`, например `app/checks/robots.py`
2. Импортируйте декоратор и необходимые классы:

```python
from app.core import AuditContext, CheckResult, Finding
from app.registry import check
```

3. Создайте асинхронную функцию с декоратором `@check(id="robots", title="Проверка robots.txt", category="Технический SEO")`:

```python
@check(id="robots", title="Проверка robots.txt", category="Технический SEO")
async def robots(ctx: AuditContext) -> CheckResult:
    resp = await ctx.get(f"{ctx.base}/robots.txt")
    if resp is None:
        return CheckResult(
            id="robots",
            title="Проверка robots.txt",
            category="Технический SEO",
            status="error",
            score=0,
            findings=[Finding(level="critical", text="robots.txt недоступен", fix="Создать robots.txt")],
            raw={},
        )
    return CheckResult(
        id="robots",
        title="Проверка robots.txt",
        category="Технический SEO",
        status="ok",
        score=100,
        findings=[Finding(level="ok", text="robots.txt доступен")],
        raw={"status": resp.status_code},
    )
```

4. Модуль автоматически зарегистрируется при импорте `app.checks` (благодаря `pkgutil.iter_modules`).
5. Запустите аудит — новый чек будет выполнен параллельно с остальными.

## Тестирование

```bash
python -m pytest -q
```

## Структура данных

- `Finding(level, text, fix, hours)` — проблема с уровнем (critical/warning/info/ok), описанием, рекомендацией и трудозатратами
- `CheckResult` — результат отдельной проверки с итоговым статусом, баллом 0-100 и списком находок
- `AuditContext` — контекст аудита с нормализованным URL, общим `httpx.AsyncClient` и кешированием запросов

## Особенности

- Все проверки запускаются конкурентно с ограничением `asyncio.Semaphore(8)`
- Исключения в проверках автоматически оборачиваются в `CheckResult` со статусом `error`
- Сохранение результатов аудита в SQLite (`data/audits.db`)
- Экспорт отчёта в Markdown
- Адаптивный UI с поддержкой светлой/тёмной темы
