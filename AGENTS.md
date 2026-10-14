# AGENTS.md

Инструкции для ИИ-агентов (Claude Code, OpenCode, Codex и др.), которые работают с этим репозиторием.

## Что это

Сервис SEO/GEO-аудита сайтов: 56 проверок (технический SEO, on-page, структурированные данные,
краулинг, E-E-A-T, изображения, инфраструктура, готовность к ИИ-поиску), веб-интерфейс,
клиентский PDF-отчёт и MCP-коннектор. Платные API и LLM не используются — проверки работают кодом.

## Стек

Python 3.12, FastAPI, httpx (async), selectolax (`from selectolax.lexbor import LexborHTMLParser`),
dnspython, Jinja2, WeasyPrint (PDF), SQLite, `mcp==1.28.1`, pytest + pytest-asyncio.

## Структура

| Путь | Что там |
|---|---|
| `app/core.py` | `AuditContext` (общий HTTP-клиент с кэшем), `CheckResult`, `Finding`, `ThrottledTransport` (лимит запросов, бережный режим) |
| `app/registry.py` | декоратор `@check`, `run_audit`, детектор антибот-заглушки |
| `app/checks/*.py` | проверки; любой модуль в папке регистрируется автоматически |
| `app/main.py` | FastAPI: веб, API, Markdown/PDF-экспорт, монтирование MCP |
| `app/mcp_server.py` | MCP-инструменты (`run_audit`, `get_report`, `compare_sites` и др.) |
| `app/templates/index.html` | интерфейс (стиль EvApps «Фин») |
| `app/templates/report_pdf.html` | клиентский PDF: только проблемы, без часов |
| `tests/` | тесты без сети (httpx.MockTransport и HTML-фикстуры) |

## Команды

```bash
pip install -r requirements.txt
python -m pytest -q
python -m uvicorn app.main:app --port 8077
docker compose up -d --build
```

WeasyPrint на Windows без Pango не работает — PDF-тест там пропускается, в Docker всё есть.

## Как добавить проверку

1. Новый модуль в `app/checks/` или функция в подходящем существующем.
2. Сигнатура: `@check(id=..., title=..., category=...)` над `async def fn(ctx: AuditContext) -> CheckResult`.
3. HTTP — только через `ctx.get()` / `ctx.home()`: они кэшируют ответы и идут через лимитирующий транспорт. Свой клиент не создавать.
4. Разбор HTML/текста — в отдельных чистых функциях, чтобы тестировать без сети.
5. Никогда не бросать исключение из-за отсутствия данных — вернуть `Finding`.
6. Каждая не-ok находка: понятный текст на русском, конкретный `fix` и реалистичные `hours` (часы видны только во внутреннем плане, не в PDF).
7. Тест в `tests/` на фикстурах, затем `python -m pytest -q`.

## Правила

- Весь текст для пользователя — на русском.
- Клиентский PDF показывает только проблемы: без оценки часов, без разделов «в порядке» и «не проверено».
- Бережный режим (по умолчанию) не ослаблять: без него хостинги с Imunify/Cloudflare блокируют IP сервера.
- Признак интернет-магазина — только явные маркеры (корзина, WooCommerce/Shopify, разметка Product/Offer), не ссылки вида `/product/`.
- `mcp` закреплён на 1.28.1: в 2.x `FastMCP` переименован, сервис не стартует.
- Секреты (`MCP_TOKEN`, `PSI_API_KEY`) — только в `.env`, который не коммитится.
- В коммитах, PR и документации не указывать ИИ-инструменты как авторов (никаких `Co-Authored-By`, «Generated with»).
