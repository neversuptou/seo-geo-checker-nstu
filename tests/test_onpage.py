from __future__ import annotations

import httpx
import pytest

from app.core import AuditContext
from app.registry import CHECKS
from app.checks.onpage import (
    analyze_headings,
    analyze_images,
    analyze_links,
    find_duplicates,
    h1_problem,
    headings,
    junk_heading_reason,
    links,
    meta_tags,
    parse_meta_tags,
    starts_fragment_like,
    summarize_w3c,
    w3c_validation,
)

# ---------------------------------------------------------------------------
# Fixtures / samples
# ---------------------------------------------------------------------------

HEADINGS_HTML = """
<html><body>
<h2>Второй уровень без H1</h2>
<p>текст</p>
<h4>Прыжок через уровень</h4>
<h1>Полезный заголовок страницы</h1>
<h1>второй лишний h1</h1>
<h3>hello</h3>
<h2>123</h2>
<h2>ab</h2>
<h2>Lorem ipsum dolor</h2>
</body></html>
"""

IMAGES_HTML = """
<html><body>
<img src="/a.png">
<img src="/b.png" alt="">
<img src="/c.png" alt="Логотип компании">
<img src="/d.png" role="presentation">
<img src="/e.png" aria-hidden="true">
<img src="/f.png" alt="   ">
<img src="/g.png" role="none" alt="">
</body></html>
"""

LINKS_HTML = """
<html><body>
<a href="/page">Внутренняя</a>
<a href="https://other.example/x" rel="nofollow">Внешняя</a>
<a href="https://other.example/y">Внешняя 2</a>
<a href="">Пусто</a>
<a href="#anchor"></a>
<a href="mailto:test@example.com">Почта</a>
</body></html>
"""

META_HTML = """
<html lang="ru"><head>
<title>Купить кофе в Москве с доставкой — интернет-магазин</title>
<meta charset="utf-8">
<meta name="description" content="Свежемолотый кофе из Бразилии и Эфиопии. Доставка по Москве за два часа, свежая обжарка каждую неделю и скидки постоянным клиентам.">
<meta name="keywords" content="кофе, купить кофе, доставка кофе">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="canonical" href="/catalog">
<link rel="shortcut icon" href="/favicon.ico">
</head><body></body></html>
"""


def _ctx(url: str, pages: dict[str, str], post_json: dict | None = None) -> AuditContext:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            if post_json is not None:
                return httpx.Response(200, json=post_json)
            return httpx.Response(200, json={"messages": []})
        path = request.url.path
        for key, body in pages.items():
            if path == key:
                return httpx.Response(
                    200,
                    content=body.encode("utf-8"),
                    headers={"content-type": "text/html; charset=utf-8"},
                )
        return httpx.Response(404, content=b"not found")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return AuditContext(url=url, client=client)


# ---------------------------------------------------------------------------
# Мусорные заголовки
# ---------------------------------------------------------------------------


def test_junk_heading_reason_detects_junk():
    assert junk_heading_reason("hello") is not None
    assert junk_heading_reason("Тест") is not None
    assert junk_heading_reason("123") is not None
    assert junk_heading_reason("ab") is not None
    assert junk_heading_reason("") is not None
    assert junk_heading_reason("Lorem ipsum dolor") is not None
    assert junk_heading_reason("Полезный заголовок страницы") is None


def test_starts_fragment_like():
    assert starts_fragment_like("в Москве кофе") is True
    assert starts_fragment_like("and more text") is True
    assert starts_fragment_like("Полезный заголовок") is False
    assert starts_fragment_like("") is True


def test_h1_problem():
    assert h1_problem("") is not None
    assert h1_problem("hello") is not None
    assert h1_problem("в Москве кофе") is not None
    assert h1_problem("Купить кофе в Москве") is None


def test_analyze_headings_counts_skips_junk():
    data = analyze_headings(HEADINGS_HTML)
    assert data["h1_count"] == 2
    assert data["has_skipped_levels"] is True

    # H2 -> H4 является пропуском уровня
    assert any(s["from"] == 2 and s["to"] == 4 for s in data["skipped"])

    junk_texts = {j["text"] for j in data["junk"]}
    assert "hello" in junk_texts
    assert "123" in junk_texts
    assert "ab" in junk_texts
    assert "Lorem ipsum dolor" in junk_texts
    assert "Полезный заголовок страницы" not in junk_texts


# ---------------------------------------------------------------------------
# Дубли title / description / H1
# ---------------------------------------------------------------------------


def test_find_duplicates_exact():
    dups = find_duplicates("Купить кофе", "Купить кофе", "Другое")
    assert any(d["exact"] and d["ratio"] == 1.0 for d in dups)


def test_find_duplicates_near():
    dups = find_duplicates("Купить кофе онлайн", "Купить кофе онлайн!", "")
    assert dups and dups[0]["ratio"] > 0.9
    assert dups[0]["exact"] is False


def test_find_duplicates_none():
    assert find_duplicates("Купить кофе", "Доставка чая по России", "О компании") == []
    assert find_duplicates("", "", "") == []


# ---------------------------------------------------------------------------
# Alt изображений
# ---------------------------------------------------------------------------


def test_analyze_images_alt_counts():
    data = analyze_images(IMAGES_HTML, "https://x.example")
    assert data["total"] == 7
    # missing: /a.png
    assert data["missing_alt"] == 1
    # empty: /b.png и /f.png (role=presentation|none|aria-hidden исключены)
    assert data["empty_alt"] == 2

    joined = " ".join(data["no_alt"])
    assert "a.png" in joined
    assert "b.png" in joined
    assert "f.png" in joined
    assert "d.png" not in joined
    assert "e.png" not in joined
    assert "g.png" not in joined


def test_analyze_images_no_images():
    data = analyze_images("<html><body><p>текст</p></body></html>")
    assert data == {"total": 0, "missing_alt": 0, "empty_alt": 0, "no_alt": []}


# ---------------------------------------------------------------------------
# Метатеги
# ---------------------------------------------------------------------------


def test_parse_meta_tags():
    meta = parse_meta_tags(META_HTML, "https://shop.example")
    assert meta["title"].startswith("Купить кофе")
    assert meta["description"].startswith("Свежемолотый")
    assert meta["keywords"] == "кофе, купить кофе, доставка кофе"
    assert meta["lang"] == "ru"
    assert meta["viewport"].startswith("width=device-width")
    assert meta["charset"] == "utf-8"
    assert meta["canonical"] == "https://shop.example/catalog"
    assert meta["canonical_is_absolute"] is True
    assert meta["favicon"] == "https://shop.example/favicon.ico"
    assert meta["favicon_source"] == "link"


# ---------------------------------------------------------------------------
# Ссылки
# ---------------------------------------------------------------------------


def test_analyze_links_counts():
    data = analyze_links(LINKS_HTML, "https://example.com")
    assert data["total"] == 6
    assert data["internal"] == 1
    assert data["external"] == 2
    assert data["nofollow"] == 1
    assert data["external_domains"] == {"other.example": 2}
    assert len(data["empty_href"]) == 1
    assert len(data["empty_text"]) == 1
    assert data["placeholder"] == ["#anchor"]
    assert "https://example.com/page" in data["unique_urls"]
    assert "https://other.example/x" in data["unique_urls"]


# ---------------------------------------------------------------------------
# W3C
# ---------------------------------------------------------------------------


def test_summarize_w3c_groups_messages():
    data = {
        "messages": [
            {"type": "error", "message": "Element X not allowed"},
            {"type": "error", "message": "Element X not allowed"},
            {"type": "warning", "message": "Trailing slash"},
            {"type": "info", "message": "Просто информация"},
        ]
    }
    summary = summarize_w3c(data, top=8)
    assert summary["errors_count"] == 2
    assert summary["warnings_count"] == 1
    assert summary["info_count"] == 1
    assert summary["top_errors"][0] == {"message": "Element X not allowed", "count": 2}


def test_summarize_w3c_handles_empty():
    summary = summarize_w3c({})
    assert summary["errors_count"] == 0
    assert summary["total"] == 0
    assert summarize_w3c(None)["errors_count"] == 0


# ---------------------------------------------------------------------------
# Проверки (MockTransport, без реальной сети)
# ---------------------------------------------------------------------------


def test_all_six_checks_registered():
    ids = {getattr(fn, "_check_meta", {}).get("id") for fn in CHECKS}
    expected = {
        "meta_tags",
        "headings",
        "title_desc_h1_duplicates",
        "images_alt",
        "links",
        "w3c_validation",
    }
    assert expected <= ids


@pytest.mark.asyncio
async def test_headings_check_critical_without_h1():
    ctx = _ctx("https://example.com", {"/": "<html><body><h2>Без H1</h2></body></html>"})
    res = await headings(ctx)
    assert res.status == "critical"
    assert res.raw["h1_count"] == 0
    assert any(f.level == "critical" for f in res.findings)


@pytest.mark.asyncio
async def test_links_check_reports_broken():
    html = '<html><body><a href="/broken">Битая</a><a href="/ok">Ок</a></body></html>'
    ctx = _ctx("https://example.com", {"/": html, "/ok": "<html></html>"})
    res = await links(ctx)
    assert res.raw["checked"] == 2
    assert len(res.raw["broken"]) == 1
    assert res.status in ("warning", "critical")


@pytest.mark.asyncio
async def test_meta_tags_check_ok():
    ctx = _ctx("https://shop.example", {"/": META_HTML})
    res = await meta_tags(ctx)
    assert res.status == "ok"
    assert res.score == 100
    assert res.raw["charset"] == "utf-8"
    assert res.raw["favicon_source"] == "link"


@pytest.mark.asyncio
async def test_meta_tags_check_reports_missing():
    ctx = _ctx("https://shop.example", {"/": "<html><head></head><body>пусто</body></html>"})
    res = await meta_tags(ctx)
    assert res.status == "critical"
    assert any(f.level == "critical" for f in res.findings)


@pytest.mark.asyncio
async def test_w3c_validation_info_below_threshold():
    ctx = _ctx(
        "https://example.com",
        {"/": "<html><body>x</body></html>"},
        post_json={
            "messages": [
                {"type": "error", "message": "Element X not allowed"},
                {"type": "error", "message": "Element X not allowed"},
                {"type": "warning", "message": "Trailing slash"},
            ]
        },
    )
    res = await w3c_validation(ctx)
    assert res.status == "ok"
    assert res.raw["errors"] == 2
    assert res.raw["top_errors"][0]["count"] == 2
    assert any(f.level == "info" for f in res.findings)


@pytest.mark.asyncio
async def test_w3c_validation_warning_above_threshold():
    messages = [{"type": "error", "message": f"Ошибка {i % 3}"} for i in range(51)]
    ctx = _ctx("https://example.com", {"/": "<html><body>x</body></html>"}, post_json={"messages": messages})
    res = await w3c_validation(ctx)
    assert res.status == "warning"
    assert res.raw["errors"] == 51
    assert any(f.level == "warning" for f in res.findings)
