"""Tests for app/checks/eeat.py and app/checks/images.py (no real network)."""
from __future__ import annotations

import httpx
import pytest

from app.core import AuditContext
from app.checks.eeat import (
    analyze_authorship,
    classify_trust_links,
    collect_links,
    contact_signals,
    detect_contact_signals,
    find_section_link,
    looks_like_post_url,
    trust_pages,
)
from app.checks.images import (
    image_issues,
    images_optimization,
    parse_images,
)

# ---------------------------------------------------------------------------
# Fixtures / samples
# ---------------------------------------------------------------------------

RU_TRUST_HTML = """
<html><body>
<header>
  <nav>
    <a href="/o-nas">О компании</a>
    <a href="/contacts">Контакты</a>
  </nav>
</header>
<footer>
  <a href="/dostavka-i-oplata">Доставка и оплата</a>
  <a href="/vozvrat">Возврат и обмен</a>
  <a href="/politika-konfidencialnosti">Политика конфиденциальности</a>
  <a href="/oferta">Публичная оферта</a>
  <a href="/faq">Частые вопросы</a>
</footer>
<a href="mailto:info@example.ru">Написать нам</a>
<a href="tel:+74951234567">Позвонить</a>
</body></html>
"""

EN_TRUST_HTML = """
<html><body>
<a href="/about-us">About us</a>
<a href="/contact">Contact us</a>
<a href="/shipping">Shipping &amp; Delivery</a>
<a href="/returns">Returns &amp; Refunds</a>
<a href="/privacy-policy">Privacy Policy</a>
<a href="/terms">Terms of Service</a>
<a href="/faq">FAQ</a>
</body></html>
"""

CONTACT_HTML = """
<html><body>
<div class="contacts">
  <a href="tel:+7 (495) 123-45-67">+7 (495) 123-45-67</a>
  <a href="mailto:info@shop.ru">info@shop.ru</a>
  <p>г. Москва, ул. Ленина, д. 1, офис 5, индекс 101000</p>
  <p>ООО «Ромашка», ИНН 7701234567, ОГРН 1027700132195, КПП 770101001</p>
  <a href="https://t.me/romashka">Telegram</a>
</div>
<iframe src="https://yandex.ru/map-widget/v1/?ll=37.6,55.7"></iframe>
</body></html>
"""

IMAGES_HTML = """
<html><body>
<picture>
  <source type="image/webp" srcset="/img/hero.webp 1x, /img/hero@2x.webp 2x">
  <source type="image/avif" srcset="/img/hero.avif 1x">
  <img src="/img/hero.jpg" srcset="/img/hero.jpg 1x, /img/hero@2x.jpg 2x" width="800" height="600" alt="Герой">
</picture>
<img data-src="/img/lazy.jpg" src="/img/placeholder.gif" loading="lazy" alt="Ленивая">
<img src="/img/icon.svg" decoding="async" width="24" height="24" alt="Иконка">
</body></html>
"""


def _ctx(url: str, pages: dict[str, str], head_sizes: dict[str, int] | None = None) -> AuditContext:
    head_sizes = head_sizes or {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "HEAD":
            size = head_sizes.get(path)
            if size is None:
                return httpx.Response(404)
            return httpx.Response(
                200,
                headers={"content-type": "image/jpeg", "content-length": str(size)},
            )
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


def _words(count: int = 100) -> str:
    return " ".join(["слово"] * count)


# ---------------------------------------------------------------------------
# classify_trust_links
# ---------------------------------------------------------------------------


def test_classify_trust_links_russian():
    links = collect_links(RU_TRUST_HTML, "https://shop.example")
    classified = classify_trust_links(links)

    assert classified["about"] == "/o-nas"
    assert classified["contacts"] == "/contacts"
    assert classified["delivery"] == "/dostavka-i-oplata"
    assert classified["returns"] == "/vozvrat"
    assert classified["privacy"] == "/politika-konfidencialnosti"
    assert classified["terms"] == "/oferta"
    assert classified["faq"] == "/faq"
    # mailto/tel не являются страницами доверия
    assert all(not v.lower().startswith(("mailto:", "tel:")) for v in classified.values())


def test_classify_trust_links_english():
    links = collect_links(EN_TRUST_HTML, "https://shop.example")
    classified = classify_trust_links(links)

    assert classified["about"] == "/about-us"
    assert classified["contacts"] == "/contact"
    assert classified["delivery"] == "/shipping"
    assert classified["returns"] == "/returns"
    assert classified["privacy"] == "/privacy-policy"
    assert classified["terms"] == "/terms"
    assert classified["faq"] == "/faq"


def test_classify_trust_links_keeps_first_and_ignores_placeholders():
    classified = classify_trust_links(
        [
            ("/company", "О компании"),
            ("/company-2", "О нас"),
            ("#", "Контакты"),
            ("javascript:void(0)", "Контакты"),
        ]
    )
    assert classified["about"] == "/company"
    assert "contacts" not in classified


# ---------------------------------------------------------------------------
# contact detection
# ---------------------------------------------------------------------------


def test_detect_contact_signals_phone_email_legal():
    signals = detect_contact_signals(CONTACT_HTML)

    assert signals["phone"] is True
    assert any("123-45-67" in p for p in signals["phones"])
    assert signals["email"] is True
    assert "info@shop.ru" in signals["emails"]
    assert signals["address"] is True
    assert signals["legal"] is True
    assert any("7701234567" in d for d in signals["legal_details"])
    assert signals["social"] is True
    assert "telegram" in signals["social_links"]
    assert signals["map"] is True


def test_detect_contact_signals_empty_html():
    signals = detect_contact_signals("<html><body>нет контактов</body></html>")
    assert signals["phone"] is False
    assert signals["email"] is False
    assert signals["address"] is False
    assert signals["legal"] is False


# ---------------------------------------------------------------------------
# authorship helpers
# ---------------------------------------------------------------------------


def test_find_section_link_and_post_url():
    links = collect_links(
        '<html><body><a href="/blog">Блог</a><a href="/about">О нас</a></body></html>',
        "https://blog.example",
    )
    assert find_section_link(links, ("blog", "блог")) == "/blog"

    assert looks_like_post_url("https://blog.example/blog/kak-vybrat-kofe", "/blog") is True
    assert looks_like_post_url("https://blog.example/blog/tag/coffee", "/blog") is False
    assert looks_like_post_url("https://blog.example/blog/", "/blog") is False


def test_analyze_authorship():
    html = """
    <html><head>
      <meta name="author" content="Иван Петров">
      <meta property="article:published_time" content="2024-03-01">
      <meta property="article:modified_time" content="2024-04-01">
    </head><body>
      <a rel="author" href="/author/ivan">Иван Петров</a>
    </body></html>
    """
    data = analyze_authorship(html)
    assert data["author"] == "Иван Петров"
    assert data["published"] == "2024-03-01"
    assert data["modified"] == "2024-04-01"
    assert data["author_bio"] is True


# ---------------------------------------------------------------------------
# parse_images
# ---------------------------------------------------------------------------


def test_parse_images_srcset_data_src_picture():
    images = parse_images(IMAGES_HTML, "https://shop.example")

    assert len(images) == 3

    hero = images[0]
    assert hero["src"] == "https://shop.example/img/hero.jpg"
    assert "2x" in hero["srcset"]
    assert any(s["type"] == "image/webp" for s in hero["sources"])
    assert any(s["type"] == "image/avif" for s in hero["sources"])

    lazy = images[1]
    # data-src имеет приоритет над src-заглушкой
    assert lazy["src"] == "https://shop.example/img/lazy.jpg"
    assert lazy["data_src"] == "https://shop.example/img/lazy.jpg"
    assert lazy["loading"] == "lazy"

    icon = images[2]
    assert icon["src"] == "https://shop.example/img/icon.svg"
    assert icon["decoding"] == "async"
    assert icon["width"] == "24" and icon["height"] == "24"


# ---------------------------------------------------------------------------
# image_issues
# ---------------------------------------------------------------------------


def test_image_issues_missing_dimensions_lazy_first_and_heavy():
    images = [
        {"src": "a.jpg", "width": "", "height": "", "loading": "lazy", "size": 600 * 1024, "content_type": "image/jpeg"},
        {"src": "b.jpg", "width": "100", "height": "100", "loading": "lazy", "size": 250 * 1024, "content_type": "image/jpeg"},
        {"src": "c.webp", "width": "100", "height": "100", "loading": "", "size": 10 * 1024, "content_type": "image/webp"},
        {"src": "d.png", "width": "100", "height": "100", "loading": "", "size": 50 * 1024, "content_type": "image/png"},
        {"src": "e.jpg", "width": "100", "height": "100", "loading": "", "size": 50 * 1024, "content_type": "image/jpeg"},
    ]
    issues = image_issues(images)

    assert issues["lazy_lcp"] == "a.jpg"
    assert "a.jpg" in issues["missing_dimensions"]
    assert issues["missing_dimensions_count"] == 1

    assert len(issues["heavy_critical"]) == 1
    assert issues["heavy_critical"][0]["url"] == "a.jpg"
    assert len(issues["heavy_warning"]) == 1
    assert issues["heavy_warning"][0]["url"] == "b.jpg"

    # изображения начиная с 4-го (индекс >= 3) без lazy
    assert "d.png" in issues["not_lazy"]
    assert "e.jpg" in issues["not_lazy"]

    # legacy: a,b,d,e без webp/avif-альтернативы
    assert issues["legacy_share"] > 0.5
    assert issues["total_weight"] == (600 + 250 + 10 + 50 + 50) * 1024


def test_image_issues_modern_format_is_not_legacy():
    images = [
        {"src": "a.webp", "width": "10", "height": "10", "loading": "lazy", "size": 10, "content_type": "image/webp"},
        {"src": "b.jpg", "width": "10", "height": "10", "loading": "lazy", "size": 10, "content_type": "image/jpeg",
         "sources": [{"type": "image/webp", "srcset": "/b.webp 1x"}]},
    ]
    issues = image_issues(images)
    assert issues["legacy"] == []


# ---------------------------------------------------------------------------
# Async checks (MockTransport, no real network)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trust_pages_shop_missing_delivery_returns_terms():
    home = (
        '<html><body><div class="woocommerce">магазин</div>'
        '<a href="/product/kruzhka/">Кружка</a>'
        '<a href="/o-nas">О компании</a>'
        '<a href="/contacts">Контакты</a>'
        '<a href="/privacy">Политика конфиденциальности</a>'
        "</body></html>"
    )
    pages = {
        "/": home,
        "/o-nas": f"<html><body><p>{_words()}</p></body></html>",
        "/contacts": f"<html><body><p>{_words()}</p></body></html>",
        "/privacy": f"<html><body><p>{_words()}</p></body></html>",
    }
    ctx = _ctx("https://shop.example", pages)
    res = await trust_pages(ctx)

    assert res.status == "critical"
    assert res.raw["is_shop"] is True
    assert set(res.raw["missing_shop"]) == {"delivery", "returns", "terms"}
    assert "about" in res.raw["present"]
    assert any(f.level == "critical" for f in res.findings)


@pytest.mark.asyncio
async def test_trust_pages_all_present_is_ok():
    home = (
        "<html><body>"
        '<a href="/about">О компании</a>'
        '<a href="/contacts">Контакты</a>'
        '<a href="/privacy">Политика конфиденциальности</a>'
        "</body></html>"
    )
    posts = f"<html><body><p>{_words()}</p></body></html>"
    ctx = _ctx("https://site.example", {"/": home, "/about": posts, "/contacts": posts, "/privacy": posts})
    res = await trust_pages(ctx)

    assert res.status == "ok"
    assert set(res.raw["missing_required"]) == set()


@pytest.mark.asyncio
async def test_contact_signals_check_uses_contacts_page():
    home = '<html><body><a href="/contacts">Контакты</a></body></html>'
    ctx = _ctx(
        "https://site.example",
        {"/": home, "/contacts": CONTACT_HTML},
    )
    res = await contact_signals(ctx)

    assert res.raw["source"].endswith("/contacts")
    assert res.raw["phone"] is True
    assert res.status in ("ok", "warning")


@pytest.mark.asyncio
async def test_images_optimization_detects_heavy():
    home = (
        "<html><body>"
        '<img src="/img/heavy.jpg" width="100" height="100" alt="Тяжёлая">'
        '<img src="/img/ok.jpg" width="100" height="100" alt="Норм">'
        "</body></html>"
    )
    ctx = _ctx(
        "https://shop.example",
        {"/": home},
        head_sizes={"/img/heavy.jpg": 700 * 1024, "/img/ok.jpg": 50 * 1024},
    )
    res = await images_optimization(ctx)

    assert res.status == "critical"
    assert len(res.raw["heavy_critical"]) == 1
    assert res.raw["heavy_critical"][0]["url"].endswith("/img/heavy.jpg")
