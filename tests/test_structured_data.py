from __future__ import annotations

import json

import httpx
import pytest

from app.core import AuditContext
from app.checks.structured_data import (
    detect_shop,
    ecommerce_product_schema,
    entity_types,
    extract_jsonld,
    find_product_links,
    jsonld,
    looks_like_product_url,
    microdata_og_twitter,
    parse_meta,
    parse_sitemap_locations,
    product_offer_issues,
    validate_entity,
)

# ---------------------------------------------------------------------------
# Fixtures / samples
# ---------------------------------------------------------------------------

VALID_GRAPH_HTML = """
<html><head>
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      "name": "ООО Ромашка",
      "url": "https://shop.example",
      "logo": "https://shop.example/logo.png"
    },
    {
      "@type": "WebSite",
      "name": "Ромашка",
      "url": "https://shop.example"
    },
    {
      "@type": "Product",
      "name": "Кружка",
      "image": "https://shop.example/mug.png",
      "offers": {
        "@type": "Offer",
        "price": "499",
        "priceCurrency": "RUB",
        "availability": "https://schema.org/InStock"
      }
    }
  ]
}
</script>
</head><body>hello</body></html>
"""

BROKEN_JSON_HTML = """
<html><head>
<script type="application/ld+json">{ "name": "сломанный",, }</script>
<script type="application/ld+json">{ "@type": "WebSite", "name": "Ок", "url": "https://x.example" }</script>
</head></html>
"""

PRODUCT_NO_OFFERS_HTML = """
<html><head>
<script type="application/ld+json">
{ "@type": "Product", "name": "Кружка", "image": "https://shop.example/mug.png" }
</script>
</head></html>
"""

TOP_LEVEL_LIST_HTML = """
<html><head><script type="application/ld+json">
[
  {"@type": "WebSite", "name": "A", "url": "https://a.example"},
  {"@type": "Organization", "name": "B", "url": "https://b.example", "logo": "https://b.example/l.png"}
]
</script></head></html>
"""

META_HTML = """
<html><head>
<meta property="og:title" content="Заголовок">
<meta property="og:description" content="Описание">
<meta property="og:image" content="https://shop.example/og.png">
<meta property="og:url" content="https://shop.example">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
</head><body>
<div itemscope itemtype="https://schema.org/Product"></div>
<span itemscope itemtype="https://schema.org/Offer"></span>
<span itemscope></span>
</body></html>
"""

PRODUCT_LINKS_HTML = """
<html><body>
<a href="/product/kruzhka/">Товар</a>
<a href="/products/table/">Товар 2</a>
<a href="/catalog/">Каталог</a>
<a href="/catalog/12345/">Товар 3</a>
<a href="/about">О нас</a>
</body></html>
"""

SHOP_HTML = '<html><body><div class="woocommerce"></div><form class="cart"><button>В корзину</button></form></body></html>'


def _ctx(url: str, pages: dict[str, str]) -> AuditContext:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for key, body in pages.items():
            if path == key:
                return httpx.Response(200, content=body.encode("utf-8"), headers={"content-type": "text/html; charset=utf-8"})
        return httpx.Response(404, content=b"not found")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return AuditContext(url=url, client=client)


# ---------------------------------------------------------------------------
# extract_jsonld
# ---------------------------------------------------------------------------


def test_extract_jsonld_flattens_graph():
    entities, errors = extract_jsonld(VALID_GRAPH_HTML)
    assert errors == []
    types = [t for e in entities for t in entity_types(e)]
    assert "Organization" in types
    assert "WebSite" in types
    assert "Product" in types
    # nested offer is not flattened to top level
    assert all("@graph" not in e for e in entities)


def test_extract_jsonld_flattens_top_level_list():
    entities, errors = extract_jsonld(TOP_LEVEL_LIST_HTML)
    assert errors == []
    assert len(entities) == 2
    assert entities[1]["@type"] == "Organization"


def test_extract_jsonld_broken_json_is_reported_but_others_survive():
    entities, errors = extract_jsonld(BROKEN_JSON_HTML)
    assert len(errors) == 1
    assert "JSON" in errors[0]
    assert len(entities) == 1
    assert entities[0]["@type"] == "WebSite"


def test_extract_jsonld_empty_html():
    entities, errors = extract_jsonld("")
    assert entities == []
    assert errors == []


# ---------------------------------------------------------------------------
# validate_entity
# ---------------------------------------------------------------------------


def test_validate_entity_valid_product():
    entities, _ = extract_jsonld(VALID_GRAPH_HTML)
    product = next(e for e in entities if e["@type"] == "Product")
    assert validate_entity(product) == []


def test_validate_entity_product_missing_offers():
    entities, _ = extract_jsonld(PRODUCT_NO_OFFERS_HTML)
    issues = validate_entity(entities[0])
    assert any("offers" in i for i in issues)


def test_validate_entity_offer_missing_currency_and_availability():
    offer = {"@type": "Offer", "price": "100"}
    issues = validate_entity(offer)
    assert any("priceCurrency" in i for i in issues)
    assert any("availability" in i for i in issues)
    assert not any(i.endswith("price") for i in issues)


def test_validate_entity_article_requires_author():
    article = {"@type": "BlogPosting", "headline": "H", "datePublished": "2024-01-01"}
    issues = validate_entity(article)
    assert any("author" in i for i in issues)


def test_validate_entity_faqpage_and_breadcrumbs():
    faq = {
        "@type": "FAQPage",
        "mainEntity": [{"@type": "Question", "name": "Вопрос?"}],
    }
    assert any("acceptedAnswer" in i for i in validate_entity(faq))

    crumbs = {
        "@type": "BreadcrumbList",
        "itemListElement": [{"@type": "ListItem", "position": 1, "name": "Главная"}],
    }
    assert any("item" in i for i in validate_entity(crumbs))


def test_validate_entity_organization_and_localbusiness():
    assert validate_entity({"@type": "Organization", "name": "A"})
    assert validate_entity(
        {"@type": "LocalBusiness", "name": "A", "address": "ул. Ленина 1", "telephone": "+70000000000"}
    ) == []


def test_validate_entity_ignores_unknown_types():
    assert validate_entity({"@type": "Thing", "name": "x"}) == []


# ---------------------------------------------------------------------------
# product_offer_issues
# ---------------------------------------------------------------------------


def test_product_offer_issues_none():
    entities, _ = extract_jsonld(VALID_GRAPH_HTML)
    assert product_offer_issues(entities) == []


def test_product_offer_issues_missing_offers():
    entities, _ = extract_jsonld(PRODUCT_NO_OFFERS_HTML)
    assert product_offer_issues(entities)


def test_product_offer_issues_no_product_at_all():
    entities, _ = extract_jsonld(BROKEN_JSON_HTML)
    issues = product_offer_issues(entities)
    assert issues and "Product" in issues[0]


# ---------------------------------------------------------------------------
# parse_meta / helpers
# ---------------------------------------------------------------------------


def test_parse_meta_extracts_og_twitter_microdata():
    meta = parse_meta(META_HTML)
    assert meta["og"]["og:title"] == "Заголовок"
    assert meta["og"]["og:type"] == "website"
    assert meta["twitter"]["twitter:card"] == "summary_large_image"
    assert meta["microdata_count"] == 3
    assert "https://schema.org/Product" in meta["microdata_types"]


def test_detect_shop_and_urls():
    assert detect_shop(SHOP_HTML) is True
    assert detect_shop("<html><body>blog</body></html>") is False

    assert looks_like_product_url("https://x.example/product/kruzhka/") is True
    assert looks_like_product_url("https://x.example/catalog/") is False
    assert looks_like_product_url("https://x.example/about") is False

    links = find_product_links(PRODUCT_LINKS_HTML, "https://x.example")
    assert "https://x.example/product/kruzhka/" in links
    assert "https://x.example/catalog/12345/" in links
    assert all("/catalog/" != u for u in links)


def test_parse_sitemap_locations():
    xml = "<urlset><url><loc>https://x.example/product/a/</loc></url><url><loc>https://x.example/product/b/</loc></url></urlset>"
    locs = parse_sitemap_locations(xml)
    assert locs == ["https://x.example/product/a/", "https://x.example/product/b/"]


# ---------------------------------------------------------------------------
# Checks (MockTransport, no real network)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_jsonld_check_ok():
    ctx = _ctx("https://shop.example", {"/": VALID_GRAPH_HTML})
    res = await jsonld(ctx)
    assert res.status == "ok"
    assert res.score == 100
    assert "Product" in res.raw["types"]


@pytest.mark.asyncio
async def test_jsonld_check_reports_broken_block():
    ctx = _ctx("https://shop.example", {"/": BROKEN_JSON_HTML})
    res = await jsonld(ctx)
    assert res.status == "critical"
    assert any(f.level == "critical" for f in res.findings)


@pytest.mark.asyncio
async def test_jsonld_check_missing_markup():
    ctx = _ctx("https://shop.example", {"/": "<html><body>нет разметки</body></html>"})
    res = await jsonld(ctx)
    assert res.status == "warning"
    assert res.raw["found"] is False


@pytest.mark.asyncio
async def test_microdata_check_ok():
    ctx = _ctx("https://shop.example", {"/": META_HTML})
    res = await microdata_og_twitter(ctx)
    assert res.status == "ok"
    assert res.raw["has_twitter_card"] is True


@pytest.mark.asyncio
async def test_ecommerce_skipped_when_not_shop():
    ctx = _ctx("https://blog.example", {"/": "<html><body>обычный блог</body></html>"})
    res = await ecommerce_product_schema(ctx)
    assert res.status == "skipped"
    assert res.raw["is_shop"] is False


@pytest.mark.asyncio
async def test_ecommerce_product_with_offer_ok():
    ctx = _ctx(
        "https://shop.example",
        {
            "/": SHOP_HTML + '<a href="/product/kruzhka/">Кружка</a>',
            "/product/kruzhka/": VALID_GRAPH_HTML,
        },
    )
    res = await ecommerce_product_schema(ctx)
    assert res.status == "ok"
    assert res.raw["ok"] == 1


@pytest.mark.asyncio
async def test_ecommerce_product_without_offer_critical():
    ctx = _ctx(
        "https://shop.example",
        {
            "/": SHOP_HTML + '<a href="/product/kruzhka/">Кружка</a>',
            "/product/kruzhka/": PRODUCT_NO_OFFERS_HTML,
        },
    )
    res = await ecommerce_product_schema(ctx)
    assert res.status == "critical"
    assert res.raw["ok"] == 0
