from __future__ import annotations

import html as html_mod
import json
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin, urlparse

from selectolax.lexbor import LexborHTMLParser as HTMLParser

from app.core import AuditContext, CheckResult, Finding
from app.registry import check

CATEGORY = "Структурированные данные"

# ---------------------------------------------------------------------------
# Pure parsing helpers (no network) - unit-testable
# ---------------------------------------------------------------------------

_SCHEMA_PREFIXES = ("https://schema.org/", "http://schema.org/", "https://schema.org", "http://schema.org")


def _strip_schema(value: str) -> str:
    v = value.strip()
    for pref in _SCHEMA_PREFIXES:
        if v.startswith(pref):
            v = v[len(pref):]
            break
    return v.strip("/") if "/" not in v else v


def entity_types(entity: Dict[str, Any]) -> List[str]:
    """Return normalized @type values of one entity as a list of plain type names."""
    if not isinstance(entity, dict):
        return []
    raw = entity.get("@type")
    if raw is None:
        return []
    values = raw if isinstance(raw, list) else [raw]
    out: List[str] = []
    for v in values:
        if isinstance(v, str) and v.strip():
            out.append(_strip_schema(v))
    return out


def _flatten(value: Any, out: List[Dict[str, Any]]) -> None:
    """Recursively flatten lists and @graph containers into a flat entity list."""
    if isinstance(value, list):
        for item in value:
            _flatten(item, out)
    elif isinstance(value, dict):
        graph = value.get("@graph")
        # A pure @graph container carries no entity of its own - only flatten it.
        if isinstance(graph, (list, dict)) and "@type" not in value:
            _flatten(graph, out)
            return
        out.append(value)
        if isinstance(graph, (list, dict)):
            _flatten(graph, out)


def extract_jsonld(html: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Extract all application/ld+json blocks from HTML.

    Returns (entities, errors):
      * entities - flat list of dicts, @graph and top-level lists are flattened;
      * errors   - list of human readable Russian messages for broken blocks.
    """
    entities: List[Dict[str, Any]] = []
    errors: List[str] = []
    if not html:
        return entities, errors

    try:
        tree = HTMLParser(html)
    except Exception as exc:  # pragma: no cover - defensive
        return entities, [f"Не удалось разобрать HTML: {exc}"]

    blocks = tree.css('script[type="application/ld+json"]')
    for idx, node in enumerate(blocks, start=1):
        raw = node.text() or ""
        raw = html_mod.unescape(raw).strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except Exception as exc:
            errors.append(f"Блок JSON-LD #{idx}: ошибка разбора JSON — {exc}")
            continue
        _flatten(data, entities)

    return entities, errors


def _required(entity: Dict[str, Any], fields: List[str]) -> List[str]:
    out: List[str] = []
    for f in fields:
        value = entity.get(f)
        if value is None or (isinstance(value, (str, list, dict)) and len(value) == 0):
            out.append(f"отсутствует обязательное поле {f}")
    return out


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _validate_offer(offer: Any) -> List[str]:
    if not isinstance(offer, dict):
        return ["offers должен быть объектом Offer"]
    return _required(offer, ["price", "priceCurrency", "availability"])


def validate_entity(entity: Dict[str, Any]) -> List[str]:
    """Validate required fields of one JSON-LD entity based on its @type.

    Returns a list of Russian messages about missing/invalid data (empty == valid).
    """
    if not isinstance(entity, dict):
        return ["сущность не является объектом"]

    errors: List[str] = []
    for t in entity_types(entity):
        if t == "Product":
            errors += _required(entity, ["name", "image", "offers"])
            offers = entity.get("offers")
            if offers is not None:
                for offer in _as_list(offers):
                    errors += _validate_offer(offer)
        elif t == "Offer":
            errors += _validate_offer(entity)
        elif t in ("Article", "BlogPosting", "NewsArticle"):
            errors += _required(entity, ["headline", "datePublished", "author"])
        elif t == "FAQPage":
            main = entity.get("mainEntity")
            if not main:
                errors.append("отсутствует обязательное поле mainEntity")
            else:
                for q in _as_list(main):
                    if not isinstance(q, dict):
                        errors.append("mainEntity должен быть объектом Question")
                        continue
                    if not q.get("name"):
                        errors.append("в Question отсутствует поле name")
                    if not q.get("acceptedAnswer"):
                        errors.append("в Question отсутствует acceptedAnswer")
        elif t == "BreadcrumbList":
            items = entity.get("itemListElement")
            if not items:
                errors.append("отсутствует обязательное поле itemListElement")
            else:
                for it in _as_list(items):
                    errors += _required(it if isinstance(it, dict) else {}, ["position", "name", "item"])
        elif t == "Organization":
            errors += _required(entity, ["name", "url", "logo"])
        elif t == "LocalBusiness":
            errors += _required(entity, ["name", "address", "telephone"])
        elif t == "WebSite":
            errors += _required(entity, ["name", "url"])

    return errors


def product_offer_issues(entities: List[Dict[str, Any]]) -> List[str]:
    """Return issues for Product entities in a page; empty means a valid Product+Offer."""
    products = [e for e in entities if "Product" in entity_types(e)]
    if not products:
        return ["не найдена разметка Product"]
    issues: List[str] = []
    for p in products:
        issues += validate_entity(p)
    return issues


def parse_meta(html: str) -> Dict[str, Any]:
    """Extract Open Graph, Twitter Card and microdata info from HTML (pure, no network)."""
    result: Dict[str, Any] = {"og": {}, "twitter": {}, "microdata_count": 0, "microdata_types": []}
    if not html:
        return result
    try:
        tree = HTMLParser(html)
    except Exception:  # pragma: no cover - defensive
        return result

    for node in tree.css("meta"):
        attrs = node.attributes
        content = attrs.get("content")
        if content is None:
            continue
        prop = (attrs.get("property") or "").strip().lower()
        name = (attrs.get("name") or "").strip().lower()
        if prop.startswith("og:") and prop not in result["og"]:
            result["og"][prop] = content
        if name.startswith("twitter:") and name not in result["twitter"]:
            result["twitter"][name] = content

    scopes = tree.css("[itemscope]")
    result["microdata_count"] = len(scopes)
    types: List[str] = []
    for node in tree.css("[itemtype]"):
        it = (node.attributes.get("itemtype") or "").strip()
        if it and it not in types:
            types.append(it)
    result["microdata_types"] = types
    return result


_SHOP_MARKERS = (
    "woocommerce",
    "shopify",
    "bitrix",
    "add-to-cart",
    "add_to_cart",
    "addtocart",
    "data-product",
    "product-card",
    "купить",
    "в корзину",
    "корзина",
    "/cart",
    "checkout",
)

_PRODUCT_MARKERS = ("/product/", "/products/", "/catalog/", "/tovar/", "/shop/")


def detect_shop(html: str) -> bool:
    """Heuristic: does this HTML look like an e-commerce site."""
    if not html:
        return False
    low = html.lower()
    return any(marker in low for marker in _SHOP_MARKERS)


def looks_like_product_url(url: str) -> bool:
    """Heuristic: does a URL look like a product detail page."""
    if not url:
        return False
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    for marker in _PRODUCT_MARKERS:
        idx = path.find(marker)
        if idx == -1:
            continue
        tail = path[idx + len(marker):]
        # require an actual slug after the marker, not just a listing root
        if tail.strip("/"):
            return True
    return False


def find_product_links(html: str, base: str, limit: int = 20) -> List[str]:
    """Collect deduplicated absolute product-like URLs from anchor hrefs (pure)."""
    out: List[str] = []
    seen = set()
    if not html:
        return out
    try:
        tree = HTMLParser(html)
    except Exception:  # pragma: no cover - defensive
        return out
    for node in tree.css("a"):
        href = (node.attributes.get("href") or "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute = urljoin(base + "/", href)
        if not absolute.startswith(("http://", "https://")):
            continue
        if not looks_like_product_url(absolute):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        out.append(absolute)
        if len(out) >= limit:
            break
    return out


def parse_sitemap_locations(xml_text: str) -> List[str]:
    """Extract <loc> URLs from a sitemap XML (pure)."""
    if not xml_text:
        return []
    locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", xml_text, flags=re.IGNORECASE | re.DOTALL)
    return [html_mod.unescape(loc).strip() for loc in locs if loc.strip()]


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


@check(id="jsonld", title="Разметка JSON-LD", category=CATEGORY)
async def jsonld(ctx: AuditContext) -> CheckResult:
    resp = await ctx.home()
    if resp is None:
        return CheckResult(
            id="jsonld",
            title="Разметка JSON-LD",
            category=CATEGORY,
            status="error",
            score=0,
            findings=[Finding(level="critical", text="Не удалось загрузить главную страницу для анализа JSON-LD", fix="Проверить доступность сайта")],
            raw={"found": False, "count": 0, "types": [], "errors": []},
        )

    html = resp.text or ""
    entities, errors = extract_jsonld(html)
    types: List[str] = []
    for e in entities:
        types += entity_types(e)
    unique_types = sorted(set(types))

    findings: List[Finding] = []
    invalid: List[Dict[str, Any]] = []

    for err in errors:
        findings.append(
            Finding(
                level="critical",
                text=f"Найден блок JSON-LD с ошибкой: {err}",
                fix="Исправить синтаксис JSON-LD (валидировать через Rich Results Test / валидатор разметки) до публикации",
                hours=0.5,
            )
        )

    for idx, e in enumerate(entities, start=1):
        issues = validate_entity(e)
        if issues:
            etype = "/".join(entity_types(e)) or "без @type"
            invalid.append({"index": idx, "type": etype, "issues": issues})
            findings.append(
                Finding(
                    level="warning",
                    text=f"Разметка «{etype}» неполная: {'; '.join(issues)}",
                    fix="Добавить недостающие обязательные поля разметки в соответствии с рекомендациями schema.org",
                    hours=0.5,
                )
            )

    if not entities and not errors:
        findings.append(
            Finding(
                level="warning",
                text="На главной странице не найдена разметка JSON-LD",
                fix="Внедрить базовую JSON-LD разметку (WebSite/Organization, а для товаров и статей — Product/Article)",
                hours=2.0,
            )
        )
        status, score = "warning", 50
    elif errors:
        status = "critical"
        score = max(0, 40 - 15 * len(errors))
    elif invalid:
        status = "warning"
        score = max(20, 100 - 12 * len(invalid))
    else:
        status, score = "ok", 100
        findings.append(Finding(level="ok", text=f"Найдено разметок: {len(entities)}, типы: {', '.join(unique_types) or '—'}"))

    return CheckResult(
        id="jsonld",
        title="Разметка JSON-LD",
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "found": bool(entities),
            "count": len(entities),
            "types": unique_types,
            "errors": errors,
            "invalid": invalid,
        },
    )


@check(id="microdata_og_twitter", title="Microdata, Open Graph и Twitter Card", category=CATEGORY)
async def microdata_og_twitter(ctx: AuditContext) -> CheckResult:
    resp = await ctx.home()
    if resp is None:
        return CheckResult(
            id="microdata_og_twitter",
            title="Microdata, Open Graph и Twitter Card",
            category=CATEGORY,
            status="error",
            score=0,
            findings=[Finding(level="critical", text="Не удалось загрузить главную страницу для анализа метатегов", fix="Проверить доступность сайта")],
            raw={},
        )

    html = resp.text or ""
    meta = parse_meta(html)
    og: Dict[str, str] = meta["og"]
    twitter: Dict[str, str] = meta["twitter"]

    required_og = ["og:title", "og:description", "og:image", "og:url", "og:type"]
    missing_og = [k for k in required_og if not og.get(k)]
    has_twitter = bool(twitter.get("twitter:card"))

    findings: List[Finding] = []
    if missing_og:
        findings.append(
            Finding(
                level="warning" if len(missing_og) < len(required_og) else "critical",
                text=f"Отсутствуют обязательные Open Graph теги: {', '.join(missing_og)}",
                fix="Добавить недостающие теги Open Graph (og:title, og:description, og:image, og:url, og:type) в <head>",
                hours=1.0,
            )
        )
    else:
        findings.append(Finding(level="ok", text="Все обязательные Open Graph теги присутствуют"))

    if not has_twitter:
        findings.append(
            Finding(
                level="warning",
                text="Не найдена разметка Twitter Card (twitter:card)",
                fix="Добавить тег twitter:card (например, summary_large_image) и Twitter-метатеги",
                hours=0.5,
            )
        )
    else:
        findings.append(Finding(level="ok", text=f"Twitter Card: {twitter.get('twitter:card')}"))

    if meta["microdata_count"]:
        findings.append(Finding(level="ok", text=f"Microdata: найдено {meta['microdata_count']} элементов с itemscope"))
    else:
        findings.append(
            Finding(
                level="warning",
                text="В HTML не найдена microdata-разметка (itemscope/itemtype)",
                fix="Рассмотреть внедрение microdata либо JSON-LD для структурирования контента",
                hours=0.5,
            )
        )

    if len(missing_og) == len(required_og):
        status = "critical"
    elif missing_og or not has_twitter:
        status = "warning"
    else:
        status = "ok"

    score = 100
    score -= 18 * len(missing_og)
    score -= 0 if has_twitter else 10
    score = max(0, min(100, score))

    return CheckResult(
        id="microdata_og_twitter",
        title="Microdata, Open Graph и Twitter Card",
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "og": og,
            "twitter": twitter,
            "missing_og": missing_og,
            "has_twitter_card": has_twitter,
            "microdata_count": meta["microdata_count"],
            "microdata_types": meta["microdata_types"],
        },
    )


async def _collect_product_urls(ctx: AuditContext, html: str, limit: int = 3) -> List[str]:
    urls = find_product_links(html, ctx.base)
    if len(urls) >= limit:
        return urls[:limit]
    # Fallback: WooCommerce-style product sitemap
    for sitemap_path in ("/product-sitemap.xml", "/sitemap_products.xml", "/sitemap.xml"):
        resp = await ctx.get(ctx.base + sitemap_path)
        if resp is None or resp.status_code != 200:
            continue
        for loc in parse_sitemap_locations(resp.text or ""):
            if loc in urls:
                continue
            if looks_like_product_url(loc):
                urls.append(loc)
            if len(urls) >= limit:
                break
        if len(urls) >= limit:
            break
    return urls[:limit]


@check(id="ecommerce_product_schema", title="Разметка товаров (Product/Offer)", category=CATEGORY)
async def ecommerce_product_schema(ctx: AuditContext) -> CheckResult:
    resp = await ctx.home()
    if resp is None:
        return CheckResult(
            id="ecommerce_product_schema",
            title="Разметка товаров (Product/Offer)",
            category=CATEGORY,
            status="error",
            score=0,
            findings=[Finding(level="critical", text="Не удалось загрузить главную страницу для анализа товарной разметки", fix="Проверить доступность сайта")],
            raw={},
        )

    html = resp.text or ""
    if not detect_shop(html):
        return CheckResult(
            id="ecommerce_product_schema",
            title="Разметка товаров (Product/Offer)",
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=[Finding(level="info", text="Признаков интернет-магазина не найдено — проверка товарной разметки пропущена", fix="")],
            raw={"is_shop": False},
        )

    product_urls = await _collect_product_urls(ctx, html, limit=3)
    if not product_urls:
        return CheckResult(
            id="ecommerce_product_schema",
            title="Разметка товаров (Product/Offer)",
            category=CATEGORY,
            status="warning",
            score=50,
            findings=[
                Finding(
                    level="warning",
                    text="Сайт похож на магазин, но не удалось найти страницы товаров для проверки",
                    fix="Убедиться, что карточки товаров доступны по ссылкам и содержат разметку Product/Offer",
                    hours=1.0,
                )
            ],
            raw={"is_shop": True, "products": [], "checked": 0},
        )

    findings: List[Finding] = []
    products_raw: List[Dict[str, Any]] = []
    ok_count = 0

    for url in product_urls:
        presp = await ctx.get(url)
        if presp is None:
            products_raw.append({"url": url, "ok": False, "issues": ["страница недоступна"]})
            findings.append(
                Finding(level="warning", text=f"Страница товара недоступна для проверки: {url}", fix="Проверить доступность страницы товара", hours=0.2)
            )
            continue
        entities, errors = extract_jsonld(presp.text or "")
        issues = product_offer_issues(entities)
        issues += errors
        is_ok = not issues
        products_raw.append({"url": url, "ok": is_ok, "issues": issues})
        if is_ok:
            ok_count += 1
        else:
            findings.append(
                Finding(
                    level="critical",
                    text=f"Страница товара {url} не имеет корректной разметки Product/Offer: {'; '.join(issues) or 'нет данных'}",
                    fix="Добавить JSON-LD Product с полями name, image и Offer (price, priceCurrency, availability) на странице товара",
                    hours=1.5,
                )
            )

    if ok_count == 0:
        status, score = "critical", 0
    elif ok_count < len(product_urls):
        status, score = "warning", 60
    else:
        status, score = "ok", 100
        findings.append(Finding(level="ok", text=f"Все проверенные страницы товаров ({ok_count}) содержат корректную разметку Product/Offer"))

    return CheckResult(
        id="ecommerce_product_schema",
        title="Разметка товаров (Product/Offer)",
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={"is_shop": True, "products": products_raw, "checked": len(product_urls), "ok": ok_count},
    )
