"""Узнаваемость бренда для ИИ без API-ключей: Wikidata, Википедия и запросы ниши для ручной проверки."""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from selectolax.lexbor import LexborHTMLParser

from app.core import AuditContext, CheckResult, Finding
from app.registry import check

CATEGORY = "GEO / AI"
WIKI_UA = {"User-Agent": "seo-geo-checker/1.0 (EvApps; https://check-seo-geo.evapps.ru)"}


def _bare(host: str) -> str:
    return re.sub(r"^www\.", "", (host or "").lower())


def extract_brand(html: str, host: str) -> dict:
    """Название бренда и язык страницы: og:site_name → JSON-LD Organization/WebSite → title → домен."""
    lang_match = re.search(r"<html[^>]*\slang=[\"']?([a-zA-Z-]+)", html or "", re.I)
    lang = lang_match.group(1).lower() if lang_match else ""
    parser = LexborHTMLParser(html or "")
    brand = ""

    og = parser.css_first('meta[property="og:site_name"]')
    if og is not None and (og.attributes.get("content") or "").strip():
        brand = og.attributes["content"].strip()

    if not brand:
        for node in parser.css("script[type='application/ld+json']"):
            try:
                data = json.loads(node.text() or "")
            except Exception:
                continue
            items = data.get("@graph", [data]) if isinstance(data, dict) else data
            for item in items if isinstance(items, list) else []:
                if not isinstance(item, dict):
                    continue
                types = item.get("@type")
                types = [str(t).lower() for t in (types if isinstance(types, list) else [types])]
                name = item.get("name")
                if ("organization" in types or "website" in types) and isinstance(name, str) and name.strip():
                    brand = name.strip()
                    break
            if brand:
                break

    if not brand:
        title_node = parser.css_first("title")
        title = title_node.text(strip=True) if title_node is not None else ""
        # «Korean cosmetics - Pandeoshop» / «FreshCare — магазин ухода»: часть, совпадающая с доменом,
        # иначе самая короткая (бренд короче описания)
        parts = [p.strip() for p in re.split(r"\s[-|—–]\s", title) if p.strip()]
        if len(parts) > 1:
            label = _bare(host).split(".")[0]
            squash = lambda s: re.sub(r"[^a-zа-я0-9]", "", s.lower())  # noqa: E731
            brand = next((p for p in parts if squash(p) == squash(label)), min(parts, key=len))

    if not brand:
        brand = _bare(host).split(".")[0].capitalize()
    return {"brand": brand, "lang": lang}


def match_official_site(entity_json: dict, host: str) -> bool:
    """Есть ли у сущности Wikidata официальный сайт (P856) на этом домене."""
    target = _bare(host)
    for entity in (entity_json.get("entities") or {}).values():
        for claim in ((entity or {}).get("claims") or {}).get("P856", []):
            value = (((claim or {}).get("mainsnak") or {}).get("datavalue") or {}).get("value")
            if isinstance(value, str):
                parsed = urlparse(value if "://" in value else f"https://{value}")
                if _bare(parsed.netloc) == target:
                    return True
    return False


_JUNK_WORDS = {
    # навигация, служебные блоки и «маркетинговые» заголовки, из которых не получаются запросы
    "cart", "basket", "login", "log in", "sign in", "sign up", "register", "account", "my account", "wishlist",
    "contact", "contacts", "contact us", "about", "about us", "home", "blog", "news", "faq", "help", "search",
    "menu", "more", "all", "welcome", "sale", "new", "special offer", "privacy", "terms", "shipping", "returns",
    "корзина", "войти", "вход", "регистрация", "кабинет", "личный кабинет", "избранное", "контакты", "о нас",
    "о компании", "главная", "блог", "новости", "помощь", "поиск", "меню", "ещё", "все", "доставка", "оплата",
    "возврат", "акции", "новинки", "почему мы", "отзывы", "вакансии", "карьера", "политика конфиденциальности",
    "кейсы", "проекты", "портфолио", "продукты", "услуги", "решения", "команда", "партнёры", "партнеры",
    "cases", "projects", "portfolio", "products", "services", "solutions", "team", "partners",
}
_QUERY_TEMPLATES = {
    "ru": {
        "topic": ["{t} купить", "лучшие {t}", "где купить {t}{r}", "как выбрать {t}", "{t} рейтинг"],
        "cat": ["{c} купить{r}", "лучшие {c}"],
        "brand": ["{b} отзывы", "{b} официальный сайт", "{b} или конкуренты — что выбрать"],
        "product": ["{p} купить", "{p} отзывы"],
        "region": {"Европа": " в Европе", "Россия": " в России"},
    },
    "en": {
        "topic": ["buy {t}", "best {t}", "where to buy {t}{r}", "how to choose {t}", "top {t} brands"],
        "cat": ["buy {c}{r}", "best {c}"],
        "brand": ["{b} reviews", "{b} official site", "is {b} legit"],
        "product": ["buy {p}", "{p} review"],
        "region": {"Europe": " in Europe", "Russia": " in Russia"},
    },
}


_SERVICE_TEMPLATES = {
    "ru": {
        "topic": ["{t} заказать", "лучшие компании {t}", "{t} цена", "как выбрать подрядчика {t}", "{t} отзывы"],
        "cat": ["{c} заказать{r}", "{c} компании"],
    },
    "en": {
        "topic": ["hire {t}", "best {t} companies", "{t} pricing", "how to choose {t} provider", "{t} reviews"],
        "cat": ["hire {c}{r}", "{c} companies"],
    },
}


def _clean_phrase(text: str) -> str:
    text = re.sub(r"[\U0001F000-\U0001FAFF☀-➿]", " ", text or "")
    text = re.sub(r"\(\d+\)|\d+\s*(шт|items?)\b", " ", text, flags=re.I)
    text = re.sub(r"[^\w\s&'-]", " ", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def _is_junk(phrase: str, brand: str) -> bool:
    if not phrase or len(phrase) < 3 or len(phrase.split()) > 6:
        return True
    if phrase in _JUNK_WORDS or phrase == brand.lower():
        return True
    if re.search(r"\d{3,}", phrase):  # артикулы, id из SVG/вёрстки
        return True
    return phrase.replace(" ", "").isdigit()


def _topic(data: dict, brand: str) -> str:
    """Тема сайта из title без бренда и разделителей: «Korean cosmetics Europe - Pandeoshop» → korean cosmetics."""
    for source in (data.get("title") or "", data.get("h1") or ""):
        parts = [p for p in re.split(r"\s[-|—–:]\s", source) if p.strip()]
        parts = [p for p in parts if brand.lower() not in p.lower()] or parts
        for part in parts:
            phrase = _clean_phrase(part)
            if brand:
                phrase = re.sub(rf"\b{re.escape(brand.lower())}\b", " ", phrase)
            for word in ("europe", "европа", "россия", "russia", "online", "онлайн", "интернет-магазин", "магазин", "store", "shop"):
                phrase = re.sub(rf"\b{word}\b", " ", phrase)
            phrase = re.sub(r"\s+", " ", phrase).strip()
            if not _is_junk(phrase, brand):
                return " ".join(phrase.split()[:4])
    return ""


def generate_queries(data: dict) -> list[str]:
    """8–12 запросов ниши по данным страницы, без ИИ: тема, категории меню, бренд, бренды товаров."""
    brand = (data.get("brand") or "").strip()
    lang = "ru" if (data.get("lang") or "").startswith("ru") else "en"
    tpl = _QUERY_TEMPLATES[lang]
    if data.get("is_shop") is False:
        tpl = {**tpl, **_SERVICE_TEMPLATES[lang]}
    region = tpl["region"].get(data.get("region") or "", "")

    categories: list[str] = []
    for raw in list(data.get("nav_anchors") or []) + list(data.get("h2") or []):
        phrase = _clean_phrase(raw)
        if not _is_junk(phrase, brand) and phrase not in categories:
            categories.append(phrase)

    topic = _topic(data, brand) or (categories[0] if categories else "")
    out: list[str] = []

    def add(q: str) -> None:
        q = re.sub(r"\s+", " ", q).strip()
        if q and q not in out:
            out.append(q)

    if topic:
        for t in tpl["topic"]:
            add(t.format(t=topic, r=region))
    for cat in categories[:3]:
        if cat != topic:
            for t in tpl["cat"]:
                add(t.format(c=cat, r=region))
    if brand:
        for t in tpl["brand"]:
            add(t.format(b=brand))
    for product in (data.get("product_names") or [])[:2]:
        p = _clean_phrase(product)
        if not _is_junk(p, brand):
            add(tpl["product"][0].format(p=p))
    # Добиваем до 8 вариантами по категориям глубже по списку
    for cat in categories[3:]:
        if len(out) >= 8:
            break
        add(tpl["cat"][0].format(c=cat, r=region))
    return out[:12]


def _page_data(html: str, host: str) -> dict:
    """Данные страницы для генерации запросов: title, description, заголовки, меню, бренды товаров."""
    info = extract_brand(html, host)
    parser = LexborHTMLParser(html)

    def first_text(selector: str) -> str:
        node = parser.css_first(selector)
        return node.text(strip=True) if node is not None and node.text() else ""

    desc_node = parser.css_first('meta[name="description"]')
    product_names: list[str] = []
    for node in parser.css("script[type='application/ld+json']"):
        try:
            data = json.loads(node.text() or "")
        except Exception:
            continue
        for item in data if isinstance(data, list) else [data]:
            if isinstance(item, dict):
                brand_val = item.get("brand")
                if isinstance(brand_val, dict):
                    brand_val = brand_val.get("name")
                if isinstance(brand_val, str) and brand_val.strip():
                    product_names.append(brand_val.strip())

    h2 = [h.text(strip=True) for h in parser.css("h2")[:10]]
    full_text = " ".join([first_text("title"), first_text("h1")] + h2)
    lang = (info.get("lang") or "")[:2]
    region = ""
    if re.search(r"европ|europe", full_text, re.I):
        region = "Европа" if lang == "ru" else "Europe"
    elif re.search(r"росси|russia|москв|moscow", full_text, re.I):
        region = "Россия" if lang == "ru" else "Russia"

    return {
        "brand": info.get("brand") or "",
        "lang": lang,
        "title": first_text("title"),
        "description": (desc_node.attributes.get("content") or "") if desc_node is not None else "",
        "h1": first_text("h1"),
        "h2": h2,
        "nav_anchors": [a.text(strip=True) for a in parser.css("nav a, header a, .menu a")[:30] if a.text(strip=True)],
        "product_names": product_names[:5],
        "region": region,
        # Магазин или услуги: от этого зависят шаблоны «купить» / «заказать»
        "is_shop": bool(re.search(
            r"woocommerce|add-to-cart|add_to_cart|cdn\.shopify|\"@type\"\s*:\s*\"(Product|Offer)\"|в корзину|add to cart",
            html, re.I,
        )),
    }


def _site_host(ctx: AuditContext) -> str:
    return re.sub(r"^www\.", "", ctx.host.lower())


def _same_as(html: str) -> list[str]:
    blocks = re.findall(r'"sameAs"\s*:\s*\[([^\]]*)\]', html)
    return re.findall(r'"([^"]+)"', " ".join(blocks))


def _result(check_id: str, title: str, status: str, score: int, findings: list[Finding], raw: dict) -> CheckResult:
    return CheckResult(id=check_id, title=title, category=CATEGORY, status=status, score=score, findings=findings, raw=raw)


@check(id="wikidata_presence", title="Бренд в Wikidata", category=CATEGORY)
async def wikidata_presence(ctx: AuditContext) -> CheckResult:
    check_id, title = "wikidata_presence", "Бренд в Wikidata"
    home = await ctx.home()
    if home is None:
        return _result(check_id, title, "skipped", 0, [Finding("info", "Главная недоступна — бренд не определён")], {})
    host = _site_host(ctx)
    info = extract_brand(home.text, host)
    brand, lang = info["brand"], (info.get("lang") or "en")[:2] or "en"

    search = await ctx.get(
        "https://www.wikidata.org/w/api.php",
        params={"action": "wbsearchentities", "search": brand, "language": lang, "uselang": lang, "format": "json", "limit": 5},
        headers=WIKI_UA,
    )
    if search is None or search.status_code != 200:
        return _result(check_id, title, "skipped", 0, [Finding("info", "Wikidata API недоступен — проверка пропущена")], {"brand": brand})
    candidates = (search.json() or {}).get("search", [])

    matched = None
    for cand in candidates:
        entity = await ctx.get(f"https://www.wikidata.org/wiki/Special:EntityData/{cand['id']}.json", headers=WIKI_UA)
        if entity is not None and entity.status_code == 200 and match_official_site(entity.json(), host):
            matched = cand
            break

    linked = any("wikidata.org" in s or "wikipedia.org" in s for s in _same_as(home.text))
    raw = {"brand": brand, "candidates": [{"id": c.get("id"), "label": c.get("label"), "description": c.get("description")} for c in candidates]}

    if matched:
        findings = [Finding("ok", f"Бренд «{brand}» есть в Wikidata: {matched['id']} {matched.get('description') or ''}".strip())]
        if not linked:
            findings.append(Finding(
                "warning", "Элемент Wikidata не указан в Organization.sameAs на сайте",
                fix=f"Добавить https://www.wikidata.org/wiki/{matched['id']} в sameAs разметки Organization", hours=0.25,
            ))
        return _result(check_id, title, "ok" if linked else "warning", 100 if linked else 80, findings, {**raw, "matched": matched["id"]})

    if candidates:
        names = ", ".join(f"{c.get('label')} ({c.get('description') or c.get('id')})" for c in candidates[:3])
        return _result(check_id, title, "warning", 50, [Finding(
            "warning",
            f"В Wikidata есть одноимённые сущности, но ни одна не связана с {host}: {names}. ИИ может путать бренд с ними",
            fix="Создать отдельный элемент Wikidata для компании (P31 — тип организации, P856 — официальный сайт, "
                "источники о компании) и указать его в Organization.sameAs",
            hours=2,
        )], raw)

    return _result(check_id, title, "warning", 40, [Finding(
        "warning",
        f"Бренд «{brand}» не найден в Wikidata — ИИ-модели хуже распознают компанию как сущность",
        fix="Создать элемент Wikidata: название, описание, P31 (тип организации), P856 (официальный сайт), P17 (страна), "
            "ссылки на независимые источники; затем добавить ссылку в Organization.sameAs",
        hours=2,
    )], raw)


@check(id="wikipedia_presence", title="Бренд в Википедии", category=CATEGORY)
async def wikipedia_presence(ctx: AuditContext) -> CheckResult:
    check_id, title = "wikipedia_presence", "Бренд в Википедии"
    home = await ctx.home()
    if home is None:
        return _result(check_id, title, "skipped", 0, [Finding("info", "Главная недоступна — бренд не определён")], {})
    host = _site_host(ctx)
    info = extract_brand(home.text, host)
    brand = info["brand"]
    langs = list(dict.fromkeys([(info.get("lang") or "en")[:2] or "en", "en"]))

    mentions: list[dict] = []
    for lang in langs:
        api = f"https://{lang}.wikipedia.org/w/api.php"
        resp = await ctx.get(api, params={"action": "query", "list": "search", "srsearch": f'"{brand}"', "format": "json", "srlimit": 5}, headers=WIKI_UA)
        if resp is None or resp.status_code != 200:
            continue
        for hit in (resp.json().get("query") or {}).get("search", []):
            ext = await ctx.get(api, params={"action": "query", "prop": "extlinks", "titles": hit["title"], "ellimit": 100, "format": "json"}, headers=WIKI_UA)
            links_site = False
            if ext is not None and ext.status_code == 200:
                for page in (ext.json().get("query") or {}).get("pages", {}).values():
                    links_site = links_site or any(host in (link.get("*") or "") for link in page.get("extlinks", []))
            mentions.append({"lang": lang, "title": hit["title"], "links_site": links_site})

    raw = {"brand": brand, "mentions": mentions}
    linking = [m for m in mentions if m["links_site"]]
    if linking:
        names = ", ".join(f"{m['lang']}: {m['title']}" for m in linking[:3])
        return _result(check_id, title, "ok", 100, [Finding("ok", f"Статьи Википедии ссылаются на сайт: {names}")], raw)
    if mentions:
        names = ", ".join(f"{m['lang']}: {m['title']}" for m in mentions[:3])
        return _result(check_id, title, "ok", 80, [Finding(
            "info", f"Бренд упоминается в Википедии без ссылки на сайт: {names}",
            fix="Если статья о компании — предложить добавить официальный сайт через обсуждение статьи (с источниками)", hours=0.5,
        )], raw)
    return _result(check_id, title, "ok", 70, [Finding(
        "info", f"Бренд «{brand}» не упоминается в Википедии",
        fix="Набирать упоминания в независимых СМИ и отраслевых обзорах — это основа и для статьи, и для узнаваемости бренда ИИ",
    )], raw)


@check(id="niche_queries", title="Запросы для проверки видимости в ИИ", category=CATEGORY)
async def niche_queries(ctx: AuditContext) -> CheckResult:
    check_id, title = "niche_queries", "Запросы для проверки видимости в ИИ"
    home = await ctx.home()
    if home is None:
        return _result(check_id, title, "skipped", 0, [Finding("info", "Главная недоступна")], {})
    data = _page_data(home.text, _site_host(ctx))
    queries = generate_queries(data)
    if len(queries) < 8:
        queries = list(dict.fromkeys(queries + generate_queries({**data, "lang": "en"})))[:12]
    return _result(check_id, title, "ok", 100, [Finding(
        "info",
        "Запросы для проверки видимости в ИИ: " + "; ".join(queries),
        fix="Задать эти вопросы ChatGPT, Perplexity и Алисе и проверить, упоминается ли сайт; повторять раз в месяц",
    )], {"queries": queries, "brand": data["brand"]})
