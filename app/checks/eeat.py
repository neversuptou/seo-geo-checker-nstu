"""Проверки доверия и E-E-A-T (Experience, Expertise, Authoritativeness, Trustworthiness).

Проверки:
- trust_pages         — страницы доверия: о нас, контакты, доставка, возврат, политика, оферта, FAQ
- contact_signals     — контактные данные и реквизиты компании (телефон, e-mail, адрес, ИНН/ОГРН, соцсети, карта)
- authorship          — авторство и даты публикации статей блога
- reviews_social_proof — отзывы и социальные доказательства (AggregateRating/Review, тексты виджетов)

Чистая логика (без сети) вынесена в синхронные функции и покрыта юнит-тестами:
`classify_trust_links`, `collect_links`, `detect_contact_signals`, `analyze_authorship`,
`find_section_link`, `looks_like_post_url`.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from selectolax.lexbor import LexborHTMLParser as HTMLParser

from app.core import AuditContext, CheckResult, Finding
from app.registry import check
from app.checks.structured_data import (
    detect_shop,
    entity_types,
    extract_jsonld,
    find_product_links,
)

CATEGORY = "Доверие и E-E-A-T"

_WORD_RE = re.compile(r"[0-9A-Za-zА-Яа-яЁё]+")

# Типы страниц доверия, которые нужны всем сайтам (при отсутствии — warning).
TRUST_REQUIRED_ALL: Tuple[str, ...] = ("about", "contacts", "privacy")
# Типы, которые обязательны для интернет-магазина (при отсутствии — critical).
TRUST_REQUIRED_SHOP: Tuple[str, ...] = ("delivery", "returns", "terms")

TRUST_LABEL: Dict[str, str] = {
    "about": "О компании",
    "contacts": "Контакты",
    "delivery": "Доставка и оплата",
    "returns": "Возврат и обмен",
    "privacy": "Политика конфиденциальности",
    "terms": "Публичная оферта и условия",
    "faq": "FAQ (частые вопросы)",
}

# (что сделать, часы) для каждой отсутствующей страницы доверия.
TRUST_FIX: Dict[str, Tuple[str, float]] = {
    "about": (
        "Создать страницу «О компании»: кто основал бизнес, опыт, команда, экспертиза и достижения — это основной сигнал E-E-A-T",
        3.0,
    ),
    "contacts": (
        "Создать страницу «Контакты» с телефоном, e-mail, физическим адресом и формой обратной связи",
        1.5,
    ),
    "delivery": (
        "Создать страницу «Доставка и оплата»: сроки, стоимость, регионы, способы оплаты и условия бесплатной доставки",
        3.0,
    ),
    "returns": (
        "Создать страницу «Возврат и обмен»: сроки, условия возврата, порядок действий и форма заявления",
        2.0,
    ),
    "privacy": (
        "Опубликовать политику конфиденциальности и обработки персональных данных (152-ФЗ / GDPR) со ссылкой в футере",
        2.0,
    ),
    "terms": (
        "Опубликовать публичную оферту / условия использования сайта и разместить ссылку в футере",
        2.0,
    ),
    "faq": (
        "Добавить раздел FAQ с частыми вопросами и развёрнутыми ответами — помогает и людям, и AI-поиску",
        2.0,
    ),
}

# Порядок важен: более специфичные типы идут раньше, чтобы не «съесть» чужой тип.
_TRUST_PATTERNS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (
        "privacy",
        (
            "политик",
            "конфиденциальност",
            "персональн",
            "privacy",
            "gdpr",
            "cookie",
            "zasebnost",
            "zasebno",
            "datenschutz",
            "confidential",
        ),
    ),
    (
        "returns",
        (
            "возврат",
            "обмен",
            "returns",
            "return",
            "refund",
            "vračilo",
            "vracilo",
            "reklamacij",
            "reklamaci",
            "money-back",
        ),
    ),
    (
        "delivery",
        (
            "доставк",
            "shipping",
            "delivery",
            "dostava",
            "dostav",
            "оплат",
            "payment",
            "plačilo",
            "placilo",
        ),
    ),
    (
        "terms",
        (
            "оферт",
            "пользовательское соглашение",
            "условия использования",
            "условия продажи",
            "условия покупки",
            "terms",
            "pogoji",
            "splošni pogoji",
        ),
    ),
    (
        "faq",
        ("faq", "вопрос", "частозадаваем", "vprašanj", "vprasanj", "q&a"),
    ),
    (
        "contacts",
        (
            "контакт",
            "contact",
            "связь",
            "обратн",
            "kontakt",
            "zveza",
            "телефон",
            "написать",
        ),
    ),
    (
        "about",
        (
            "о нас",
            "о компании",
            "о бренде",
            "o-kompanii",
            "o-nas",
            "about",
            "o nas",
            "o-podjetju",
            "o podjetju",
        ),
    ),
)

_NON_PAGE_PREFIXES = ("mailto:", "tel:", "javascript:", "data:", "#", "sms:", "callto:")

# --- keyword-детекторы контактов -------------------------------------------------
_PHONE_RE = re.compile(r"\+?\d[\d\s\-\(\)\.]{8,}\d")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_EMAIL_OBFUSCATED_RE = re.compile(r"([A-Za-z0-9._%+\-]+)\s*(?:\(at\)|\[at\]|@)\s*([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", re.IGNORECASE)

_LEGAL_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("ИНН", re.compile(r"ИНН\s*[:№]?\s*\d{10,12}", re.IGNORECASE)),
    ("ОГРН", re.compile(r"ОГРН\s*[:№]?\s*\d{13,15}", re.IGNORECASE)),
    ("ОГРНИП", re.compile(r"ОГРНИП\s*[:№]?\s*\d{15}", re.IGNORECASE)),
    ("КПП", re.compile(r"КПП\s*[:№]?\s*\d{9}", re.IGNORECASE)),
    ("VAT", re.compile(r"\bVAT\s*(?:number|no|id)?\s*[:№]?\s*[A-Z]{0,3}\d{6,}", re.IGNORECASE)),
    ("Reg. no", re.compile(r"\b(?:Reg(?:istration)?\.?\s*(?:no|number|št))\s*[:№.]?\s*[\d\-]{6,}", re.IGNORECASE)),
    ("ООО/ОАО/ИП", re.compile(r"\b(?:ООО|ОАО|ЗАО|ПАО|АО|ИП)\s+[«\"][^»\"]{2,60}[»\"]", re.IGNORECASE)),
)

_ADDRESS_MARKERS = (
    "ул.",
    "улица",
    "проспект",
    "пр-т",
    "переулок",
    "шоссе",
    "наб.",
    "квартал",
    "д.",
    "дом ",
    "офис",
    "оф.",
    "корпус",
    "строение",
    "индекс",
    "street",
    "avenue",
    "road",
    "office",
    "suite",
    "floor",
    "ulica",
    "cesta",
    "naslov",
)

_SOCIAL_MARKERS: Tuple[Tuple[str, str], ...] = (
    ("telegram", "t.me/"),
    ("telegram", "telegram.me/"),
    ("telegram", "tg://"),
    ("whatsapp", "wa.me/"),
    ("whatsapp", "whatsapp.com/"),
    ("whatsapp", "whatsapp://"),
    ("viber", "viber:"),
    ("viber", "viber.com/"),
    ("vk", "vk.com/"),
    ("vk", "vk.ru/"),
    ("instagram", "instagram.com/"),
    ("facebook", "facebook.com/"),
    ("youtube", "youtube.com/"),
    ("youtube", "youtu.be/"),
    ("ok", "ok.ru/"),
    ("dzen", "dzen.ru/"),
    ("tiktok", "tiktok.com/"),
    ("linkedin", "linkedin.com/"),
)

_MAP_MARKERS = (
    "yandex.ru/map",
    "yandex.com/map",
    "yandex.ru/maps",
    "google.com/maps",
    "google.ru/maps",
    "maps.google",
    "2gis.",
    "google.com/map",
    "openstreetmap.org/export/embed",
    "mapbox.com",
)


# ===========================================================================
# Вспомогательные функции
# ===========================================================================
def _truncate(text: str, limit: int = 90) -> str:
    t = (text or "").strip()
    return t if len(t) <= limit else t[: limit - 1] + "…"


def _absolute(href: str, base: str) -> str:
    h = (href or "").strip()
    if not h:
        return ""
    if h.startswith(("http://", "https://")):
        return h
    if base:
        return urljoin(base.rstrip("/") + "/", h)
    return h


def collect_links(html: str, base: str = "") -> List[Tuple[str, str]]:
    """Чистая функция: собрать пары (href, anchor) по всем анкорам документа.

    Возвращаются только ссылки-страницы (http/https/относительные) — служебные
    схемы (mailto:, tel:, javascript:, #) отбрасываются как не относящиеся к «страницам доверия».
    """
    out: List[Tuple[str, str]] = []
    seen = set()
    try:
        tree = HTMLParser(html or "")
    except Exception:  # pragma: no cover - защитный путь
        return out

    for node in tree.css("a"):
        href = (node.attributes.get("href") or "").strip()
        if not href:
            continue
        low = href.lower()
        if low.startswith(_NON_PAGE_PREFIXES) or "?" in low:
            # ссылки с параметрами — фильтры и сортировки каталога, а не страницы доверия
            continue
        anchor = node.text(separator=" ", strip=True)
        key = (href, anchor)
        if key in seen:
            continue
        seen.add(key)
        out.append((href, anchor))
    return out


def classify_trust_links(links: List[Tuple[str, str]]) -> Dict[str, str]:
    """Чистая функция: классифицировать ссылки в типы страниц доверия.

    На вход принимает список пар (href, anchor). Возвращает словарь
    ``{тип: ссылка}`` — по одной ссылке на тип (первая подходящая).
    Классификация идёт и по URL-слагу, и по анкорному тексту; поддерживаются
    русские, английские и словенские ключевые слова.
    """
    result: Dict[str, str] = {}
    for href, anchor in links or []:
        h = (href or "").strip()
        if not h:
            continue
        low = h.lower()
        if low.startswith(_NON_PAGE_PREFIXES):
            continue
        haystack = (low + " " + (anchor or "").strip().lower()).replace("ё", "е")
        for ttype, keywords in _TRUST_PATTERNS:
            if any(kw in haystack for kw in keywords):
                if ttype not in result:
                    result[ttype] = h
                break
    return result


def find_section_link(links: List[Tuple[str, str]], keywords: Tuple[str, ...]) -> Optional[str]:
    """Чистая функция: найти первую ссылку раздела по ключевым словам (URL или анкор)."""
    for href, anchor in links or []:
        haystack = ((href or "").lower() + " " + (anchor or "").lower()).replace("ё", "е")
        if any(kw in haystack for kw in keywords):
            return href
    return None


def _is_shop(html: str) -> bool:
    """Интернет-магазин только по явным признакам покупки: корзина, CMS магазина, разметка Product/Offer.

    Ссылки вида /product/ или /catalog/ не считаем — они есть и у сайтов услуг (evapps.ru/product/).
    """
    return bool(re.search(
        r"woocommerce|add-to-cart|add_to_cart|addtocart|cdn\.shopify|\"@type\"\s*:\s*\"(Product|Offer)\"|в корзину|add to cart",
        html or "", re.I,
    ))


def _word_count(html: str) -> int:
    """Чистая функция: количество слов в видимом тексте страницы (без script/style)."""
    cleaned = re.sub(r"(?is)<(script|style|noscript|svg|template)\b.*?</\1>", " ", html or "")
    try:
        tree = HTMLParser(cleaned)
    except Exception:  # pragma: no cover - защитный путь
        return 0
    body = tree.body
    text = body.text(separator=" ", strip=True) if body is not None else ""
    return len(_WORD_RE.findall(text))


# ===========================================================================
# Детекторы контактных сигналов (чистые функции)
# ===========================================================================
def _find_phones(text: str) -> List[str]:
    found: List[str] = []
    seen = set()
    for match in _PHONE_RE.finditer(text or ""):
        raw = match.group(0).strip(" .,;")
        digits = re.sub(r"\D", "", raw)
        if not (10 <= len(digits) <= 15):
            continue
        if raw in seen:
            continue
        seen.add(raw)
        found.append(raw)
    return found


def detect_contact_signals(html: str) -> Dict[str, Any]:
    """Чистая функция: найти контактные данные и реквизиты в HTML.

    Возвращает словарь с булевыми флагами и найденными образцами:
    phone/phones, email/emails, address/address_source, legal/legal_details,
    social/social_links, map.
    """
    raw = html or ""
    low = raw.lower()

    phones: List[str] = []
    emails: List[str] = []
    social: List[str] = []
    map_embed = False
    tel_link = False
    mailto_link = False

    tree = None
    try:
        tree = HTMLParser(raw)
    except Exception:  # pragma: no cover - защитный путь
        tree = None

    text = ""
    if tree is not None:
        for node in tree.css("a"):
            href = (node.attributes.get("href") or "").strip()
            hlow = href.lower()
            if hlow.startswith("tel:"):
                tel_link = True
                num = href[4:].strip()
                if num and num not in phones:
                    phones.append(num)
            elif hlow.startswith("mailto:"):
                mailto_link = True
                addr = href[7:].split("?", 1)[0].strip()
                if addr and addr not in emails:
                    emails.append(addr)
        for node in tree.css("iframe"):
            src = (node.attributes.get("src") or "").lower()
            if any(marker in src for marker in _MAP_MARKERS):
                map_embed = True
        for node in tree.css("[class*='map'], [id*='map'], [class*='karta'], [id*='karta']"):
            map_embed = True
            break
        body = tree.body
        text = body.text(separator=" ", strip=True) if body is not None else ""

    # Телефоны и e-mail из видимого текста + сырого HTML.
    for number in _find_phones(text):
        if number not in phones:
            phones.append(number)
    for match in _EMAIL_RE.finditer(raw):
        addr = match.group(0)
        if addr not in emails:
            emails.append(addr)
    if not emails:
        for match in _EMAIL_OBFUSCATED_RE.finditer(raw):
            addr = f"{match.group(1)}@{match.group(2)}"
            if addr not in emails:
                emails.append(addr)

    # Адрес: JSON-LD PostalAddress/address, микроразметка или адресный текст.
    address = False
    address_source = ""
    entities, _ = extract_jsonld(raw)
    for entity in entities:
        types = entity_types(entity)
        if "PostalAddress" in types or "LocalBusiness" in types or "Organization" in types:
            addr = entity.get("address")
            if isinstance(addr, dict) and any(addr.get(k) for k in ("streetAddress", "postalCode", "addressLocality")):
                address = True
                address_source = "JSON-LD PostalAddress"
                break
            if isinstance(addr, str) and addr.strip():
                address = True
                address_source = "JSON-LD address"
                break
    if not address and tree is not None:
        if tree.css_first("[itemtype*='PostalAddress']") is not None or tree.css_first("[itemprop='address']") is not None:
            address = True
            address_source = "microdata address"
    if not address:
        hay = (text + " " + raw).lower()
        if any(marker in hay for marker in _ADDRESS_MARKERS):
            address = True
            address_source = "текст с адресными признаками"

    # Юридические реквизиты.
    legal_details: List[str] = []
    for _label, pattern in _LEGAL_PATTERNS:
        match = pattern.search(raw)
        if match:
            detail = match.group(0).strip()
            if detail not in legal_details:
                legal_details.append(detail)

    # Соцсети и мессенджеры.
    for _name, marker in _SOCIAL_MARKERS:
        if marker in low:
            if _name not in social:
                social.append(_name)

    return {
        "phone": bool(phones) or tel_link,
        "phones": phones[:5],
        "email": bool(emails) or mailto_link,
        "emails": emails[:5],
        "address": address,
        "address_source": address_source,
        "legal": bool(legal_details),
        "legal_details": legal_details[:6],
        "social": bool(social),
        "social_links": social[:10],
        "map": map_embed,
    }


# ===========================================================================
# Авторство (чистые функции)
# ===========================================================================
def looks_like_post_url(url: str, blog_url: str = "") -> bool:
    """Чистая функция: похож ли URL на страницу отдельной статьи, а не на листинг."""
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:  # pragma: no cover - защитный путь
        return False
    path = parsed.path.lower()
    if not path or path == "/":
        return False
    if parsed.query:
        return False
    bad_markers = (
        "/tag/",
        "/tags/",
        "/category/",
        "/categories/",
        "/page/",
        "/author/",
        "/wp-content/",
        "/feed",
        "/rss",
        "/comment",
        "/search",
        "/login",
        "/cart",
        "/contact",
        "/about",
    )
    if any(marker in path for marker in bad_markers):
        return False

    segments = [seg for seg in path.strip("/").split("/") if seg]
    base_path = urlparse(blog_url).path.strip("/").lower() if blog_url else ""
    if base_path:
        if not path.startswith("/" + base_path):
            return False
        return len(segments) > len(base_path.split("/"))
    return len(segments) >= 1


def analyze_authorship(html: str) -> Dict[str, Any]:
    """Чистая функция: проверить авторство и даты публикации статьи.

    Возвращает: author, author_sources, published, modified, author_bio, byline.
    """
    raw = html or ""
    result: Dict[str, Any] = {
        "author": "",
        "author_sources": [],
        "published": "",
        "modified": "",
        "author_bio": False,
        "byline": False,
    }
    try:
        tree = HTMLParser(raw)
    except Exception:  # pragma: no cover - защитный путь
        return result

    for node in tree.css("meta"):
        attrs = node.attributes
        name = (attrs.get("name") or "").strip().lower()
        prop = (attrs.get("property") or "").strip().lower()
        content = (attrs.get("content") or "").strip()
        if not content:
            continue
        if name in ("author", "article:author", "twitter:creator") and not result["author"]:
            result["author"] = content
            result["author_sources"].append(f"meta {name}")
        if prop in ("article:published_time", "article:published", "og:published_time") and not result["published"]:
            result["published"] = content
        if prop in ("article:modified_time", "og:updated_time") and not result["modified"]:
            result["modified"] = content

    rel_author = tree.css_first('a[rel~="author"]')
    if rel_author is not None:
        result["author_bio"] = True
        text = rel_author.text(strip=True)
        if text and not result["author"]:
            result["author"] = text
            result["author_sources"].append("rel=author")

    for selector in ('[class*="author"]', '[class*="byline"]', '[class*="автор"]', '[class*="Author"]'):
        node = tree.css_first(selector)
        if node is None:
            continue
        result["byline"] = True
        text = node.text(separator=" ", strip=True)
        if text and not result["author"]:
            result["author"] = _truncate(text, 120)
            result["author_sources"].append("ссылка/блок автора")
        if node.css_first('a[href*="author"]') is not None or node.css_first('[class*="bio"]') is not None:
            result["author_bio"] = True
        break

    for node in tree.css("time"):
        dt = (node.attributes.get("datetime") or "").strip()
        if dt and not result["published"]:
            result["published"] = dt

    entities, _ = extract_jsonld(raw)
    for entity in entities:
        types = entity_types(entity)
        if not any(t in ("Article", "BlogPosting", "NewsArticle") for t in types):
            continue
        author = entity.get("author")
        for item in author if isinstance(author, list) else [author]:
            if isinstance(item, dict) and item.get("name") and not result["author"]:
                result["author"] = str(item["name"])
                result["author_sources"].append("JSON-LD author")
            elif isinstance(item, str) and item.strip() and not result["author"]:
                result["author"] = item.strip()
                result["author_sources"].append("JSON-LD author")
        if not result["published"] and entity.get("datePublished"):
            result["published"] = str(entity.get("datePublished"))
        if not result["modified"] and entity.get("dateModified"):
            result["modified"] = str(entity.get("dateModified"))

    return result


# ===========================================================================
# Вспомогательные конструкторы результата
# ===========================================================================
def _status_from_score(score: int) -> str:
    if score >= 80:
        return "ok"
    if score >= 40:
        return "warning"
    return "critical"


def _skipped(check_id: str, title: str, what: str, fix: str) -> CheckResult:
    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="skipped",
        score=0,
        findings=[Finding(level="warning", text=f"Не удалось получить {what} — проверка пропущена", fix=fix, hours=0.5)],
        raw={},
    )


# ===========================================================================
# Проверка 1: страницы доверия
# ===========================================================================
@check(id="trust_pages", title="Страницы доверия (о нас, контакты, доставка, оферта)", category=CATEGORY)
async def trust_pages(ctx: AuditContext) -> CheckResult:
    check_id = "trust_pages"
    title = "Страницы доверия (о нас, контакты, доставка, оферта)"

    resp = await ctx.home()
    if resp is None:
        return _skipped(check_id, title, "HTML главной страницы", "Проверить доступность сайта и повторить аудит")

    html = resp.text or ""
    links = collect_links(html, ctx.base)
    found = classify_trust_links(links)
    is_shop = _is_shop(html)

    present: List[str] = []
    details: Dict[str, Any] = {}
    for ttype, href in found.items():
        url = _absolute(href, ctx.base)
        page = await ctx.get(url) if url else None
        if page is None:
            details[ttype] = {"url": url, "status": None, "words": 0, "ok": False}
            continue
        words = _word_count(page.text or "")
        ok = page.status_code == 200 and words >= 80
        details[ttype] = {"url": url, "status": page.status_code, "words": words, "ok": ok}
        if ok:
            present.append(ttype)

    findings: List[Finding] = []
    score = 100

    required_all = list(TRUST_REQUIRED_ALL)
    required_shop = list(TRUST_REQUIRED_SHOP) if is_shop else []
    missing_all = [t for t in required_all if t not in present]
    missing_shop = [t for t in required_shop if t not in present]

    for ttype in required_all:
        if ttype in present:
            findings.append(
                Finding(level="info", text=f"Страница «{TRUST_LABEL[ttype]}» найдена и содержит достаточно текста: {details[ttype]['url']}", fix="", hours=0.0)
            )

    for ttype in missing_all:
        fix, hours = TRUST_FIX[ttype]
        if ttype in found:
            findings.append(
                Finding(
                    level="warning",
                    text=f"Страница «{TRUST_LABEL[ttype]}» найдена, но не прошла проверку (статус {details[ttype].get('status')}, слов {details[ttype].get('words', 0)}): {details[ttype].get('url')}",
                    fix=f"Наполнить страницу «{TRUST_LABEL[ttype]}» содержательным текстом (не менее 80 слов) и вернуть код 200",
                    hours=1.5,
                )
            )
        else:
            findings.append(
                Finding(
                    level="warning",
                    text=f"Не найдена страница «{TRUST_LABEL[ttype]}» — важный сигнал доверия для пользователей и AI-поиска",
                    fix=fix,
                    hours=hours,
                )
            )
        score -= 15

    if is_shop:
        for ttype in required_shop:
            if ttype in present:
                findings.append(
                    Finding(level="info", text=f"Обязательная для магазина страница «{TRUST_LABEL[ttype]}» найдена: {details[ttype]['url']}", fix="", hours=0.0)
                )
        for ttype in missing_shop:
            fix, hours = TRUST_FIX[ttype]
            if ttype in found:
                findings.append(
                    Finding(
                        level="critical",
                        text=f"Страница «{TRUST_LABEL[ttype]}» найдена, но не прошла проверку (статус {details[ttype].get('status')}, слов {details[ttype].get('words', 0)}): {details[ttype].get('url')}",
                        fix=f"Наполнить обязательную для магазина страницу «{TRUST_LABEL[ttype]}» текстом и вернуть код 200",
                        hours=2.0,
                    )
                )
            else:
                findings.append(
                    Finding(
                        level="critical",
                        text=f"Интернет-магазин без обязательной страницы «{TRUST_LABEL[ttype]}» — прямое нарушение доверия и требований платёжных систем",
                        fix=fix,
                        hours=hours,
                    )
                )
            score -= 20

    if "faq" in present:
        findings.append(Finding(level="info", text=f"Раздел FAQ найден: {details['faq']['url']}", fix="", hours=0.0))

    score = max(0, min(100, score))
    if missing_shop:
        status = "critical"
    elif missing_all:
        status = "warning"
    else:
        status = "ok"

    if status == "ok":
        findings.append(Finding(level="ok", text="Все ключевые страницы доверия присутствуют и содержательны", fix=""))

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "is_shop": is_shop,
            "found": {t: _absolute(h, ctx.base) for t, h in found.items()},
            "present": sorted(present),
            "missing_required": missing_all,
            "missing_shop": missing_shop,
            "details": details,
        },
    )


# ===========================================================================
# Проверка 2: контактные данные и реквизиты
# ===========================================================================
@check(id="contact_signals", title="Контактные данные и реквизиты компании", category=CATEGORY)
async def contact_signals(ctx: AuditContext) -> CheckResult:
    check_id = "contact_signals"
    title = "Контактные данные и реквизиты компании"

    home = await ctx.home()
    if home is None:
        return _skipped(check_id, title, "HTML главной страницы", "Проверить доступность сайта и повторить аудит")

    html = home.text or ""
    source = ctx.url
    links = classify_trust_links(collect_links(html, ctx.base))
    contacts_href = links.get("contacts")
    if contacts_href:
        contacts_url = _absolute(contacts_href, ctx.base)
        page = await ctx.get(contacts_url) if contacts_url else None
        if page is not None and page.status_code == 200 and (page.text or "").strip():
            html = page.text or ""
            source = contacts_url

    signals = detect_contact_signals(html)

    findings: List[Finding] = []
    score = 100

    if signals["phone"]:
        findings.append(Finding(level="info", text=f"Телефон найден: {', '.join(signals['phones'][:3])}", fix="", hours=0.0))
    else:
        findings.append(
            Finding(
                level="warning",
                text=f"На странице контактов не найден телефон (источник: {source})",
                fix="Добавить кликабельный телефон вида <a href=\"tel:+74951234567\"> и указать режим работы",
                hours=0.5,
            )
        )
        score -= 20

    if signals["email"]:
        findings.append(Finding(level="info", text=f"E-mail найден: {', '.join(signals['emails'][:3])}", fix="", hours=0.0))
    else:
        findings.append(
            Finding(
                level="warning",
                text=f"На странице контактов не найден e-mail (источник: {source})",
                fix="Добавить адрес электронной почты ссылкой mailto: для обращений клиентов",
                hours=0.5,
            )
        )
        score -= 20

    if signals["address"]:
        findings.append(Finding(level="info", text=f"Физический адрес найден ({signals['address_source'] or 'по разметке/тексту'})", fix="", hours=0.0))
    else:
        findings.append(
            Finding(
                level="warning",
                text=f"Не найден физический адрес компании (источник: {source})",
                fix="Указать фактический адрес с индексом и разметить его JSON-LD PostalAddress или микроразметкой",
                hours=1.0,
            )
        )
        score -= 20

    if signals["legal"]:
        findings.append(Finding(level="info", text="Юридические реквизиты найдены: " + "; ".join(signals["legal_details"]), fix="", hours=0.0))
    else:
        findings.append(
            Finding(
                level="info",
                text="Не найдены юридические реквизиты (ИНН/ОГРН/КПП/VAT/Reg. no.) — не критично, но повышает доверие",
                fix="Добавить ИНН, ОГРН и название юрлица в футер или на страницу контактов",
                hours=0.5,
            )
        )

    if signals["social"]:
        findings.append(Finding(level="info", text="Соцсети и мессенджеры найдены: " + ", ".join(signals["social_links"]), fix="", hours=0.0))
    else:
        findings.append(
            Finding(level="info", text="Ссылки на соцсети и мессенджеры не найдены", fix="Добавить ссылки на активные соцсети и мессенджеры (Telegram/WhatsApp)", hours=0.5)
        )

    if signals["map"]:
        findings.append(Finding(level="info", text="Карта (embed) на странице найдена", fix="", hours=0.0))
    else:
        findings.append(
            Finding(level="info", text="Встроенная карта не найдена", fix="Добавить интерактивную карту (Яндекс.Карты/Google Maps/2GIS) с адресом офиса", hours=0.5)
        )

    score = max(0, min(100, score))
    status = _status_from_score(score)
    if status == "ok":
        findings.append(Finding(level="ok", text="Основные контактные данные (телефон, e-mail, адрес) присутствуют", fix=""))

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={"source": source, **signals},
    )


# ===========================================================================
# Проверка 3: авторство блога
# ===========================================================================
_BLOG_KEYWORDS = ("blog", "блог", "статьи", "статья", "news", "новости", "journal", "журнал", "articles", "novice")


@check(id="authorship", title="Авторство и даты публикации статей", category=CATEGORY)
async def authorship(ctx: AuditContext) -> CheckResult:
    check_id = "authorship"
    title = "Авторство и даты публикации статей"

    home = await ctx.home()
    if home is None:
        return _skipped(check_id, title, "HTML главной страницы", "Проверить доступность сайта и повторить аудит")

    html = home.text or ""
    links = collect_links(html, ctx.base)
    blog_href = find_section_link(links, _BLOG_KEYWORDS)
    if not blog_href:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=[Finding(level="info", text="Раздел блога или статей не найден — проверка авторства пропущена", fix="")],
            raw={"blog_url": None},
        )

    blog_url = _absolute(blog_href, ctx.base)
    blog = await ctx.get(blog_url) if blog_url else None
    if blog is None or blog.status_code != 200:
        return _skipped(check_id, title, "страницу блога", "Проверить доступность раздела блога и повторить аудит")

    post_url = ""
    for href, _anchor in collect_links(blog.text or "", ctx.base):
        candidate = _absolute(href, ctx.base)
        if not candidate.startswith(("http://", "https://")):
            continue
        if urlparse(candidate).netloc != urlparse(ctx.base).netloc:
            continue
        if looks_like_post_url(candidate, blog_url):
            post_url = candidate
            break

    if not post_url:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=50,
            findings=[
                Finding(
                    level="warning",
                    text=f"В разделе блога ({blog_url}) не найдена ни одна статья для проверки авторства",
                    fix="Убедиться, что анонсы статей ведут на отдельные страницы с автором и датой публикации",
                    hours=1.0,
                )
            ],
            raw={"blog_url": blog_url, "post_url": None},
        )

    post = await ctx.get(post_url)
    if post is None or post.status_code != 200:
        return _skipped(check_id, title, "страницу статьи", "Проверить доступность статьи блога и повторить аудит")

    data = analyze_authorship(post.text or "")

    findings: List[Finding] = []
    score = 100

    if data["author"]:
        findings.append(Finding(level="info", text=f"Автор статьи указан: «{_truncate(data['author'], 80)}» ({', '.join(data['author_sources'])})", fix="", hours=0.0))
    else:
        findings.append(
            Finding(
                level="warning",
                text=f"На странице статьи не указан автор: {post_url}",
                fix="Добавить имя и регалии автора (meta author, rel=author или JSON-LD author) — ключевой сигнал E-E-A-T",
                hours=1.5,
            )
        )
        score -= 30

    if data["published"]:
        findings.append(Finding(level="info", text=f"Дата публикации указана: {data['published']}", fix="", hours=0.0))
    else:
        findings.append(
            Finding(
                level="warning",
                text=f"На странице статьи не указана дата публикации: {post_url}",
                fix="Проставить дату публикации: микроразметку <time datetime> или JSON-LD datePublished",
                hours=1.0,
            )
        )
        score -= 20

    if data["modified"]:
        findings.append(Finding(level="info", text=f"Дата обновления указана: {data['modified']}", fix="", hours=0.0))
    else:
        findings.append(
            Finding(
                level="info",
                text="Дата обновления статьи не указана",
                fix="Добавить dateModified в JSON-LD и отображать «Обновлено: …» для актуальности материала",
                hours=0.5,
            )
        )

    if data["author_bio"]:
        findings.append(Finding(level="info", text="Есть ссылка на профиль/биографию автора", fix="", hours=0.0))
    else:
        findings.append(
            Finding(
                level="info",
                text="Ссылка на страницу автора с биографией не найдена",
                fix="Сделать имя автора ссылкой на страницу с биографией и опытом — усиливает экспертность",
                hours=1.0,
            )
        )

    score = max(0, min(100, score))
    status = _status_from_score(score)
    if status == "ok":
        findings.append(Finding(level="ok", text="Статья содержит автора и дату публикации", fix=""))

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={"blog_url": blog_url, "post_url": post_url, **data},
    )


# ===========================================================================
# Проверка 4: отзывы и социальные доказательства
# ===========================================================================
_REVIEW_TEXT_MARKERS = (
    "отзыв",
    "reviews",
    "review",
    "trustpilot",
    "яндекс отзыв",
    "яндекс.отзыв",
    "рейтинг",
    "rating",
    "оценк",
    "мнение клиентов",
    "mnenja",
    "recenzij",
    "рекомендац",
)


def _collect_review_evidence(html: str) -> Dict[str, Any]:
    """Чистая функция: признаки отзывов и рейтингов на странице."""
    raw = html or ""
    low = raw.lower()
    entities, _ = extract_jsonld(raw)
    schema_types: List[str] = []
    for entity in entities:
        for t in entity_types(entity):
            if t in ("AggregateRating", "Review", "Rating") and t not in schema_types:
                schema_types.append(t)
    markers = [m for m in _REVIEW_TEXT_MARKERS if m in low]
    return {"schema_types": schema_types, "text_markers": sorted(set(markers))}


@check(id="reviews_social_proof", title="Отзывы и социальные доказательства", category=CATEGORY)
async def reviews_social_proof(ctx: AuditContext) -> CheckResult:
    check_id = "reviews_social_proof"
    title = "Отзывы и социальные доказательства"

    resp = await ctx.home()
    if resp is None:
        return _skipped(check_id, title, "HTML главной страницы", "Проверить доступность сайта и повторить аудит")

    html = resp.text or ""
    if html:
        pass

    checked: List[Dict[str, Any]] = [{"url": ctx.url, "kind": "home"}]

    product_url = ""
    if _is_shop(html):
        prod_links = find_product_links(html, ctx.base, limit=1)
        if prod_links:
            product_url = prod_links[0]
            page = await ctx.get(product_url)
            if page is not None and page.status_code == 200:
                checked.append({"url": product_url, "kind": "product", "html": page.text or ""})

    findings: List[Finding] = []
    summary: List[Dict[str, Any]] = []
    best_schema: List[str] = []
    best_markers: List[str] = []

    for item in checked:
        page_html = item.get("html") or html
        evidence = _collect_review_evidence(page_html)
        summary.append({"url": item["url"], "kind": item["kind"], **evidence})
        for t in evidence["schema_types"]:
            if t not in best_schema:
                best_schema.append(t)
        for m in evidence["text_markers"]:
            if m not in best_markers:
                best_markers.append(m)

    if best_schema:
        findings.append(
            Finding(
                level="info",
                text="Найдена разметка отзывов/рейтинга: " + ", ".join(best_schema),
                fix="Поддерживать разметку в актуальном состоянии и синхронизировать её с реальными отзывами",
                hours=0.0,
            )
        )
    if best_markers:
        findings.append(
            Finding(
                level="info",
                text="Найдены блоки отзывов на странице (упоминания: " + ", ".join(best_markers[:8]) + ")",
                fix="Поддерживать свежесть отзывов и отвечать на них — это усиливает социальное доказательство",
                hours=0.0,
            )
        )

    if not best_schema and not best_markers:
        findings.append(
            Finding(
                level="info",
                text="На главной и карточке товара не найдены отзывы, рейтинг или социальные доказательства",
                fix="Добавить блок отзывов с рейтингом и разметить его schema.org AggregateRating/Review",
                hours=3.0,
            )
        )

    findings.append(
        Finding(
            level="info",
            text=f"Проверено страниц на признаки отзывов: {len(checked)}",
            fix="",
            hours=0.0,
        )
    )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="ok",
        score=100,
        findings=findings,
        raw={"checked": summary, "schema_types": best_schema, "text_markers": best_markers, "product_url": product_url},
    )
