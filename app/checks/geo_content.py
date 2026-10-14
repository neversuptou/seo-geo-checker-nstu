from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Dict, List

from selectolax.lexbor import LexborHTMLParser

from app.core import AuditContext, CheckResult, Finding
from app.registry import check

CATEGORY = "GEO / AI"

# --- AI / search bots ------------------------------------------------------
# (name, user-agent, is_ai). Google-Extended опознаётся по UA Googlebot.
AI_BOTS: list[tuple[str, str, bool]] = [
    (
        "GPTBot",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot",
        True,
    ),
    (
        "OAI-SearchBot",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",
        True,
    ),
    (
        "ClaudeBot",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ClaudeBot/1.0; +claudebot@anthropic.com",
        True,
    ),
    (
        "PerplexityBot",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot",
        True,
    ),
    (
        "Google-Extended",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        True,
    ),
    (
        "YandexBot",
        "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
        False,
    ),
    (
        "Bytespider",
        "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)",
        True,
    ),
    (
        "CCBot",
        "Mozilla/5.0 (compatible; CCBot/2.0; +https://commoncrawl.org/faq/)",
        False,
    ),
]

# Признаки анти-бот заглушек / challenge-страниц.
CHALLENGE_MARKERS = [
    "just a moment",
    "checking your browser",
    "attention required",
    "cf-chl",
    "cf_chl",
    "enable javascript and cookies to continue",
    "ddos protection",
    "captcha",
    "recaptcha",
    "hcaptcha",
    "проверка браузера",
    "включите javascript",
    "доступ ограничен",
]

WORD_RE = re.compile(r"[0-9A-Za-zА-Яа-яЁё]+")


# ==========================================================================
# 1. Доступ для AI-ботов
# ==========================================================================
def _looks_like_challenge(body: str) -> str | None:
    low = body[:20000].lower()
    for marker in CHALLENGE_MARKERS:
        if marker in low:
            return marker
    return None


async def _fetch_bot(ctx: AuditContext, name: str, ua: str) -> Dict[str, Any]:
    resp = await ctx.get(ctx.url, headers={"User-Agent": ua, "Accept": "text/html,*/*"})
    if resp is None:
        return {"name": name, "status": None, "size": 0, "blocked": True, "reason": "нет ответа (сетевая ошибка/таймаут)"}
    body = resp.text or ""
    challenge = _looks_like_challenge(body)
    entry: Dict[str, Any] = {
        "name": name,
        "status": resp.status_code,
        "size": len(resp.content),
        "final_url": str(resp.url),
        "challenge": challenge,
        "blocked": False,
        "reason": "",
    }
    if resp.status_code in (401, 403, 429) or resp.status_code >= 500:
        entry["blocked"] = True
        entry["reason"] = f"статус {resp.status_code}"
    elif challenge:
        entry["blocked"] = True
        entry["reason"] = f"страница-заглушка ({challenge})"
    return entry


@check(id="ai_bot_access", title="Доступ для AI-краулеров", category=CATEGORY)
async def ai_bot_access(ctx: AuditContext) -> CheckResult:
    browser = await ctx.home()
    if browser is None:
        return CheckResult(
            id="ai_bot_access",
            title="Доступ для AI-краулеров",
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=[Finding(
                level="warning",
                text="Не удалось получить главную страницу браузерным User-Agent — сравнение доступа ботов невозможно",
                fix="Убедиться, что сайт доступен и отвечает на обычные запросы",
                hours=1.0,
            )],
            raw={"browser": None},
        )

    browser_size = len(browser.content)
    results = await asyncio.gather(*[_fetch_bot(ctx, name, ua) for name, ua, _ in AI_BOTS])

    findings: list[Finding] = []
    blocked: list[Dict[str, Any]] = []
    degraded: list[Dict[str, Any]] = []

    for entry in results:
        if entry["blocked"]:
            blocked.append(entry)
        elif browser_size > 0 and entry["size"] < browser_size * 0.3:
            entry["reason"] = f"тело ответа {entry['size']} Б — менее 30% от браузерного ({browser_size} Б)"
            degraded.append(entry)

    for entry in blocked:
        findings.append(Finding(
            level="critical",
            text=f"{entry['name']} не получает контент: {entry['reason']}",
            fix=(
                f"Разрешить {entry['name']} в правилах сервера/WAF и robots.txt (User-Agent: {entry['name']}). "
                "Для Cloudflare отключить Bot Fight Mode / managed challenge для этого бота"
            ),
            hours=2.0,
        ))
    for entry in degraded:
        findings.append(Finding(
            level="warning",
            text=f"{entry['name']} получает урезанный контент: {entry['reason']}",
            fix=f"Проверить серверные правила и CDN — {entry['name']} должен получать ту же страницу, что и браузер",
            hours=1.5,
        ))

    total = len(results)
    blocked_n = len(blocked)
    degraded_n = len(degraded)

    if blocked_n == 0 and degraded_n == 0:
        status = "ok"
        score = 100
        findings.append(Finding(level="ok", text=f"Все {total} AI/поисковых краулеров получают контент как браузер"))
    elif blocked_n >= max(3, total // 2):
        status = "critical"
        score = max(0, int(round(100 * (total - blocked_n) / total)))
    else:
        status = "warning"
        score = max(10, int(round(100 * (total - blocked_n) / total)) - 5 * degraded_n)

    return CheckResult(
        id="ai_bot_access",
        title="Доступ для AI-краулеров",
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "browser_size": browser_size,
            "browser_status": browser.status_code,
            "total": total,
            "blocked_count": blocked_n,
            "degraded_count": degraded_n,
            "bots": results,
        },
    )


# ==========================================================================
# 2. Контент без JavaScript
# ==========================================================================
def analyze_no_js(html: str) -> Dict[str, Any]:
    """Чистая функция: анализирует HTML без выполнения JS."""
    tree = LexborHTMLParser(html or "")

    noscript_nodes = tree.css("noscript")
    noscript_text = " ".join(n.text(separator=" ", strip=True) for n in noscript_nodes).lower()
    noscript_mentions_js = bool(
        re.search(r"(enable javascript|включите javascript|включить javascript|javascript (is )?disabled|требуется javascript)", noscript_text)
    )

    # убрать неиндексируемое до подсчёта слов
    for node in list(tree.css("script, style, noscript, template")):
        node.decompose()

    title_node = tree.css_first("title")
    h1_node = tree.css_first("h1")
    title = title_node.text(strip=True) if title_node else ""
    h1 = h1_node.text(strip=True) if h1_node else ""

    body = tree.body or tree.root
    body_text = body.text(separator=" ", strip=True) if body else ""
    words = len(WORD_RE.findall(body_text))

    empty_spa_containers: List[str] = []
    for sel in ("#root", "#app", "#__next", "#app-root", "#svelte"):
        node = tree.css_first(sel)
        if node is not None and len(node.text(strip=True)) < 20:
            empty_spa_containers.append(sel)

    spa_signs: List[str] = []
    if empty_spa_containers:
        spa_signs.append("Пустые контейнеры SPA: " + ", ".join(empty_spa_containers))
    if words < 150:
        spa_signs.append(f"Мало текста в исходном HTML: {words} слов (< 150)")
    if noscript_mentions_js:
        spa_signs.append("В <noscript> есть требование включить JavaScript")

    return {
        "words": words,
        "title": title,
        "h1": h1,
        "has_title": bool(title),
        "has_h1": bool(h1),
        "empty_spa_containers": empty_spa_containers,
        "noscript_mentions_js": noscript_mentions_js,
        "spa_signs": spa_signs,
        "is_spa_likely": bool(empty_spa_containers) or words < 150 or noscript_mentions_js,
    }


@check(id="content_no_js", title="Контент доступен без JavaScript", category=CATEGORY)
async def content_no_js(ctx: AuditContext) -> CheckResult:
    resp = await ctx.home()
    if resp is None:
        return CheckResult(
            id="content_no_js",
            title="Контент доступен без JavaScript",
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=[Finding(
                level="warning",
                text="Не удалось получить HTML главной страницы",
                fix="Проверить доступность сайта",
                hours=1.0,
            )],
            raw={},
        )

    data = analyze_no_js(resp.text or "")

    findings: list[Finding] = []
    if not data["has_title"]:
        findings.append(Finding(
            level="warning",
            text="В исходном HTML нет <title>",
            fix="Добавить уникальный <title> в серверный HTML",
            hours=1.0,
        ))
    if not data["has_h1"]:
        findings.append(Finding(
            level="warning",
            text="В исходном HTML нет <h1>",
            fix="Добавить один содержательный <h1> в серверный HTML",
            hours=1.0,
        ))

    if data["is_spa_likely"]:
        findings.append(Finding(
            level="critical",
            text="Контент недоступен без JS: " + "; ".join(data["spa_signs"]),
            fix="Внедрить SSR/SSG или prerender, чтобы AI-краулеры и поисковики видели текст без выполнения JavaScript",
            hours=16.0,
        ))
        status = "critical"
        score = 20 if data["words"] > 0 else 0
    elif data["words"] < 300:
        findings.append(Finding(
            level="warning",
            text=f"Текста в исходном HTML немного: {data['words']} слов",
            fix="Добавить серверный текст: описание, преимущества, FAQ",
            hours=4.0,
        ))
        status = "warning"
        score = 70
    else:
        findings.append(Finding(level="ok", text=f"Серверный HTML содержит {data['words']} слов, title и H1 на месте"))
        status = "ok"
        score = 100

    return CheckResult(
        id="content_no_js",
        title="Контент доступен без JavaScript",
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw=data,
    )


# ==========================================================================
# 3. Цитируемость в RAG / AI-ответах
# ==========================================================================
_TEXT_TAGS = {"p", "li", "td", "th", "blockquote", "figcaption", "dt", "dd", "pre", "h4", "h5", "h6"}


def analyze_sections(html: str) -> List[Dict[str, Any]]:
    """Чистая функция: делит контент по H2/H3 на секции и считает метрики."""
    tree = LexborHTMLParser(html or "")
    body = tree.body or tree.root
    if body is None:
        return []

    sections: List[Dict[str, Any]] = []
    current: Dict[str, Any] | None = None
    for node in body.traverse():
        tag = node.tag
        if tag in ("script", "style", "noscript", "template"):
            continue
        if tag in ("h2", "h3"):
            heading = node.text(strip=True)
            current = {
                "heading": heading,
                "level": int(tag[1]),
                "has_list": False,
                "has_table": False,
                "is_question": heading.rstrip().endswith("?"),
                "_parts": [],
            }
            sections.append(current)
            continue
        if current is None:
            continue
        if tag in ("ul", "ol"):
            current["has_list"] = True
        elif tag == "table":
            current["has_table"] = True
        elif tag in _TEXT_TAGS:
            current["_parts"].append(node.text(separator=" ", strip=True))

    for sec in sections:
        parts = [p for p in sec.pop("_parts") if p]
        text = " ".join(parts)
        sec["text"] = text
        sec["words"] = len(WORD_RE.findall(text))
        sec["numbers"] = len(re.findall(r"\d+", text))
    return sections


def detect_faq(html: str) -> Dict[str, Any]:
    """Чистая функция: ищет FAQ по заголовкам и schema.org FAQPage."""
    tree = LexborHTMLParser(html or "")
    heading_hit = False
    for node in tree.css("h1, h2, h3, h4"):
        h = node.text(strip=True).lower()
        if "faq" in h or "частые вопросы" in h or "часто задаваемые" in h or "вопросы и ответы" in h:
            heading_hit = True
            break
    schema_hit = "faqpage" in (html or "").lower()
    return {"heading": heading_hit, "schema": schema_hit, "present": heading_hit or schema_hit}


def detect_dates_author(html: str) -> Dict[str, Any]:
    """Чистая функция: ищет даты публикации/обновления и автора."""
    raw = html or ""
    low = raw.lower()
    tree = LexborHTMLParser(raw)

    published = modified = ""
    for prop, key in (
        ("article:published_time", "published"),
        ("article:modified_time", "modified"),
    ):
        node = tree.css_first(f'meta[property="{prop}"]') or tree.css_first(f'meta[name="{prop}"]')
        if node is not None:
            content = node.attributes.get("content") or ""
            if key == "published":
                published = content
            else:
                modified = content

    has_time_element = tree.css_first("time[datetime]") is not None
    schema_published = '"datepublished"' in low
    schema_modified = '"datemodified"' in low

    author_node = tree.css_first('meta[name="author"]') or tree.css_first('link[rel="author"]')
    author = (author_node.attributes.get("content") or author_node.attributes.get("href") or "") if author_node else ""
    schema_author = '"author"' in low

    return {
        "published": published,
        "modified": modified,
        "has_time_element": has_time_element,
        "schema_published": schema_published,
        "schema_modified": schema_modified,
        "has_date": bool(published or modified or has_time_element or schema_published or schema_modified),
        "author": author,
        "schema_author": schema_author,
        "has_author": bool(author or schema_author),
    }


@check(id="rag_citability", title="Цитируемость для RAG и AI-ответов", category=CATEGORY)
async def rag_citability(ctx: AuditContext) -> CheckResult:
    resp = await ctx.home()
    if resp is None:
        return CheckResult(
            id="rag_citability",
            title="Цитируемость для RAG и AI-ответов",
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=[Finding(
                level="warning",
                text="Не удалось получить HTML главной страницы",
                fix="Проверить доступность сайта",
                hours=1.0,
            )],
            raw={},
        )

    html = resp.text or ""
    sections = analyze_sections(html)
    faq = detect_faq(html)
    signals = detect_dates_author(html)

    findings: list[Finding] = []
    score = 100

    if not sections:
        findings.append(Finding(
            level="critical",
            text="Страница не разбита на смысловые секции заголовками H2/H3",
            fix="Разбить контент на секции с подзаголовками H2/H3 по 40–300 слов — так AI-системы извлекают готовые фрагменты",
            hours=6.0,
        ))
        score -= 40

    weak: List[Dict[str, Any]] = []
    good = 0
    for sec in sections:
        issues = []
        w = sec["words"]
        if w < 40:
            issues.append("мало слов (< 40)")
        elif w > 300:
            issues.append("слишком длинная секция (> 300)")
        if not sec["has_list"] and not sec["has_table"]:
            issues.append("нет списка или таблицы")
        if sec["numbers"] == 0:
            issues.append("нет цифр/фактов")
        if issues:
            weak.append({"heading": sec["heading"], "words": w, "issues": issues})
        else:
            good += 1

    if sections:
        ideal_ratio = good / len(sections)
        if ideal_ratio < 0.5:
            findings.append(Finding(
                level="warning",
                text=f"Большинство секций неоптимальны для извлечения: {len(weak)} из {len(sections)}",
                fix="Привести секции к 40–300 словам, добавить списки/таблицы и конкретные цифры и факты",
                hours=6.0,
            ))
            score -= 25
        if weak:
            top = ", ".join(f"«{w['heading']}» ({w['words']} сл.)" for w in weak[:3] if w["heading"]) or ""
            findings.append(Finding(
                level="info",
                text=(f"Слабые секции ({len(weak)}): {top}" if top else f"Слабых секций: {len(weak)}"),
            ))

    # вопросные заголовки
    question_headings = sum(1 for s in sections if s["is_question"])
    if sections and question_headings == 0:
        findings.append(Finding(
            level="warning",
            text="Нет заголовков в форме вопроса — хуже попадание в AI-ответы",
            fix="Переформулировать часть H2/H3 как вопросы пользователей («Что такое…», «Сколько стоит…»)",
            hours=2.0,
        ))
        score -= 10

    if not faq["present"]:
        findings.append(Finding(
            level="warning",
            text="Нет блока FAQ (вопрос-ответ) и разметки FAQPage",
            fix="Добавить блок FAQ с 5–10 вопросами и schema.org FAQPage — AI-системы часто цитируют такие фрагменты",
            hours=5.0,
        ))
        score -= 10

    if not signals["has_date"]:
        findings.append(Finding(
            level="warning",
            text="Не найдены даты публикации/обновления",
            fix="Проставлять published/modified (meta article:*, schema datePublished/dateModified) — свежесть повышает цитируемость",
            hours=2.0,
        ))
        score -= 8

    if not signals["has_author"]:
        findings.append(Finding(
            level="warning",
            text="Не найден автор материала",
            fix="Указать автора (meta author, schema author, блок «автор») — сигнал E-E-A-T",
            hours=2.0,
        ))
        score -= 8

    score = max(0, min(100, score))
    if not findings:
        findings.append(Finding(level="ok", text="Структура страницы удобна для извлечения AI-системами"))

    if score >= 80:
        status = "ok"
    elif score >= 40:
        status = "warning"
    else:
        status = "critical"

    return CheckResult(
        id="rag_citability",
        title="Цитируемость для RAG и AI-ответов",
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "sections_count": len(sections),
            "ideal_sections": good,
            "weak_sections": weak,
            "question_headings": question_headings,
            "faq": faq,
            "dates_author": signals,
        },
    )


# ==========================================================================
# 4. Бренд-сущность (JSON-LD Organization)
# ==========================================================================
_ORG_TYPES = {
    "organization",
    "localbusiness",
    "onlinestore",
    "corporation",
    "store",
    "restaurant",
    "medicalorganization",
    "educationalorganization",
}
_SOCIAL_HOSTS = {
    "vk.com": "VK",
    "t.me": "Telegram",
    "telegram.me": "Telegram",
    "ok.ru": "OK",
    "youtube.com": "YouTube",
    "youtu.be": "YouTube",
    "dzen.ru": "Дзен",
    "zen.yandex.ru": "Дзен",
    "twitter.com": "X/Twitter",
    "x.com": "X/Twitter",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "linkedin.com": "LinkedIn",
    "github.com": "GitHub",
    "habr.com": "Habr",
    "pinterest.com": "Pinterest",
}


def _iter_jsonld_objects(html: str) -> List[Dict[str, Any]]:
    tree = LexborHTMLParser(html or "")
    objects: List[Dict[str, Any]] = []
    for node in tree.css('script[type="application/ld+json"]'):
        raw = node.text() or ""
        if not raw.strip():
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue
        stack = [data]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                if "@graph" in item and isinstance(item["@graph"], list):
                    stack.extend(item["@graph"])
                objects.append(item)
            elif isinstance(item, list):
                stack.extend(item)
    return objects


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _type_names(node: Dict[str, Any]) -> List[str]:
    return [str(t).lower() for t in _as_list(node.get("@type"))]


def extract_brand(html: str) -> Dict[str, Any]:
    """Чистая функция: достаёт данные бренда из JSON-LD Organization/LocalBusiness/OnlineStore."""
    org_nodes: List[Dict[str, Any]] = []
    for obj in _iter_jsonld_objects(html):
        if any(t in _ORG_TYPES for t in _type_names(obj)):
            org_nodes.append(obj)

    if not org_nodes:
        return {
            "found": False,
            "types": [],
            "name": "",
            "logo": "",
            "url": "",
            "same_as": [],
            "socials": {},
            "wikidata": False,
            "wikipedia": False,
            "contact_point": False,
            "telephone": "",
            "email": "",
            "address": "",
        }

    node = org_nodes[0]
    same_as = [str(u) for u in _as_list(node.get("sameAs")) if u]

    socials: Dict[str, str] = {}
    wikidata = wikipedia = False
    for url in same_as:
        low = url.lower()
        if "wikidata.org" in low:
            wikidata = True
        if "wikipedia.org" in low:
            wikipedia = True
        for host, label in _SOCIAL_HOSTS.items():
            if host in low:
                socials[label] = url
                break

    contact_points = _as_list(node.get("contactPoint"))
    telephone = ""
    email = ""
    for cp in contact_points:
        if isinstance(cp, dict):
            telephone = telephone or str(cp.get("telephone") or "")
            email = email or str(cp.get("email") or "")
    telephone = telephone or str(node.get("telephone") or "")
    email = email or str(node.get("email") or "")

    address = node.get("address")
    if isinstance(address, dict):
        address_str = ", ".join(str(v) for v in address.values() if v)
    elif address:
        address_str = str(address)
    else:
        address_str = ""

    logo = node.get("logo")
    if isinstance(logo, dict):
        logo = logo.get("url") or logo.get("@id") or ""
    logo = str(logo or "")

    url = node.get("url")
    if isinstance(url, dict):
        url = url.get("@id") or url.get("url") or ""
    url = str(url or "")

    return {
        "found": True,
        "types": [str(t) for t in _as_list(node.get("@type"))],
        "name": str(node.get("name") or ""),
        "logo": logo,
        "url": url,
        "same_as": same_as,
        "socials": socials,
        "wikidata": wikidata,
        "wikipedia": wikipedia,
        "contact_point": bool(contact_points),
        "telephone": telephone,
        "email": email,
        "address": address_str,
    }


@check(id="brand_entity", title="Бренд как сущность (Organization)", category=CATEGORY)
async def brand_entity(ctx: AuditContext) -> CheckResult:
    resp = await ctx.home()
    if resp is None:
        return CheckResult(
            id="brand_entity",
            title="Бренд как сущность (Organization)",
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=[Finding(
                level="warning",
                text="Не удалось получить HTML главной страницы",
                fix="Проверить доступность сайта",
                hours=1.0,
            )],
            raw={},
        )

    brand = extract_brand(resp.text or "")
    findings: list[Finding] = []
    score = 100

    if not brand["found"]:
        findings.append(Finding(
            level="critical",
            text="Не найдена разметка Organization / LocalBusiness / OnlineStore в JSON-LD",
            fix="Добавить JSON-LD Organization с name, url, logo, sameAs и contactPoint — без сущности бренда AI не связывает сайт с компанией",
            hours=4.0,
        ))
        return CheckResult(
            id="brand_entity",
            title="Бренд как сущность (Organization)",
            category=CATEGORY,
            status="critical",
            score=0,
            findings=findings,
            raw=brand,
        )

    if not brand["name"]:
        findings.append(Finding(
            level="warning",
            text="В Organization не указано name (название бренда)",
            fix="Добавить поле name с точным юридическим/публичным названием",
            hours=0.5,
        ))
        score -= 15

    if not brand["url"]:
        findings.append(Finding(
            level="warning",
            text="В Organization не указан url сайта",
            fix="Добавить url — канонический адрес сайта",
            hours=0.5,
        ))
        score -= 10

    if not brand["logo"]:
        findings.append(Finding(
            level="warning",
            text="В Organization не указан logo",
            fix="Добавить logo (URL изображения не менее 112×112)",
            hours=1.0,
        ))
        score -= 12

    if not brand["same_as"]:
        findings.append(Finding(
            level="warning",
            text="В Organization нет sameAs — профилей бренда во внешних источниках",
            fix="Заполнить sameAs ссылками на соцсети, Wikidata и Wikipedia для связывания сущности",
            hours=1.5,
        ))
        score -= 15
    else:
        if not brand["socials"]:
            findings.append(Finding(
                level="info",
                text="В sameAs нет узнаваемых соцсетей",
                fix="Добавить ссылки на профили в соцсетях и мессенджерах",
                hours=0.5,
            ))
        if not (brand["wikidata"] or brand["wikipedia"]):
            findings.append(Finding(
                level="warning",
                text="В sameAs нет ссылок на Wikidata/Wikipedia",
                fix="Связать бренд с Wikidata (и, при значимости, Wikipedia) — сильный сигнал сущности для AI",
                hours=2.0,
            ))
            score -= 10

    if not brand["contact_point"]:
        findings.append(Finding(
            level="warning",
            text="В Organization нет contactPoint",
            fix="Добавить contactPoint с telephone/email и contactType",
            hours=1.0,
        ))
        score -= 10

    if not (brand["telephone"] or brand["email"]):
        findings.append(Finding(
            level="warning",
            text="Не указаны контакты бренда (telephone/email)",
            fix="Добавить telephone и email в Organization/contactPoint",
            hours=0.5,
        ))
        score -= 8

    if not brand["address"]:
        findings.append(Finding(
            level="warning",
            text="В Organization не указан адрес (address)",
            fix="Добавить PostalAddress (addressLocality, streetAddress, postalCode) для локального бизнеса",
            hours=1.0,
        ))
        score -= 8

    score = max(0, min(100, score))
    if not findings:
        findings.append(Finding(level="ok", text="Организация описана в JSON-LD: name, url, logo, sameAs, контакты"))

    if score >= 80:
        status = "ok"
    elif score >= 40:
        status = "warning"
    else:
        status = "critical"

    return CheckResult(
        id="brand_entity",
        title="Бренд как сущность (Organization)",
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw=brand,
    )
