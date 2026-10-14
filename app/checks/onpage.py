"""On-page проверки: метатеги, заголовки, дубли, изображения, ссылки, W3C.

Проверки:
- meta_tags                — title, description, keywords, canonical, lang, viewport, charset, favicon
- headings                 — единственный H1, качество H1, структура H1–H6, мусорные заголовки
- title_desc_h1_duplicates — точные и близкие дубли между title / description / H1
- images_alt               — изображения без alt / с пустым alt
- links                    — внутренние/внешние/nofollow, домены, пустые анкоры и битые ссылки
- w3c_validation           — валидация HTML через W3C Nu HTML Checker

Чистая логика парсинга вынесена в отдельные синхронные функции без сети,
поэтому её можно покрывать юнит-тестами:
`parse_meta_tags`, `analyze_headings`, `junk_heading_reason`, `starts_fragment_like`,
`h1_problem`, `find_duplicates`, `analyze_images`, `analyze_links`, `summarize_w3c`.
"""
from __future__ import annotations

import asyncio
import difflib
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from selectolax.lexbor import LexborHTMLParser

from app.core import BROWSER_UA, AuditContext, CheckResult, Finding
from app.registry import check

CATEGORY = "On-page"

# Эндпоинт W3C Nu HTML Checker с JSON-выводом.
W3C_ENDPOINT = "https://validator.w3.org/nu/?out=json"

# Лимиты проверок ссылок.
LINKS_LIMIT = 50
LINKS_CONCURRENCY = 8

# Минимальная и максимальная длина title / description.
TITLE_MIN, TITLE_MAX = 30, 65
DESC_MIN, DESC_MAX = 70, 160

# Схемы, которые игнорируются при подсчёте http(s)-ссылок.
_SKIP_SCHEMES = ("mailto:", "tel:")
# Схемы/значения href, которые считаются ссылкой-заглушкой.
_PLACEHOLDER_SCHEMES = ("javascript:", "data:", "blob:")


# ===========================================================================
# Чистые функции: заголовки
# ===========================================================================
_WORD_RE = re.compile(r"[0-9A-Za-zА-Яа-яЁё]+")
_NUM_RE = re.compile(r"^\d+$")

# Слова-заглушки, которые не являются осмысленным заголовком.
_JUNK_WORDS = {
    "hello",
    "hi",
    "test",
    "tests",
    "lorem",
    "ipsum",
    "foo",
    "bar",
    "baz",
    "untitled",
    "no title",
    "тест",
    "тесты",
    "привет",
    "заголовок",
    "заголовок 1",
    "текст",
    "без названия",
    "h1",
    "h2",
    "h3",
}

# Служебные слова/предлоги, с которых не должен начинаться H1.
_LOWERCASE_START_WORDS = {
    "to",
    "and",
    "of",
    "or",
    "the",
    "a",
    "an",
    "for",
    "with",
    "in",
    "on",
    "at",
    "by",
    "from",
    "as",
    "в",
    "и",
    "с",
    "со",
    "на",
    "по",
    "для",
    "из",
    "к",
    "ко",
    "о",
    "об",
    "обо",
    "от",
    "до",
    "при",
    "за",
    "под",
    "над",
    "но",
    "а",
    "или",
    "что",
    "как",
    "это",
    "же",
    "ли",
    "бы",
}


def junk_heading_reason(text: str) -> Optional[str]:
    """Вернуть причину, почему заголовок считается мусорным, или None если он нормальный."""
    t = (text or "").strip()
    if not t:
        return "пустой заголовок"
    if len(t) < 3:
        return "слишком короткий (меньше 3 символов)"
    if _NUM_RE.match(t):
        return "состоит только из цифр"

    low = t.lower()
    if low in _JUNK_WORDS:
        return f"слово-заглушка «{t}»"

    words = _WORD_RE.findall(low)
    if words and words[0] in _JUNK_WORDS:
        return f"слово-заглушка «{words[0]}»"
    return None


def is_junk_heading(text: str) -> bool:
    """Является ли заголовок мусорным (пустой, короткий, только цифры, слово-заглушка)."""
    return junk_heading_reason(text) is not None


def starts_fragment_like(text: str) -> bool:
    """Похож ли текст на обрывок: начинается со строчной буквы или служебного слова."""
    t = (text or "").strip()
    if not t:
        return True

    first_alpha = next((ch for ch in t if ch.isalpha()), "")
    if first_alpha and first_alpha.islower():
        return True

    words = _WORD_RE.findall(t)
    if words and words[0].lower() in _LOWERCASE_START_WORDS:
        return True
    return False


def h1_problem(text: str) -> Optional[str]:
    """Описать проблему с H1 или вернуть None, если заголовок нормальный."""
    t = (text or "").strip()
    if not t:
        return "H1 пустой"
    reason = junk_heading_reason(t)
    if reason:
        return f"H1 выглядит как заглушка: {reason}"
    if starts_fragment_like(t):
        return "H1 начинается со строчной буквы или служебного слова — выглядит как обрывок текста"
    return None


def analyze_headings(html: str) -> Dict[str, Any]:
    """Чистая функция: анализ заголовков H1–H6.

    Возвращает:
      h1_count   — сколько H1 на странице;
      h1_text    — текст первого H1;
      h1_problem — текст проблемы с H1 (или None);
      outline    — список {"level", "text"} в порядке документа;
      has_skipped_levels — есть ли пропуск уровня (например H2 → H4);
      skipped    — список пропусков {"from", "to", "text"};
      junk       — список мусорных/пустых заголовков {"level", "text", "reason"};
    """
    tree = LexborHTMLParser(html or "")
    headings: List[Dict[str, Any]] = []
    for node in tree.css("h1, h2, h3, h4, h5, h6"):
        tag = node.tag or ""
        if len(tag) != 2 or not tag[1].isdigit():
            continue
        headings.append({"level": int(tag[1]), "text": node.text(separator=" ", strip=True)})

    h1s = [h for h in headings if h["level"] == 1]
    h1_text = h1s[0]["text"] if h1s else ""

    skipped: List[Dict[str, Any]] = []
    prev_level: Optional[int] = None
    for h in headings:
        if prev_level is not None and h["level"] > prev_level + 1:
            skipped.append({"from": prev_level, "to": h["level"], "text": h["text"]})
        prev_level = h["level"]

    junk: List[Dict[str, Any]] = []
    for h in headings:
        reason = junk_heading_reason(h["text"])
        if reason:
            junk.append({"level": h["level"], "text": h["text"], "reason": reason})

    return {
        "h1_count": len(h1s),
        "h1_text": h1_text,
        "h1_problem": h1_problem(h1_text),
        "outline": headings,
        "has_skipped_levels": bool(skipped),
        "skipped": skipped,
        "junk": junk,
    }


# ===========================================================================
# Чистые функции: дубли title / description / H1
# ===========================================================================
_DUP_THRESHOLD = 0.9


def find_duplicates(title: str, description: str, h1: str) -> List[Dict[str, Any]]:
    """Чистая функция: точные и близкие (difflib > 0.9) дубли между title / description / H1."""
    pairs: List[Tuple[str, str, str, str]] = [
        ("title", "description", title, description),
        ("title", "H1", title, h1),
        ("description", "H1", description, h1),
    ]
    out: List[Dict[str, Any]] = []
    for a, b, x, y in pairs:
        x = (x or "").strip()
        y = (y or "").strip()
        if not x or not y:
            continue
        ratio = difflib.SequenceMatcher(None, x.lower(), y.lower()).ratio()
        if ratio > _DUP_THRESHOLD:
            out.append(
                {
                    "a": a,
                    "b": b,
                    "ratio": round(ratio, 3),
                    "exact": x.lower() == y.lower(),
                }
            )
    return out


# ===========================================================================
# Чистые функции: метатеги
# ===========================================================================
def parse_meta_tags(html: str, base: str = "") -> Dict[str, Any]:
    """Чистая функция: собрать title, description, keywords, canonical, lang, viewport, charset, favicon."""

    def absolute(href: str) -> str:
        if not href:
            return ""
        if base:
            return urljoin(base.rstrip("/") + "/", href)
        return href

    result: Dict[str, Any] = {
        "title": "",
        "description": "",
        "keywords": "",
        "canonical": "",
        "canonical_is_absolute": False,
        "lang": "",
        "viewport": "",
        "charset": "",
        "favicon": "",
        "favicon_source": "",
    }

    tree = LexborHTMLParser(html or "")

    title_node = tree.css_first("title")
    if title_node is not None:
        result["title"] = title_node.text(strip=True)

    html_node = tree.css_first("html")
    if html_node is not None:
        result["lang"] = (html_node.attributes.get("lang") or "").strip()

    for node in tree.css("meta"):
        attrs = node.attributes
        name = (attrs.get("name") or "").strip().lower()
        http_equiv = (attrs.get("http-equiv") or "").strip().lower()
        content = attrs.get("content") or ""

        if not result["charset"]:
            charset_attr = attrs.get("charset")
            if charset_attr:
                result["charset"] = charset_attr.strip()
            elif http_equiv == "content-type":
                m = re.search(r"charset=([\w\-]+)", content, flags=re.IGNORECASE)
                if m:
                    result["charset"] = m.group(1).strip()

        if name == "description" and not result["description"]:
            result["description"] = content.strip()
        elif name == "keywords" and not result["keywords"]:
            result["keywords"] = content.strip()
        elif name == "viewport" and not result["viewport"]:
            result["viewport"] = content.strip()

    for node in tree.css("link"):
        attrs = node.attributes
        rel = (attrs.get("rel") or "").lower()
        rel_tokens = rel.split()
        href = (attrs.get("href") or "").strip()
        if "canonical" in rel_tokens and not result["canonical"]:
            result["canonical"] = absolute(href)
        if "icon" in rel_tokens and not result["favicon"] and href:
            result["favicon"] = absolute(href)
            result["favicon_source"] = "link"

    result["canonical_is_absolute"] = result["canonical"].startswith(("http://", "https://"))
    return result


# ===========================================================================
# Чистые функции: изображения
# ===========================================================================
def _is_decorative(attrs: Dict[str, Any]) -> bool:
    """Изображение помечено как декоративное (role=presentation/none или aria-hidden=true)."""
    role = (attrs.get("role") or "").strip().lower()
    aria_hidden = (attrs.get("aria-hidden") or "").strip().lower()
    return role in ("presentation", "none") or aria_hidden == "true"


def analyze_images(html: str, base: str = "") -> Dict[str, Any]:
    """Чистая функция: подсчёт изображений без alt и с пустым alt (декоративные исключаются)."""
    tree = LexborHTMLParser(html or "")
    total = 0
    missing_alt = 0
    empty_alt = 0
    no_alt: List[str] = []

    for node in tree.css("img"):
        total += 1
        attrs = node.attributes
        if _is_decorative(attrs):
            continue

        src = (attrs.get("src") or attrs.get("data-src") or attrs.get("data-lazy-src") or "").strip()
        if base and src:
            src = urljoin(base.rstrip("/") + "/", src)

        alt = attrs.get("alt")
        if alt is None:
            missing_alt += 1
            if len(no_alt) < 20:
                no_alt.append(src)
        elif alt.strip() == "":
            empty_alt += 1
            if len(no_alt) < 20:
                no_alt.append(src)

    return {
        "total": total,
        "missing_alt": missing_alt,
        "empty_alt": empty_alt,
        "no_alt": no_alt,
    }


# ===========================================================================
# Чистые функции: ссылки
# ===========================================================================
def analyze_links(html: str, base: str = "") -> Dict[str, Any]:
    """Чистая функция: статистика ссылок и список уникальных URL для проверки.

    Возвращает:
      total, internal, external, nofollow — счётчики анкоров;
      external_domains — {домен: количество};
      empty_href       — анкоры без href / с пустым href;
      empty_text       — анкоры без текста;
      placeholder      — анкоры-заглушки (href="#", javascript:);
      unique_urls      — уникальные абсолютные http(s)-ссылки (для проверки доступности).
    """
    base_host = urlparse(base).netloc.lower() if base else ""

    total = internal = external = nofollow = 0
    domains: Dict[str, int] = {}
    empty_href: List[str] = []
    empty_text: List[str] = []
    placeholder: List[str] = []
    seen = set()
    unique_urls: List[str] = []

    tree = LexborHTMLParser(html or "")
    for node in tree.css("a"):
        attrs = node.attributes
        href = (attrs.get("href") or "").strip()
        rel = (attrs.get("rel") or "").lower()
        text = node.text(separator=" ", strip=True)
        total += 1

        if "nofollow" in rel.split():
            nofollow += 1

        if not text:
            empty_text.append(href[:120])

        if not href:
            empty_href.append(text[:120])
            continue

        low = href.lower()
        if href.startswith("#") or low.startswith(_PLACEHOLDER_SCHEMES):
            placeholder.append(href[:120])
            continue
        if low.startswith(_SKIP_SCHEMES):
            continue

        absolute = urljoin(base.rstrip("/") + "/", href) if base else href
        if not absolute.startswith(("http://", "https://")):
            continue

        host = urlparse(absolute).netloc.lower()
        if base_host and host == base_host:
            internal += 1
        else:
            external += 1
            domains[host] = domains.get(host, 0) + 1

        normalized = absolute.split("#", 1)[0]
        if normalized not in seen:
            seen.add(normalized)
            unique_urls.append(normalized)

    return {
        "total": total,
        "internal": internal,
        "external": external,
        "nofollow": nofollow,
        "external_domains": domains,
        "empty_href": empty_href,
        "empty_text": empty_text,
        "placeholder": placeholder,
        "unique_urls": unique_urls,
    }


# ===========================================================================
# Чистые функции: W3C
# ===========================================================================
def summarize_w3c(data: Any, top: int = 8) -> Dict[str, Any]:
    """Чистая функция: сгруппировать сообщения W3C Nu Checker по типам и текстам."""
    messages = []
    if isinstance(data, dict):
        messages = data.get("messages") or []
    if not isinstance(messages, list):
        messages = []

    errors: List[str] = []
    warnings: List[str] = []
    info: List[str] = []

    for m in messages:
        if not isinstance(m, dict):
            continue
        msg = str(m.get("message") or "").strip()
        mtype = str(m.get("type") or "").strip().lower()
        if mtype == "error":
            errors.append(msg)
        elif mtype == "warning":
            warnings.append(msg)
        else:
            info.append(msg)

    def group(items: List[str]) -> List[Dict[str, Any]]:
        counts: Dict[str, int] = {}
        for msg in items:
            counts[msg] = counts.get(msg, 0) + 1
        grouped = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return [{"message": msg, "count": cnt} for msg, cnt in grouped[:top]]

    return {
        "errors_count": len(errors),
        "warnings_count": len(warnings),
        "info_count": len(info),
        "total": len(messages),
        "top_errors": group(errors),
        "top_warnings": group(warnings),
    }


# ===========================================================================
# Вспомогательные конструкторы
# ===========================================================================
def _status_from_score(score: int) -> str:
    if score >= 80:
        return "ok"
    if score >= 40:
        return "warning"
    return "critical"


def _skipped_result(check_id: str, title: str, what: str, fix: str) -> CheckResult:
    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="skipped",
        score=0,
        findings=[
            Finding(
                level="warning",
                text=f"Не удалось получить {what} — проверка пропущена",
                fix=fix,
                hours=0.5,
            )
        ],
        raw={},
    )


def _truncate(text: str, limit: int = 80) -> str:
    t = (text or "").strip()
    return t if len(t) <= limit else t[: limit - 1] + "…"


# ===========================================================================
# Проверка 1: метатеги
# ===========================================================================
@check(id="meta_tags", title="Метатеги и служебные теги <head>", category=CATEGORY)
async def meta_tags(ctx: AuditContext) -> CheckResult:
    check_id = "meta_tags"
    title = "Метатеги и служебные теги <head>"

    resp = await ctx.home()
    if resp is None:
        return _skipped_result(check_id, title, "HTML главной страницы", "Проверить доступность сайта и повторить аудит")

    meta = parse_meta_tags(resp.text or "", ctx.base)

    # favicon: если в разметке нет link rel=icon, проверяем /favicon.ico
    favicon_ok = bool(meta["favicon"])
    favicon_source = meta["favicon_source"]
    favicon_status: Optional[int] = None
    if not favicon_ok:
        fav = await ctx.get(ctx.base + "/favicon.ico")
        if fav is not None:
            favicon_status = fav.status_code
            if fav.status_code == 200:
                favicon_ok = True
                favicon_source = "/favicon.ico"

    findings: List[Finding] = []
    score = 100

    # title
    title_len = len(meta["title"])
    if not meta["title"]:
        findings.append(
            Finding(
                level="critical",
                text="Отсутствует тег <title> на главной странице",
                fix="Добавить уникальный <title> длиной 30–65 символов с главным ключевым запросом в начале",
                hours=1.0,
            )
        )
        score -= 25
    elif title_len < TITLE_MIN:
        findings.append(
            Finding(
                level="warning",
                text=f"<title> слишком короткий: {title_len} символов (< {TITLE_MIN}) — «{_truncate(meta['title'])}»",
                fix="Расширить title до 30–65 символов, добавив уточняющие ключевые слова и название бренда",
                hours=0.5,
            )
        )
        score -= 10
    elif title_len > TITLE_MAX:
        findings.append(
            Finding(
                level="warning",
                text=f"<title> слишком длинный: {title_len} символов (> {TITLE_MAX}) — «{_truncate(meta['title'])}»",
                fix="Сократить title до 30–65 символов, чтобы он не обрезался в выдаче",
                hours=0.5,
            )
        )
        score -= 10

    # description
    desc_len = len(meta["description"])
    if not meta["description"]:
        findings.append(
            Finding(
                level="warning",
                text="Отсутствует meta description",
                fix="Добавить уникальное описание 70–160 символов с ключевыми запросами и призывом к действию",
                hours=1.0,
            )
        )
        score -= 20
    elif not (DESC_MIN <= desc_len <= DESC_MAX):
        findings.append(
            Finding(
                level="warning",
                text=f"meta description вне рекомендованной длины: {desc_len} символов (нужно {DESC_MIN}–{DESC_MAX})",
                fix="Привести описание к 70–160 символам — иначе оно обрезается в сниппете",
                hours=0.5,
            )
        )
        score -= 8

    # keywords — только информация
    if meta["keywords"]:
        findings.append(
            Finding(
                level="info",
                text=f"meta keywords задан ({len(meta['keywords'])} символов) — поисковики его не учитывают",
                fix="Оставить только для внутренних целей или убрать; на ранжирование не влияет",
                hours=0.25,
            )
        )

    # canonical
    if not meta["canonical"]:
        findings.append(
            Finding(
                level="warning",
                text="Не найден canonical URL (<link rel=\"canonical\">)",
                fix="Добавить абсолютный canonical на главную страницу, чтобы исключить дубли",
                hours=1.0,
            )
        )
        score -= 12
    elif not meta["canonical_is_absolute"]:
        findings.append(
            Finding(
                level="warning",
                text=f"canonical задан не абсолютным URL: «{_truncate(meta['canonical'])}»",
                fix="Указать canonical полным абсолютным адресом с протоколом и доменом",
                hours=0.5,
            )
        )
        score -= 6

    # lang
    if not meta["lang"]:
        findings.append(
            Finding(
                level="warning",
                text="У тега <html> не задан атрибут lang",
                fix="Указать язык страницы, например <html lang=\"ru\"> — это важно для поиска и скринридеров",
                hours=0.5,
            )
        )
        score -= 8

    # viewport
    if not meta["viewport"]:
        findings.append(
            Finding(
                level="warning",
                text="Не найден meta viewport — страница может некорректно отображаться на мобильных",
                fix="Добавить <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
                hours=0.5,
            )
        )
        score -= 8

    # charset
    if not meta["charset"]:
        findings.append(
            Finding(
                level="warning",
                text="Не объявлена кодировка страницы (meta charset)",
                fix="Добавить <meta charset=\"utf-8\"> в самое начало <head>",
                hours=0.25,
            )
        )
        score -= 6

    # favicon
    if not favicon_ok:
        findings.append(
            Finding(
                level="warning",
                text="Не найден favicon (ни link rel=icon, ни /favicon.ico)",
                fix="Добавить <link rel=\"icon\" href=\"/favicon.ico\"> и сам файл favicon.ico в корень сайта",
                hours=0.5,
            )
        )
        score -= 8

    score = max(0, min(100, score))
    status = _status_from_score(score)
    if status == "ok":
        findings.append(
            Finding(level="ok", text="Базовые метатеги и служебные теги <head> заполнены корректно", fix="")
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "title": meta["title"],
            "title_length": title_len,
            "description": meta["description"],
            "description_length": desc_len,
            "keywords": meta["keywords"],
            "canonical": meta["canonical"],
            "canonical_is_absolute": meta["canonical_is_absolute"],
            "lang": meta["lang"],
            "viewport": meta["viewport"],
            "charset": meta["charset"],
            "favicon": meta["favicon"],
            "favicon_source": favicon_source,
            "favicon_status": favicon_status,
        },
    )


# ===========================================================================
# Проверка 2: заголовки
# ===========================================================================
@check(id="headings", title="Заголовки H1–H6 и их структура", category=CATEGORY)
async def headings(ctx: AuditContext) -> CheckResult:
    check_id = "headings"
    title = "Заголовки H1–H6 и их структура"

    resp = await ctx.home()
    if resp is None:
        return _skipped_result(check_id, title, "HTML главной страницы", "Проверить доступность сайта и повторить аудит")

    data = analyze_headings(resp.text or "")
    findings: List[Finding] = []
    score = 100

    if data["h1_count"] == 0:
        findings.append(
            Finding(
                level="critical",
                text="На странице нет ни одного заголовка H1",
                fix="Добавить один содержательный H1 с главным ключевым запросом, отражающий суть страницы",
                hours=1.0,
            )
        )
        score -= 40
    elif data["h1_count"] > 1:
        findings.append(
            Finding(
                level="warning",
                text=f"На странице несколько H1 ({data['h1_count']}) — это размывает структуру",
                fix="Оставить один H1, остальные понизить до H2/H3",
                hours=1.0,
            )
        )
        score -= 20

    if data["h1_problem"]:
        findings.append(
            Finding(
                level="warning",
                text=f"Проблема с H1: {data['h1_problem']} (текст: «{_truncate(data['h1_text'])}»)",
                fix="Переписать H1 осмысленной фразой с заглавной буквы без служебных слов в начале",
                hours=1.0,
            )
        )
        score -= 15

    if data["has_skipped_levels"]:
        skips = ", ".join(f"H{s['from']}→H{s['to']}" for s in data["skipped"][:5])
        findings.append(
            Finding(
                level="warning",
                text=f"Нарушена иерархия заголовков (пропуск уровня): {skips}",
                fix="Выстроить последовательность H1→H2→H3 без пропусков уровней",
                hours=2.0,
            )
        )
        score -= 15

    if data["junk"]:
        samples = "; ".join(
            f"H{j['level']} «{_truncate(j['text'], 40)}» — {j['reason']}" for j in data["junk"][:5]
        )
        findings.append(
            Finding(
                level="warning",
                text=f"Найдены пустые или мусорные заголовки ({len(data['junk'])}): {samples}",
                fix="Заменить пустые и служебные заголовки на осмысленные, соответствующие содержанию раздела",
                hours=2.0,
            )
        )
        score -= 5 * min(len(data["junk"]), 4)

    score = max(0, min(100, score))
    status = _status_from_score(score)
    if data["h1_count"] == 0:
        status = "critical"
    if status == "ok":
        findings.append(
            Finding(level="ok", text=f"Структура заголовков корректна: H1 = «{_truncate(data['h1_text'])}»", fix="")
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "h1_count": data["h1_count"],
            "h1_text": data["h1_text"],
            "h1_problem": data["h1_problem"],
            "outline": data["outline"],
            "has_skipped_levels": data["has_skipped_levels"],
            "skipped": data["skipped"],
            "junk": data["junk"],
        },
    )


# ===========================================================================
# Проверка 3: дубли title / description / H1
# ===========================================================================
@check(id="title_desc_h1_duplicates", title="Дубли title, description и H1", category=CATEGORY)
async def title_desc_h1_duplicates(ctx: AuditContext) -> CheckResult:
    check_id = "title_desc_h1_duplicates"
    title = "Дубли title, description и H1"

    resp = await ctx.home()
    if resp is None:
        return _skipped_result(check_id, title, "HTML главной страницы", "Проверить доступность сайта и повторить аудит")

    html = resp.text or ""
    meta = parse_meta_tags(html, ctx.base)
    heads = analyze_headings(html)
    duplicates = find_duplicates(meta["title"], meta["description"], heads["h1_text"])

    findings: List[Finding] = []
    score = 100

    if duplicates:
        for d in duplicates:
            kind = "полностью совпадают" if d["exact"] else f"почти совпадают (схожесть {int(d['ratio'] * 100)}%)"
            findings.append(
                Finding(
                    level="warning",
                    text=f"{d['a']} и {d['b']} {kind}",
                    fix="Сделать title, description и H1 уникальными: разные формулировки, H1 — про содержание страницы, title — про запрос",
                    hours=1.0,
                )
            )
        score = max(0, 100 - 30 * len(duplicates))
    else:
        findings.append(Finding(level="ok", text="title, description и H1 не дублируют друг друга", fix=""))

    status = _status_from_score(score)
    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "title": meta["title"],
            "description": meta["description"],
            "h1": heads["h1_text"],
            "duplicates": duplicates,
        },
    )


# ===========================================================================
# Проверка 4: изображения и alt
# ===========================================================================
@check(id="images_alt", title="Alt-тексты изображений", category=CATEGORY)
async def images_alt(ctx: AuditContext) -> CheckResult:
    check_id = "images_alt"
    title = "Alt-тексты изображений"

    resp = await ctx.home()
    if resp is None:
        return _skipped_result(check_id, title, "HTML главной страницы", "Проверить доступность сайта и повторить аудит")

    data = analyze_images(resp.text or "", ctx.base)
    findings: List[Finding] = []
    score = 100

    if data["total"] == 0:
        status = "ok"
        findings.append(Finding(level="ok", text="На главной странице не найдено изображений", fix=""))
    else:
        if data["missing_alt"]:
            samples = "; ".join(_truncate(s, 60) for s in data["no_alt"][:5])
            findings.append(
                Finding(
                    level="warning",
                    text=f"У {data['missing_alt']} изображений нет атрибута alt (всего изображений: {data['total']}). Примеры: {samples}",
                    fix="Добавить осмысленный alt каждому содержательному изображению; декоративные пометить role=presentation или alt=\"\"",
                    hours=2.0,
                )
            )
            score -= min(60, data["missing_alt"] * 5)

        if data["empty_alt"]:
            findings.append(
                Finding(
                    level="warning",
                    text=f"У {data['empty_alt']} изображений пустой alt",
                    fix="Заполнить alt описанием изображения либо явно пометить декоративные как role=presentation",
                    hours=1.0,
                )
            )
            score -= min(20, data["empty_alt"] * 2)

        score = max(0, min(100, score))
        status = _status_from_score(score)
        if status == "ok":
            findings.append(
                Finding(level="ok", text=f"Все изображения ({data['total']}) имеют корректные alt-тексты", fix="")
            )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "total": data["total"],
            "missing_alt": data["missing_alt"],
            "empty_alt": data["empty_alt"],
            "no_alt": data["no_alt"],
        },
    )


# ===========================================================================
# Проверка 5: ссылки
# ===========================================================================
async def _probe_link(
    client: Any, sem: asyncio.Semaphore, url: str
) -> Dict[str, Any]:
    """Проверить доступность ссылки: HEAD, при ошибке/статусе >=400 — GET."""
    async with sem:
        try:
            resp = await client.head(url, follow_redirects=True, timeout=10.0)
            if resp.status_code < 400:
                return {"url": url, "status": resp.status_code, "final_url": str(resp.url), "error": None}
        except Exception:
            pass
        try:
            resp = await client.get(url, follow_redirects=True, timeout=10.0)
            return {"url": url, "status": resp.status_code, "final_url": str(resp.url), "error": None}
        except Exception as exc:  # noqa: BLE001 - нужна любая причина
            return {"url": url, "status": None, "final_url": url, "error": str(exc)}


@check(id="links", title="Ссылки: битые, внешние, nofollow", category=CATEGORY)
async def links(ctx: AuditContext) -> CheckResult:
    check_id = "links"
    title = "Ссылки: битые, внешние, nofollow"

    resp = await ctx.home()
    if resp is None:
        return _skipped_result(check_id, title, "HTML главной страницы", "Проверить доступность сайта и повторить аудит")

    data = analyze_links(resp.text or "", ctx.base)
    findings: List[Finding] = []

    findings.append(
        Finding(
            level="info",
            text=(
                f"Ссылок на странице: {data['total']} "
                f"(внутренних {data['internal']}, внешних {data['external']}, nofollow {data['nofollow']})"
            ),
            fix="Следить за балансом внутренних и внешних ссылок и не размечать важные ссылки как nofollow",
            hours=0.5,
        )
    )

    if data["external_domains"]:
        top_domains = sorted(data["external_domains"].items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        findings.append(
            Finding(
                level="info",
                text="Внешние домены: " + ", ".join(f"{d} ({c})" for d, c in top_domains),
                fix="Периодически проверять внешние домены на траст и актуальность",
                hours=0.5,
            )
        )

    if data["empty_href"]:
        findings.append(
            Finding(
                level="warning",
                text=f"Найдены анкоры без href: {len(data['empty_href'])}",
                fix="Убрать ссылки-заглушки без href или заменить их обычным текстом/кнопками",
                hours=1.0,
            )
        )

    if data["empty_text"]:
        findings.append(
            Finding(
                level="warning",
                text=f"Найдены ссылки без анкорного текста: {len(data['empty_text'])}",
                fix="Добавить осмысленный анкорный текст (для картинок-ссылок использовать alt)",
                hours=1.0,
            )
        )

    urls = data["unique_urls"][:LINKS_LIMIT]
    broken: List[Dict[str, Any]] = []
    checked = len(urls) if ctx.client is not None else 0

    if checked:
        sem = asyncio.Semaphore(LINKS_CONCURRENCY)
        results = await asyncio.gather(*[_probe_link(ctx.client, sem, u) for u in urls])
        for r in results:
            if r["error"] is not None or (r["status"] is not None and r["status"] >= 400):
                broken.append(r)

    if broken:
        samples = "; ".join(
            f"{_truncate(b['url'], 70)} ({b['status'] if b['status'] is not None else 'нет ответа'})"
            for b in broken[:8]
        )
        ratio = len(broken) / checked if checked else 0
        findings.append(
            Finding(
                level="critical" if ratio >= 0.3 else "warning",
                text=f"Битые ссылки: {len(broken)} из {checked}. Примеры: {samples}",
                fix="Исправить или удалить битые ссылки, настроить 301-редиректы на актуальные адреса",
                hours=2.0,
            )
        )

    if checked == 0:
        score = 100
    else:
        score = max(0, int(round(100 * (checked - len(broken)) / checked)))

    if broken:
        status = "critical" if (len(broken) / checked) >= 0.3 else "warning"
    elif data["empty_href"] or data["empty_text"]:
        status = "warning"
        score = min(score, 80)
    else:
        status = "ok"

    if status == "ok":
        findings.append(
            Finding(level="ok", text=f"Проверено ссылок: {checked}, битых не найдено", fix="")
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "total": data["total"],
            "internal": data["internal"],
            "external": data["external"],
            "nofollow": data["nofollow"],
            "external_domains": data["external_domains"],
            "empty_href_count": len(data["empty_href"]),
            "empty_text_count": len(data["empty_text"]),
            "empty_href": data["empty_href"],
            "empty_text": data["empty_text"],
            "checked": checked,
            "broken": broken,
        },
    )


# ===========================================================================
# Проверка 6: W3C-валидация
# ===========================================================================
@check(id="w3c_validation", title="Валидация HTML по стандарту W3C", category=CATEGORY)
async def w3c_validation(ctx: AuditContext) -> CheckResult:
    check_id = "w3c_validation"
    title = "Валидация HTML по стандарту W3C"

    resp = await ctx.home()
    if resp is None:
        return _skipped_result(check_id, title, "HTML главной страницы", "Проверить доступность сайта и повторить аудит")

    if ctx.client is None:
        return _skipped_result(check_id, title, "HTTP-клиент", "Повторить аудит с активным HTTP-клиентом")

    html = resp.text or ""
    payload = html.encode("utf-8")

    try:
        vresp = await ctx.client.post(
            W3C_ENDPOINT,
            content=payload,
            headers={"Content-Type": "text/html; charset=utf-8", "User-Agent": "seo-geo-checker/1.0"},
            timeout=30.0,
            follow_redirects=True,
        )
    except Exception:
        return _skipped_result(
            check_id,
            title,
            "ответ валидатора W3C",
            "Проверить доступность validator.w3.org и повторить проверку позже",
        )

    if vresp.status_code != 200:
        return _skipped_result(
            check_id,
            title,
            f"ответ валидатора W3C (HTTP {vresp.status_code})",
            "Повторить проверку позже, когда сервис validator.w3.org доступен",
        )

    try:
        data = vresp.json()
    except Exception:
        return _skipped_result(
            check_id,
            title,
            "JSON валидатора W3C",
            "Повторить проверку позже — валидатор вернул неразбираемый ответ",
        )

    summary = summarize_w3c(data, top=8)
    errors = summary["errors_count"]
    warnings = summary["warnings_count"]

    findings: List[Finding] = []

    if errors == 0 and warnings == 0:
        status = "ok"
        score = 100
        findings.append(Finding(level="ok", text="HTML главной страницы проходит валидацию W3C без ошибок", fix=""))
    else:
        if errors > 0:
            samples = "; ".join(f"{e['message']} (×{e['count']})" for e in summary["top_errors"][:8])
            findings.append(
                Finding(
                    level="warning" if errors > 50 else "info",
                    text=f"Валидатор W3C нашёл ошибок: {errors}. Частые ошибки: {samples or '—'}",
                    fix="Исправить ошибки разметки по отчёту validator.w3.org (закрыть теги, убрать недопустимые атрибуты, проверить вложенность)",
                    hours=min(8.0, max(1.0, errors * 0.1)),
                )
            )
        if warnings > 0:
            samples = "; ".join(f"{w['message']} (×{w['count']})" for w in summary["top_warnings"][:8])
            findings.append(
                Finding(
                    level="info",
                    text=f"Предупреждений W3C: {warnings}. Примеры: {samples or '—'}",
                    fix="По возможности устранить предупреждения, чтобы разметка была чистой",
                    hours=1.0,
                )
            )

        status = "warning" if errors > 50 else "ok"
        score = max(0, min(100, 100 - errors * 2 - warnings))

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "errors": errors,
            "warnings": warnings,
            "info": summary["info_count"],
            "total_messages": summary["total"],
            "top_errors": summary["top_errors"],
            "top_warnings": summary["top_warnings"],
        },
    )
