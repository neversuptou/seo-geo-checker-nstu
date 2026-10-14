"""Технический SEO-аудит: robots.txt, sitemap, фиды, стабильность URL и др.

Проверки:
- robots_txt        — доступность, Content-Type, синтаксис, Sitemap, закрытие корня
- sitemap           — поиск карты сайта, рекурсивный разбор индексов, выборка URL
- feeds             — RSS/Atom/JSON Feed через link rel=alternate и стандартные пути
- url_stability     — http->https, www/non-www, цепочки редиректов, слаги
- soft_404          — мягкие 404 (страница-заглушка со статусом 200)
- hreflang          — взаимные hreflang-ссылки и x-default
- conditional_get   — Last-Modified/ETag/Cache-Control и ответ 304
- http_headers      — информационный вывод заголовков ответа главной
- security_headers  — HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy
- version_leaks     — утечки версий сервера/движка и устаревший PHP
- performance_basic — TTFB/полное время, сжатие, размер HTML, число ресурсов, alt-svc h3
- mixed_content     — http-ресурсы на https-странице

Чистая логика парсинга вынесена в синхронные функции без сети и покрыта тестами:
`parse_robots_txt`, `parse_sitemap`, `detect_template_duplicates`, `extract_page_meta`,
`extract_hreflang`, `find_mixed_content`, `find_feed_links`, `looks_like_feed`,
`analyze_slugs`, `parse_hsts_max_age`, `parse_php_version`, `is_php_outdated`.
"""
from __future__ import annotations

import asyncio
import gzip
import random
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

from selectolax.lexbor import LexborHTMLParser as HTMLParser

from app.core import AuditContext, CheckResult, Finding
from app.registry import check

CATEGORY = "Технический SEO"

# Ограничения сетевых проверок.
SITEMAP_MAX_CHILDREN = 50
SITEMAP_SAMPLE_SIZE = 30
HREFLANG_SAMPLE_SIZE = 5
MAX_REDIRECT_HOPS = 5
HSTS_MIN_MAX_AGE = 15552000  # 180 дней
MIN_PHP_VERSION = (8, 1)
SLUG_JUNK_THRESHOLD = 0.2


# --------------------------------------------------------------------------- #
# Чистые функции: robots.txt
# --------------------------------------------------------------------------- #
# Директивы, которые мы считаем корректными (остальные — «неизвестные»).
_KNOWN_ROBOTS_FIELDS = {
    "user-agent",
    "allow",
    "disallow",
    "sitemap",
    "crawl-delay",
    "host",
    "clean-param",
    "request-rate",
    "visit-time",
    "noindex",
    "content-signal",
}

# Агенты, для которых критично проверять закрытие корня.
ROOT_AGENTS = ("*", "Googlebot", "Yandex")


def _robots_pattern_to_regex(pattern: str) -> str:
    """Преобразовать путь robots.txt в regex (`*` -> `.*`, концевой `$` -> якорь)."""
    parts: List[str] = []
    n = len(pattern)
    for i, ch in enumerate(pattern):
        if ch == "*":
            parts.append(".*")
        elif ch == "$" and i == n - 1:
            parts.append("$")
        else:
            parts.append(re.escape(ch))
    return "".join(parts)


def _robots_path_matches(pattern: str, path: str) -> bool:
    if pattern == "":
        return True
    try:
        return re.match(_robots_pattern_to_regex(pattern), path) is not None
    except re.error:
        return path.startswith(pattern)


def _match_agent_groups(groups: List[Dict[str, Any]], ua: str) -> List[Dict[str, Any]]:
    """Группы, применимые к агенту: точные совпадения, иначе группа `*`."""
    specific = [
        g for g in groups if any(a.strip().lower() == ua.lower() for a in g.get("user_agents", []))
    ]
    if specific:
        return specific
    return [g for g in groups if any(a.strip() == "*" for a in g.get("user_agents", []))]


def _root_allowed(groups: List[Dict[str, Any]], ua: str) -> bool:
    """Разрешён ли корень `/` для агента (правило самого длинного совпадения)."""
    rules = [r for g in _match_agent_groups(groups, ua) for r in g.get("rules", [])]
    best: Optional[Dict[str, Any]] = None
    best_len = -1
    for rule in rules:
        pattern = rule.get("path", "")
        rtype = rule.get("type", "disallow")
        # Пустой Disallow означает «разрешить всё».
        if pattern == "" and rtype == "disallow":
            continue
        if not _robots_path_matches(pattern, "/"):
            continue
        if len(pattern) > best_len or (len(pattern) == best_len and rtype == "allow"):
            best_len = len(pattern)
            best = rule
    if best is None:
        return True
    return best.get("type") == "allow"


def parse_robots_txt(text: str) -> Dict[str, Any]:
    """Разобрать robots.txt: синтаксис, директивы Sitemap, закрытие корня.

    Возвращает словарь:
    {
        "problems": [...]            — русскоязычные описания проблем синтаксиса,
        "unknown_directives": [...],  — встреченные неизвестные директивы,
        "rules_before_agent": int,    — сколько правил стояло до первого User-agent,
        "sitemaps": [...],            — значения директив Sitemap,
        "disallowed_root": [...],     — агенты, для которых закрыт `/`,
        "groups": [{"user_agents": [...], "rules": [{"type","path"}]}],
    }
    """
    problems: List[str] = []
    unknown: List[str] = []
    sitemaps: List[str] = []
    groups: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    seen_any_agent = False
    rules_before_agent = 0

    if text is None:  # защита от неожиданных типов
        text = ""
    text = text.lstrip("\ufeff")

    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            problems.append(f"Строка {lineno}: нет двоеточия — «{raw_line.strip()}»")
            continue

        field, _, value = line.partition(":")
        field_l = field.strip().lower()
        value = value.strip()

        if field_l == "user-agent":
            seen_any_agent = True
            if not value:
                problems.append(f"Строка {lineno}: пустой User-agent")
            # Новая группа, если у текущей уже есть правила.
            if current is None or current["rules"]:
                current = {"user_agents": [], "rules": []}
                groups.append(current)
            current["user_agents"].append(value)
        elif field_l in ("allow", "disallow"):
            if not seen_any_agent:
                rules_before_agent += 1
                problems.append(
                    f"Строка {lineno}: правило {field.strip()} стоит до первого User-agent"
                )
            if current is None:
                current = {"user_agents": ["*"], "rules": []}
                groups.append(current)
            current["rules"].append({"type": field_l, "path": value})
        elif field_l == "sitemap":
            if not value:
                problems.append(f"Строка {lineno}: пустая директива Sitemap")
            else:
                sitemaps.append(value)
        elif field_l in _KNOWN_ROBOTS_FIELDS:
            # Известная, но не анализируемая детально директива.
            pass
        else:
            unknown.append(field.strip())
            problems.append(f"Строка {lineno}: неизвестная директива «{field.strip()}»")

    disallowed_root = [ua for ua in ROOT_AGENTS if not _root_allowed(groups, ua)]

    return {
        "problems": problems,
        "unknown_directives": sorted(set(unknown)),
        "rules_before_agent": rules_before_agent,
        "sitemaps": sitemaps,
        "disallowed_root": disallowed_root,
        "groups": groups,
    }


# --------------------------------------------------------------------------- #
# Чистые функции: sitemap
# --------------------------------------------------------------------------- #
def _localname(tag: str) -> str:
    """Локальное имя XML-тега без namespace: `{ns}url` -> `url`."""
    if not tag:
        return ""
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _child_text(element: ET.Element, name: str) -> Optional[str]:
    for child in element:
        if _localname(child.tag) == name:
            text = (child.text or "").strip()
            return text or None
    return None


def parse_sitemap(xml: bytes) -> Tuple[List[str], List[str], List[Optional[str]]]:
    """Разобрать sitemap или sitemap index.

    Возвращает `(urls, child_sitemaps, lastmods)`:
    * для `<urlset>` — список URL и список lastmod, выровненный по URL;
    * для `<sitemapindex>` — список дочерних sitemap и их lastmod.

    Поддерживает gzip (по магическим байтам) и XML с namespace.
    Никогда не бросает исключение — при ошибке возвращает пустые списки.
    """
    urls: List[str] = []
    children: List[str] = []
    lastmods: List[Optional[str]] = []

    if not xml:
        return urls, children, lastmods

    data = xml
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except Exception:  # noqa: BLE001 - битый gzip
            return urls, children, lastmods

    try:
        root = ET.fromstring(data)
    except Exception:  # noqa: BLE001 - пробуем снять ведущие пробелы/BOM
        try:
            root = ET.fromstring(data.lstrip())
        except Exception:  # noqa: BLE001 - не XML вовсе
            return urls, children, lastmods

    tag = _localname(root.tag)
    if tag == "sitemapindex":
        for item in root:
            if _localname(item.tag) != "sitemap":
                continue
            loc = _child_text(item, "loc")
            if loc:
                children.append(loc)
                lastmods.append(_child_text(item, "lastmod"))
    elif tag == "urlset":
        for item in root:
            if _localname(item.tag) != "url":
                continue
            loc = _child_text(item, "loc")
            if loc:
                urls.append(loc)
                lastmods.append(_child_text(item, "lastmod"))

    return urls, children, lastmods


def parse_lastmod(value: Optional[str]) -> Optional[datetime]:
    """Разобрать lastmod sitemap в timezone-aware datetime (или None)."""
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except Exception:  # noqa: BLE001 - нестандартный формат даты
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


_SLUG_NUMBER_RE = re.compile(r"/[^/]+-\d+/?$")


def detect_template_duplicates(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Найти шаблонный мусор в выборке URL из sitemap.

    Признаки:
    * одинаковый `<title>` встречается на >= 3 URL;
    * слаг вида `/name-123/` (числовой хвост — типичный шаблон-заглушка).

    Возвращает доли и ориентировочные счётчики; `junk_share` — доля URL,
    помеченных хотя бы одним признаком (по ней оценивается общий объём мусора).
    """
    samples = samples or []
    total = len(samples)

    title_map: Dict[str, List[str]] = {}
    title_original: Dict[str, str] = {}
    for sample in samples:
        title = (sample.get("title") or "").strip()
        if not title:
            continue
        key = title.casefold()
        title_map.setdefault(key, []).append(sample.get("url") or "")
        title_original.setdefault(key, title)

    duplicate_groups: Dict[str, List[str]] = {
        title_original[key]: urls for key, urls in title_map.items() if len(urls) >= 3
    }
    duplicate_urls = {u for urls in duplicate_groups.values() for u in urls}

    slug_urls: set[str] = set()
    for sample in samples:
        url = sample.get("url") or ""
        path = urlparse(url).path or url
        if _SLUG_NUMBER_RE.search(path or ""):
            slug_urls.add(url)

    junk_urls = duplicate_urls | slug_urls

    def _share(count: int) -> float:
        return round(count / total, 4) if total else 0.0

    return {
        "total": total,
        "duplicate_title_groups": duplicate_groups,
        "duplicate_title_count": len(duplicate_urls),
        "duplicate_title_share": _share(len(duplicate_urls)),
        "slug_pattern_count": len(slug_urls),
        "slug_pattern_share": _share(len(slug_urls)),
        "junk_count": len(junk_urls),
        "junk_share": _share(len(junk_urls)),
        "junk_urls": sorted(junk_urls),
    }


# --------------------------------------------------------------------------- #
# Чистые функции: HTML главной
# --------------------------------------------------------------------------- #
def extract_page_meta(html: str) -> Dict[str, Optional[str]]:
    """Извлечь `<title>`, canonical и meta robots из HTML страницы."""
    result: Dict[str, Optional[str]] = {"title": None, "canonical": None, "robots": None}
    if not html:
        return result
    try:
        tree = HTMLParser(html)
    except Exception:  # noqa: BLE001 - битый HTML
        return result

    title_node = tree.css_first("title")
    if title_node is not None:
        result["title"] = title_node.text(strip=True) or None

    for link in tree.css("link"):
        rel = (link.attributes.get("rel") or "").lower()
        if "canonical" in rel:
            href = link.attributes.get("href")
            if href:
                result["canonical"] = href.strip()
            break

    for meta in tree.css("meta"):
        name = (meta.attributes.get("name") or "").lower()
        if name in ("robots", "googlebot"):
            content = meta.attributes.get("content")
            if content:
                result["robots"] = content.strip()
            if name == "robots":
                break

    return result


def extract_hreflang(html: str) -> List[Dict[str, str]]:
    """Собрать теги `<link rel="alternate" hreflang="...">` со страницы."""
    out: List[Dict[str, str]] = []
    if not html:
        return out
    try:
        tree = HTMLParser(html)
    except Exception:  # noqa: BLE001 - битый HTML
        return out
    for link in tree.css("link"):
        rel = (link.attributes.get("rel") or "").lower()
        hreflang = link.attributes.get("hreflang")
        href = link.attributes.get("href")
        if "alternate" in rel and hreflang and href:
            out.append({"hreflang": hreflang.strip(), "href": href.strip()})
    return out


def find_feed_links(html: str) -> List[Dict[str, str]]:
    """Найти фиды по `<link rel="alternate">` на странице."""
    out: List[Dict[str, str]] = []
    if not html:
        return out
    try:
        tree = HTMLParser(html)
    except Exception:  # noqa: BLE001 - битый HTML
        return out
    for link in tree.css("link"):
        rel = (link.attributes.get("rel") or "").lower()
        if "alternate" not in rel:
            continue
        typ = (link.attributes.get("type") or "").lower()
        title = (link.attributes.get("title") or "").lower()
        href = link.attributes.get("href")
        if not href:
            continue
        if any(t in typ for t in ("rss", "atom", "feed", "json", "rdf")) or "feed" in title:
            out.append({"href": href.strip(), "type": typ, "title": title})
    return out


def looks_like_feed(text: str, content_type: str = "") -> bool:
    """Похож ли ответ на фид (RSS/Atom/RDF/JSON Feed)."""
    ct = (content_type or "").lower()
    if any(t in ct for t in ("xml", "rss", "atom", "json")):
        return True
    head = (text or "")[:1500].strip().lower()
    return any(
        marker in head
        for marker in ("<rss", "<feed", "<rdf:rdf", '"version"', '"items"', "<channel")
    )


def count_assets(html: str) -> Dict[str, int]:
    """Посчитать внешние скрипты и таблицы стилей на странице."""
    result = {"scripts": 0, "stylesheets": 0}
    if not html:
        return result
    try:
        tree = HTMLParser(html)
    except Exception:  # noqa: BLE001 - битый HTML
        return result
    result["scripts"] = len(tree.css("script[src]"))
    result["stylesheets"] = len(tree.css('link[rel="stylesheet"]'))
    return result


_MIXED_TAGS: Tuple[Tuple[str, str], ...] = (
    ("img", "src"),
    ("script", "src"),
    ("link", "href"),
    ("iframe", "src"),
    ("source", "src"),
    ("video", "src"),
    ("audio", "src"),
    ("embed", "src"),
    ("object", "data"),
)


def find_mixed_content(html: str) -> List[Dict[str, str]]:
    """Найти http://-ресурсы на странице (смешанный контент)."""
    out: List[Dict[str, str]] = []
    if not html:
        return out
    try:
        tree = HTMLParser(html)
    except Exception:  # noqa: BLE001 - битый HTML
        return out

    for tag, attr in _MIXED_TAGS:
        for node in tree.css(tag):
            value = node.attributes.get(attr)
            if value and value.strip().lower().startswith("http://"):
                out.append({"tag": tag, "attribute": attr, "url": value.strip()})

    for tag in ("img", "source"):
        for node in tree.css(tag):
            srcset = node.attributes.get("srcset")
            if not srcset:
                continue
            for part in srcset.split(","):
                candidate = part.strip().split(" ")[0]
                if candidate.lower().startswith("http://"):
                    out.append({"tag": tag, "attribute": "srcset", "url": candidate})

    return out


def parse_hsts_max_age(value: str) -> Optional[int]:
    """Извлечь max-age из заголовка Strict-Transport-Security."""
    if not value:
        return None
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


def parse_php_version(text: str) -> Optional[Tuple[int, int]]:
    """Найти версию PHP в строке (например, `PHP/7.4.33`)."""
    if not text:
        return None
    match = re.search(r"PHP[/ ](\d+)\.(\d+)", text, re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def is_php_outdated(version: Optional[Tuple[int, int]]) -> bool:
    """Устаревшая ли версия PHP (младше 8.1)."""
    return version is not None and version < MIN_PHP_VERSION


def find_generators(html: str) -> List[str]:
    """Собрать значения `<meta name="generator">`."""
    out: List[str] = []
    if not html:
        return out
    try:
        tree = HTMLParser(html)
    except Exception:  # noqa: BLE001 - битый HTML
        return out
    for meta in tree.css("meta"):
        name = (meta.attributes.get("name") or "").lower()
        if name == "generator":
            content = meta.attributes.get("content")
            if content:
                out.append(content.strip())
    return out


# --------------------------------------------------------------------------- #
# Чистые функции: слаги внутренних ссылок
# --------------------------------------------------------------------------- #
_KEBAB_RE = re.compile(r"^[a-z0-9]+(?:[-.][a-z0-9]+)*$")


def analyze_slugs(urls: List[str], host: str) -> Dict[str, Any]:
    """Проанализировать слаги внутренних ссылок.

    Проверяет: kebab-case/lowercase, наличие query-параметров.
    Возвращает доли и примеры проблемных URL.
    """
    internal: List[str] = []
    params: List[str] = []
    uppercase: List[str] = []
    non_kebab: List[str] = []
    seen: set[str] = set()
    host_l = (host or "").lower()

    for url in urls or []:
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme not in ("http", "https"):
            continue
        netloc = parsed.netloc.lower()
        if netloc and host_l and host_l not in netloc:
            continue
        if url in seen:
            continue
        seen.add(url)
        internal.append(url)

        if parsed.query:
            params.append(url)

        path = parsed.path or "/"
        if path != path.lower():
            uppercase.append(url)

        last = path.strip("/").rsplit("/", 1)[-1]
        if last and "%" not in last:
            name = last.rsplit(".", 1)[0] if "." in last else last
            if name and not _KEBAB_RE.match(name):
                non_kebab.append(url)

    total = len(internal)

    def _share(count: int) -> float:
        return round(count / total, 4) if total else 0.0

    return {
        "total": total,
        "internal": internal[:200],
        "params_count": len(params),
        "params_share": _share(len(params)),
        "uppercase_count": len(uppercase),
        "uppercase_share": _share(len(uppercase)),
        "non_kebab_count": len(non_kebab),
        "non_kebab_share": _share(len(non_kebab)),
        "params": params[:20],
        "non_kebab": non_kebab[:20],
    }


# --------------------------------------------------------------------------- #
# Вспомогательные конструкторы результатов
# --------------------------------------------------------------------------- #
def _net_fail(check_id: str, title: str, what: str, hours: float = 0.5) -> CheckResult:
    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="warning",
        score=0,
        findings=[
            Finding(
                level="warning",
                text=f"Не удалось получить {what} — сетевой сбой или ресурс недоступен",
                fix=f"Проверить доступность {what} и повторить аудит",
                hours=hours,
            )
        ],
        raw={"error": "network", "what": what},
    )


def _norm_url(url: str) -> str:
    """Нормализовать URL для сравнения: без фрагмента, без концевого слэша, нижний host."""
    parsed = urlparse(url or "")
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((parsed.scheme, parsed.netloc.lower(), path, "", parsed.query, ""))


async def _redirect_chain(ctx: AuditContext, start_url: str, max_hops: int = MAX_REDIRECT_HOPS) -> List[Dict[str, Any]]:
    """Проследить цепочку редиректов вручную (follow_redirects=False), максимум max_hops."""
    chain: List[Dict[str, Any]] = []
    url = start_url
    for _ in range(max_hops):
        resp = await ctx.get(url, follow_redirects=False)
        if resp is None:
            chain.append({"url": url, "status": None, "location": None})
            break
        location = resp.headers.get("location")
        chain.append({"url": url, "status": resp.status_code, "location": location})
        if resp.status_code in (301, 302, 303, 307, 308) and location:
            url = urljoin(url, location)
        else:
            break
    return chain


# --------------------------------------------------------------------------- #
# Проверка 1: robots.txt
# --------------------------------------------------------------------------- #
@check(id="robots_txt", title="robots.txt: доступность и синтаксис", category=CATEGORY)
async def robots_txt(ctx: AuditContext) -> CheckResult:
    check_id = "robots_txt"
    title = "robots.txt: доступность и синтаксис"
    url = f"{ctx.base}/robots.txt"

    resp = await ctx.get(url)
    if resp is None:
        return _net_fail(check_id, title, "robots.txt")

    body = resp.text or ""
    size = len(body.encode("utf-8"))
    content_type = resp.headers.get("content-type", "")
    parsed = parse_robots_txt(body)

    if resp.status_code >= 400:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=50,
            findings=[
                Finding(
                    level="warning",
                    text=f"robots.txt недоступен (HTTP {resp.status_code}) — краулеры не получают правил обхода",
                    fix="Создать файл /robots.txt в корне сайта и отдавать его со статусом 200 и Content-Type text/plain",
                    hours=1.0,
                )
            ],
            raw={"url": url, "status": resp.status_code, "content_type": content_type, "size_bytes": size},
        )

    findings: List[Finding] = []
    status = "ok"
    score = 100

    if "text/plain" not in content_type.lower():
        findings.append(
            Finding(
                level="warning",
                text=f"Content-Type robots.txt — «{content_type or 'не задан'}», ожидается text/plain",
                fix="Отдавать robots.txt с заголовком Content-Type: text/plain; charset=utf-8",
                hours=0.5,
            )
        )
        status = "warning"
        score = min(score, 80)

    if parsed["problems"]:
        findings.append(
            Finding(
                level="warning",
                text="Синтаксические проблемы robots.txt: " + "; ".join(parsed["problems"][:6]),
                fix="Исправить синтаксис: директива и значение через двоеточие; правила Allow/Disallow только после User-agent; использовать известные директивы",
                hours=1.0,
            )
        )
        status = "warning"
        score = min(score, 60)

    sitemap_statuses: List[Dict[str, Any]] = []
    for sitemap_url in parsed["sitemaps"][:5]:
        sitemap_resp = await ctx.get(sitemap_url)
        code = sitemap_resp.status_code if sitemap_resp is not None else None
        sitemap_statuses.append({"url": sitemap_url, "status": code})
        if sitemap_resp is None or sitemap_resp.status_code >= 400:
            findings.append(
                Finding(
                    level="warning",
                    text=f"Sitemap из robots.txt недоступен: {sitemap_url} (HTTP {code if code is not None else 'нет ответа'})",
                    fix="Убедиться, что URL в директиве Sitemap ведёт на доступную XML-карту и возвращает 200",
                    hours=0.5,
                )
            )
            status = "warning"
            score = min(score, 75)

    if not parsed["sitemaps"]:
        findings.append(
            Finding(
                level="info",
                text="В robots.txt нет директивы Sitemap",
                fix="Добавить строку 'Sitemap: <полный URL карты сайта>' для ускорения обхода",
                hours=0.25,
            )
        )

    for agent in parsed["disallowed_root"]:
        findings.append(
            Finding(
                level="critical",
                text=f"В robots.txt закрыт весь сайт для «{agent}» правилом Disallow: /",
                fix=f"Разрешить обход для «{agent}»: убрать Disallow: / и оставить точечные запреты для служебных разделов",
                hours=1.0,
            )
        )
        status = "critical"
        score = 0

    if status == "ok":
        findings.append(
            Finding(
                level="ok",
                text=f"robots.txt доступен ({size} байт), синтаксис в порядке, директив Sitemap: {len(parsed['sitemaps'])}",
                fix="",
            )
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "url": url,
            "status": resp.status_code,
            "content_type": content_type,
            "size_bytes": size,
            "problems": parsed["problems"],
            "unknown_directives": parsed["unknown_directives"],
            "rules_before_agent": parsed["rules_before_agent"],
            "sitemaps": parsed["sitemaps"],
            "sitemap_statuses": sitemap_statuses,
            "disallowed_root": parsed["disallowed_root"],
            "groups_count": len(parsed["groups"]),
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 2: sitemap
# --------------------------------------------------------------------------- #
_SITEMAP_PATHS = ("/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml")


@check(id="sitemap", title="XML-карта сайта и её содержимое", category=CATEGORY)
async def sitemap(ctx: AuditContext) -> CheckResult:
    check_id = "sitemap"
    title = "XML-карта сайта и её содержимое"

    # 1. Кандидаты: Sitemap из robots.txt + стандартные пути.
    candidates: List[str] = []
    robots_resp = await ctx.get(f"{ctx.base}/robots.txt")
    if robots_resp is not None and robots_resp.status_code < 400:
        candidates.extend(parse_robots_txt(robots_resp.text or "")["sitemaps"])
    for path in _SITEMAP_PATHS:
        candidates.append(f"{ctx.base}{path}")

    seen: set[str] = set()
    unique: List[str] = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)

    roots: List[str] = []
    checked: List[Dict[str, Any]] = []
    for candidate in unique:
        resp = await ctx.get(candidate)
        code = resp.status_code if resp is not None else None
        head = ((resp.content if resp is not None else b"") or b"")[:200].lstrip().lower()
        is_html = head.startswith(b"<!doctype") or head.startswith(b"<html")
        ok = resp is not None and resp.status_code == 200 and not is_html
        checked.append({"url": candidate, "status": code, "ok": ok})
        if ok:
            roots.append(candidate)
        if len(roots) >= 3:
            break

    if not roots:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=30,
            findings=[
                Finding(
                    level="warning",
                    text="XML-карта сайта не найдена ни по стандартным адресам, ни в robots.txt",
                    fix="Сгенерировать sitemap.xml со списком ключевых URL и указать её в robots.txt директивой Sitemap",
                    hours=2.0,
                )
            ],
            raw={"candidates": checked, "roots": []},
        )

    # 2. Рекурсивный разбор индексов (максимум SITEMAP_MAX_CHILDREN дочерних карт).
    queue = list(roots)
    visited: set[str] = set()
    child_sitemaps: List[str] = []
    url_lastmod: Dict[str, Optional[str]] = {}
    processed = 0
    gzip_used = False

    while queue and processed < SITEMAP_MAX_CHILDREN:
        sitemap_url = queue.pop(0)
        if sitemap_url in visited:
            continue
        visited.add(sitemap_url)
        resp = await ctx.get(sitemap_url)
        if resp is None or resp.status_code >= 400:
            continue
        processed += 1
        content = resp.content or b""
        if content[:2] == b"\x1f\x8b":
            gzip_used = True
        urls, children, lastmods = parse_sitemap(content)
        for index, loc in enumerate(urls):
            if loc not in url_lastmod:
                url_lastmod[loc] = lastmods[index] if index < len(lastmods) else None
        child_sitemaps.extend(children)
        for child in children:
            if child not in visited and processed + len(queue) < SITEMAP_MAX_CHILDREN:
                queue.append(child)

    all_urls = list(url_lastmod.keys())
    total_urls = len(all_urls)

    # 3. Свежесть lastmod.
    now = datetime.now(timezone.utc)
    valid_dates = [d for d in (parse_lastmod(v) for v in url_lastmod.values()) if d is not None]
    newest = max(valid_dates) if valid_dates else None
    recent_count = sum(1 for d in valid_dates if (now - d).days <= 90)
    with_lastmod = sum(1 for value in url_lastmod.values() if value)

    # 4. Выборка до SITEMAP_SAMPLE_SIZE URL и параллельная загрузка (Semaphore(6)).
    sample_size = min(SITEMAP_SAMPLE_SIZE, total_urls)
    sampled = random.sample(all_urls, sample_size) if total_urls else []
    sem = asyncio.Semaphore(6)

    async def fetch_one(target: str) -> Dict[str, Any]:
        async with sem:
            resp = await ctx.get(target, timeout=10.0)
        if resp is None:
            return {"url": target, "requested": target, "status": None, "title": None, "canonical": None, "robots": None}
        meta = extract_page_meta(resp.text or "")
        return {
            "url": str(resp.url),
            "requested": target,
            "status": resp.status_code,
            "title": meta["title"],
            "canonical": meta["canonical"],
            "robots": meta["robots"],
        }

    samples = await asyncio.gather(*[fetch_one(u) for u in sampled]) if sampled else []
    duplicates = detect_template_duplicates(samples)

    # 5. Находки.
    findings: List[Finding] = [
        Finding(
            level="ok",
            text=f"Карта сайта найдена ({len(roots)} корневых sitemap), URL в карте: {total_urls}, проверено в выборке: {len(samples)}",
            fix="",
        )
    ]
    status = "ok"
    score = 100

    bad = [s for s in samples if s["status"] is None or s["status"] >= 400]
    if bad:
        examples = ", ".join(s["url"] for s in bad[:3])
        findings.append(
            Finding(
                level="warning",
                text=f"Из карты сайта {len(bad)} из {len(samples)} URL отдают ошибку (например: {examples})",
                fix="Удалить недоступные URL из sitemap или вернуть их в 200/301; не включать в карту страницы с ошибками",
                hours=1.0,
            )
        )
        status = "warning"
        score = min(score, 70)

    noindex = [s for s in samples if s["robots"] and "noindex" in s["robots"].lower()]
    if noindex:
        examples = ", ".join(s["url"] for s in noindex[:3])
        findings.append(
            Finding(
                level="warning",
                text=f"В карте сайта есть URL с meta robots noindex: {len(noindex)} (например: {examples})",
                fix="Убрать noindex с важных страниц или исключить их из sitemap — карта должна содержать только индексируемые URL",
                hours=1.0,
            )
        )
        status = "warning"
        score = min(score, 70)

    mismatched: List[Dict[str, Any]] = []
    for sample in samples:
        if sample["status"] != 200 or not sample["canonical"]:
            continue
        resolved = _norm_url(urljoin(sample["requested"], sample["canonical"]))
        if resolved != _norm_url(sample["requested"]):
            mismatched.append(sample)
    if mismatched:
        examples = ", ".join(s["url"] for s in mismatched[:3])
        findings.append(
            Finding(
                level="warning",
                text=f"Canonical в карте сайта указывает на другой URL: {len(mismatched)} из {len(samples)} (например: {examples})",
                fix="Привести canonical к тому URL, который указан в sitemap, либо заменить URL в sitemap на canonical-версию",
                hours=2.0,
            )
        )
        status = "warning"
        score = min(score, 70)

    if total_urls and duplicates["junk_share"] > SLUG_JUNK_THRESHOLD:
        estimated = int(round(duplicates["junk_share"] * total_urls))
        findings.append(
            Finding(
                level="critical",
                text=(
                    f"Шаблонный мусор в sitemap: {int(round(duplicates['junk_share'] * 100))}% выборки "
                    f"(дубли title или слаги вида /name-123/), ориентировочно {estimated} URL из {total_urls}"
                ),
                fix="Убрать шаблонные и почти пустые страницы из индекса (canonical/noindex), исключить их из sitemap и настроить генерацию пагинации без сотен почти одинаковых URL",
                hours=6.0,
            )
        )
        status = "critical"
        score = 0
    elif duplicates["junk_count"]:
        findings.append(
            Finding(
                level="info",
                text=(
                    f"В выборке найдены возможные шаблонные страницы: дубли title — {duplicates['duplicate_title_count']}, "
                    f"слаги вида /name-123/ — {duplicates['slug_pattern_count']}"
                ),
                fix="Проверить эти URL вручную и при необходимости закрыть их от индексации и убрать из sitemap",
                hours=2.0,
            )
        )

    if valid_dates:
        stale_days = (now - newest).days if newest else None
        if stale_days is not None and stale_days > 365:
            findings.append(
                Finding(
                    level="warning",
                    text=f"Самый свежий lastmod в карте сайта старше года ({stale_days} дней назад)",
                    fix="Обновлять lastmod при изменении страниц и перегенерировать sitemap автоматически",
                    hours=1.0,
                )
            )
            status = "warning" if status == "ok" else status
            score = min(score, 85)
        else:
            findings.append(
                Finding(
                    level="ok",
                    text=f"lastmod актуален: обновлено за 90 дней — {recent_count} из {len(valid_dates)}, newest: {newest.date().isoformat()}",
                    fix="",
                )
            )
    else:
        findings.append(
            Finding(
                level="info",
                text="В карте сайта нет корректных значений lastmod",
                fix="Добавить тег lastmod к URL в sitemap — он помогает поисковикам оценивать свежесть страниц",
                hours=1.0,
            )
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "candidates": checked,
            "roots": roots,
            "child_sitemaps": child_sitemaps,
            "processed_sitemaps": processed,
            "gzip_used": gzip_used,
            "total_urls": total_urls,
            "with_lastmod": with_lastmod,
            "newest_lastmod": newest.isoformat() if newest else None,
            "recent_lastmod_count": recent_count,
            "sampled_count": len(samples),
            "samples": samples,
            "duplicates": duplicates,
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 3: фиды
# --------------------------------------------------------------------------- #
_FEED_PATHS = ("/feed", "/rss.xml", "/atom.xml", "/feed.json", "/feed/")


@check(id="feeds", title="RSS/Atom/JSON-фиды", category=CATEGORY)
async def feeds(ctx: AuditContext) -> CheckResult:
    check_id = "feeds"
    title = "RSS/Atom/JSON-фиды"

    home = await ctx.home()
    if home is None:
        return _net_fail(check_id, title, "главную страницу")

    candidates: List[Dict[str, str]] = []
    for link in find_feed_links(home.text or ""):
        candidates.append({"url": urljoin(str(home.url), link["href"]), "source": "link rel=alternate", "type": link["type"]})
    for path in _FEED_PATHS:
        candidates.append({"url": f"{ctx.base}{path}", "source": "стандартный путь", "type": ""})

    seen: set[str] = set()
    unique: List[Dict[str, str]] = []
    for candidate in candidates:
        if candidate["url"] not in seen:
            seen.add(candidate["url"])
            unique.append(candidate)

    results: List[Dict[str, Any]] = []
    valid: List[Dict[str, Any]] = []
    for candidate in unique[:8]:
        resp = await ctx.get(candidate["url"])
        code = resp.status_code if resp is not None else None
        content_type = resp.headers.get("content-type", "") if resp is not None else ""
        body = (resp.text or "") if resp is not None else ""
        ok = bool(resp is not None and resp.status_code == 200 and looks_like_feed(body, content_type))
        item = {
            "url": candidate["url"],
            "source": candidate["source"],
            "status": code,
            "content_type": content_type,
            "valid": ok,
        }
        results.append(item)
        if ok:
            valid.append(item)

    if valid:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="ok",
            score=100,
            findings=[
                Finding(
                    level="ok",
                    text="Фид найден и доступен: " + ", ".join(v["url"] for v in valid[:5]),
                    fix="",
                )
            ],
            raw={"feeds": results, "valid": [v["url"] for v in valid]},
        )

    advertised = [r for r in results if r["source"] == "link rel=alternate"]
    if advertised:
        findings = [
            Finding(
                level="warning",
                text="В HTML объявлен фид, но он не отвечает корректным RSS/Atom/JSON: " + ", ".join(r["url"] for r in advertised[:5]),
                fix="Проверить адрес фида в link rel=alternate и отдавать по нему валидный RSS/Atom/JSON Feed со статусом 200",
                hours=2.0,
            )
        ]
        score = 50
    else:
        findings = [
            Finding(
                level="warning",
                text="Фид не найден: нет link rel=alternate и пусто по /feed, /rss.xml, /atom.xml, /feed.json",
                fix="Включить генерацию RSS/Atom-ленты и добавить в HTML '<link rel=\"alternate\" type=\"application/rss+xml\" href=\"...\">'",
                hours=3.0,
            )
        ]
        score = 30

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="warning",
        score=score,
        findings=findings,
        raw={"feeds": results, "valid": []},
    )


# --------------------------------------------------------------------------- #
# Проверка 4: стабильность URL
# --------------------------------------------------------------------------- #
@check(id="url_stability", title="Стабильность URL и редиректы", category=CATEGORY)
async def url_stability(ctx: AuditContext) -> CheckResult:
    check_id = "url_stability"
    title = "Стабильность URL и редиректы"

    home = await ctx.home()
    if home is None:
        return _net_fail(check_id, title, "главную страницу")

    final_home = str(home.url)
    findings: List[Finding] = []
    status = "ok"
    score = 100

    # 1. http -> https.
    http_url = f"http://{ctx.host}"
    http_resp = await ctx.get(http_url, follow_redirects=False)
    https_redirect: Dict[str, Any] = {"url": http_url, "status": None, "location": None}
    if http_resp is not None:
        location = http_resp.headers.get("location", "")
        https_redirect = {"url": http_url, "status": http_resp.status_code, "location": location}
        if http_resp.status_code not in (301, 308):
            findings.append(
                Finding(
                    level="warning",
                    text=f"Переход http -> https не является постоянным (HTTP {http_resp.status_code})",
                    fix="Настроить постоянный редирект 301 с http на https на уровне веб-сервера",
                    hours=1.0,
                )
            )
            status = "warning"
            score = min(score, 75)
        elif "https://" not in location.lower():
            findings.append(
                Finding(
                    level="warning",
                    text="HTTP-версия не ведёт на HTTPS",
                    fix="Настроить редирект http -> https для всего сайта",
                    hours=1.0,
                )
            )
            status = "warning"
            score = min(score, 70)
        else:
            findings.append(Finding(level="ok", text="HTTP постоянно (301) перенаправляется на HTTPS", fix=""))

    # 2. www / non-www.
    host = ctx.host
    if host.startswith("www."):
        variant_host = host[4:]
    else:
        variant_host = "www." + host
    scheme = urlparse(ctx.base).scheme
    variant_url = f"{scheme}://{variant_host}"
    variant_resp = await ctx.get(variant_url, follow_redirects=False)
    www_consolidation: Dict[str, Any] = {"url": variant_url, "status": None, "location": None}
    if variant_resp is not None:
        location = variant_resp.headers.get("location", "")
        www_consolidation = {"url": variant_url, "status": variant_resp.status_code, "location": location}
        if variant_resp.status_code in (0, 200):
            findings.append(
                Finding(
                    level="critical",
                    text=f"Дубликат хоста: и {ctx.host}, и {variant_host} отдают 200 без склейки",
                    fix=f"Настроить 301-редирект с {variant_host} на {ctx.host} (или наоборот) и закрепить основной хост в canonical",
                    hours=1.5,
                )
            )
            status = "critical"
            score = 0
        elif ctx.host not in location:
            findings.append(
                Finding(
                    level="warning",
                    text=f"Дубль хоста {variant_host} перенаправляется не на основной хост {ctx.host}",
                    fix=f"Настроить 301-редирект с {variant_host} на {ctx.host}",
                    hours=1.0,
                )
            )
            if status != "critical":
                status = "warning"
            score = min(score, 75) if score else score

    # 3. Длина цепочки редиректов.
    chain = await _redirect_chain(ctx, final_home)
    chain_len = max(0, len(chain) - 1)
    if chain_len > 2:
        findings.append(
            Finding(
                level="warning",
                text=f"Длинная цепочка редиректов главной: {chain_len} переход(ов)",
                fix="Сократить цепочку до одного редиректа на итоговый URL",
                hours=1.5,
            )
        )
        if status != "critical":
            status = "warning"
        score = min(score, 80) if score else score

    # 4. Единообразие концевого слэша.
    with_slash = await ctx.get(f"{ctx.base}/", follow_redirects=True)
    final_slash = str(with_slash.url) if with_slash is not None else None
    if final_slash is not None and _norm_url(final_slash) != _norm_url(final_home):
        findings.append(
            Finding(
                level="warning",
                text=f"Неединообразный концевой слэш: {ctx.base} и {ctx.base}/ ведут на разные URL",
                fix="Выбрать один вариант (со слэшем или без) и настроить 301-редирект для другого по всему сайту",
                hours=1.5,
            )
        )
        if status != "critical":
            status = "warning"
        score = min(score, 80) if score else score

    # 5. canonical главной совпадает с итоговым URL.
    meta = extract_page_meta(home.text or "")
    canonical = meta["canonical"]
    canonical_match: Optional[bool] = None
    if canonical:
        resolved = urljoin(final_home, canonical)
        canonical_match = _norm_url(resolved) == _norm_url(final_home)
        if not canonical_match:
            findings.append(
                Finding(
                    level="warning",
                    text=f"Canonical главной ({canonical}) не совпадает с итоговым URL ({final_home})",
                    fix="Указать в canonical главной точный итоговый URL (после редиректов, с нужным хостом и слэшем)",
                    hours=0.5,
                )
            )
            if status != "critical":
                status = "warning"
            score = min(score, 85) if score else score
    else:
        findings.append(
            Finding(
                level="info",
                text="На главной нет тега canonical",
                fix="Добавить '<link rel=\"canonical\" href=\"{итоговый URL главной}\">' для консолидации дублей",
                hours=0.5,
            )
        )

    # 6. Слаги внутренних ссылок.
    tree = await ctx.home_tree()
    links: List[str] = []
    if tree is not None:
        for node in tree.css("a[href]"):
            href = node.attributes.get("href")
            if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            links.append(urljoin(final_home, href))
    slugs = analyze_slugs(links, ctx.host)
    if slugs["total"]:
        problems = []
        if slugs["non_kebab_count"]:
            problems.append(f"слаги не в kebab-case/lowercase — {slugs['non_kebab_count']} (например: {', '.join(slugs['non_kebab'][:3])})")
        if slugs["params_count"]:
            problems.append(f"URL с query-параметрами — {slugs['params_count']} (например: {', '.join(slugs['params'][:3])})")
        if problems:
            findings.append(
                Finding(
                    level="warning",
                    text="Неаккуратные URL внутренних ссылок: " + "; ".join(problems),
                    fix="Привести слаги к нижнему регистру и kebab-case (слова через дефис), убрать лишние query-параметры из URL содержимого",
                    hours=2.0,
                )
            )
            if status != "critical":
                status = "warning"
            score = min(score, 70) if score else score
        else:
            findings.append(
                Finding(level="ok", text=f"Слаги внутренних ссылок корректны (проверено {slugs['total']})", fix="")
            )

    if status == "ok" and not findings:
        findings.append(Finding(level="ok", text="URL стабильны, редиректы и canonical в порядке", fix=""))

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "final_home": final_home,
            "http_redirect": https_redirect,
            "www_consolidation": www_consolidation,
            "redirect_chain": chain,
            "chain_length": chain_len,
            "final_with_slash": final_slash,
            "canonical": canonical,
            "canonical_match": canonical_match,
            "slugs": slugs,
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 5: soft 404
# --------------------------------------------------------------------------- #
@check(id="soft_404", title="Мягкие 404 (soft 404)", category=CATEGORY)
async def soft_404(ctx: AuditContext) -> CheckResult:
    check_id = "soft_404"
    title = "Мягкие 404 (soft 404)"
    token = random.randint(100000, 999999)
    url = f"{ctx.base}/this-page-does-not-exist-{token}"

    resp = await ctx.get(url, follow_redirects=True)
    if resp is None:
        return _net_fail(check_id, title, "несуществующий URL")

    status_code = resp.status_code
    final_url = str(resp.url)

    if status_code in (404, 410):
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="ok",
            score=100,
            findings=[
                Finding(
                    level="ok",
                    text=f"Несуществующий URL корректно отдаёт HTTP {status_code}",
                    fix="",
                )
            ],
            raw={"url": url, "status": status_code, "final_url": final_url},
        )

    if status_code in (301, 302, 307, 308):
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=60,
            findings=[
                Finding(
                    level="warning",
                    text=f"Несуществующий URL перенаправлен ({status_code}) на {final_url} вместо 404",
                    fix="Отдавать для несуществующих страниц статус 404/410, а не редирект на главную",
                    hours=1.0,
                )
            ],
            raw={"url": url, "status": status_code, "final_url": final_url},
        )

    if status_code == 200:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="critical",
            score=0,
            findings=[
                Finding(
                    level="critical",
                    text=f"Soft 404: несуществующий URL {url} отдаёт HTTP 200 (страница-заглушка вместо 404)",
                    fix="Настроить сервер и CMS так, чтобы несуществующие адреса возвращали статус 404/410, а не страницу с 200",
                    hours=2.0,
                )
            ],
            raw={"url": url, "status": status_code, "final_url": final_url},
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="warning",
        score=50,
        findings=[
            Finding(
                level="warning",
                text=f"Несуществующий URL вернул неожиданный статус HTTP {status_code}",
                fix="Настроить корректный ответ 404/410 для несуществующих адресов",
                hours=1.0,
            )
        ],
        raw={"url": url, "status": status_code, "final_url": final_url},
    )


# --------------------------------------------------------------------------- #
# Проверка 6: hreflang
# --------------------------------------------------------------------------- #
@check(id="hreflang", title="Разметка hreflang", category=CATEGORY)
async def hreflang(ctx: AuditContext) -> CheckResult:
    check_id = "hreflang"
    title = "Разметка hreflang"

    home = await ctx.home()
    if home is None:
        return _net_fail(check_id, title, "главную страницу")

    final_home = str(home.url)
    entries = extract_hreflang(home.text or "")

    if not entries:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=70,
            findings=[
                Finding(
                    level="warning",
                    text="На главной не найдено ни одного тега hreflang",
                    fix="Для многоязычного/мультирегионального сайта добавить '<link rel=\"alternate\" hreflang=\"...\" href=\"...\">' на все языковые версии и x-default",
                    hours=2.0,
                )
            ],
            raw={"entries": [], "final_home": final_home},
        )

    languages = [e["hreflang"].lower() for e in entries]
    has_x_default = "x-default" in languages
    self_reference = any(_norm_url(urljoin(final_home, e["href"])) == _norm_url(final_home) for e in entries)

    findings: List[Finding] = []
    status = "ok"
    score = 100

    findings.append(
        Finding(level="ok", text=f"Найдено hreflang-тегов: {len(entries)} ({', '.join(sorted(set(languages)))})", fix="")
    )
    if not has_x_default:
        findings.append(
            Finding(
                level="warning",
                text="Отсутствует hreflang=\"x-default\"",
                fix="Добавить тег с hreflang=\"x-default\" на страницу выбора языка/основную версию",
                hours=0.5,
            )
        )
        status = "warning"
        score = min(score, 85)
    if not self_reference:
        findings.append(
            Finding(
                level="warning",
                text="Нет самоссылки: hreflang не указывает на саму главную",
                fix="Добавить на каждую страницу hreflang-тег на саму себя — это требование корректной разметки",
                hours=0.5,
            )
        )
        status = "warning"
        score = min(score, 85)

    # Проверка альтернативных версий: доступность и взаимность.
    checked: List[Dict[str, Any]] = []
    for entry in entries[:HREFLANG_SAMPLE_SIZE]:
        if entry["hreflang"].lower() == "x-default":
            continue
        target = urljoin(final_home, entry["href"])
        resp = await ctx.get(target)
        code = resp.status_code if resp is not None else None
        back = False
        if resp is not None and resp.status_code == 200:
            back_entries = extract_hreflang(resp.text or "")
            back = any(urlparse(urljoin(target, b["href"])).netloc.lower() == urlparse(final_home).netloc.lower() for b in back_entries)
        checked.append({"hreflang": entry["hreflang"], "url": target, "status": code, "reciprocal": back})

        if code != 200:
            findings.append(
                Finding(
                    level="warning",
                    text=f"Альтернативная версия {target} (hreflang={entry['hreflang']}) недоступна: HTTP {code if code is not None else 'нет ответа'}",
                    fix="Исправить или удалить битые hreflang-ссылки: каждая альтернативная версия должна отдавать 200",
                    hours=1.0,
                )
            )
            status = "warning"
            score = min(score, 70)
        elif not back:
            findings.append(
                Finding(
                    level="warning",
                    text=f"Нет взаимной ссылки: {target} (hreflang={entry['hreflang']}) не ссылается обратно на {ctx.host}",
                    fix="На каждой языковой версии добавить hreflang-теги на все версии, включая исходную (двусторонняя связь)",
                    hours=1.5,
                )
            )
            status = "warning"
            score = min(score, 75)

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "entries": entries,
            "final_home": final_home,
            "x_default": has_x_default,
            "self_reference": self_reference,
            "checked": checked,
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 7: условный GET
# --------------------------------------------------------------------------- #
@check(id="conditional_get", title="Условный GET (304) и кеширование", category=CATEGORY)
async def conditional_get(ctx: AuditContext) -> CheckResult:
    check_id = "conditional_get"
    title = "Условный GET (304) и кеширование"

    home = await ctx.home()
    if home is None:
        return _net_fail(check_id, title, "главную страницу")

    last_modified = home.headers.get("last-modified", "")
    etag = home.headers.get("etag", "")
    cache_control = home.headers.get("cache-control", "")

    validators = {"last_modified": last_modified, "etag": etag, "cache_control": cache_control}

    if not etag and not last_modified:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=60,
            findings=[
                Finding(
                    level="warning",
                    text="Сервер не отдаёт валидаторы Last-Modified/ETag — браузер и робот не могут использовать условный GET",
                    fix="Включить отдачу заголовков Last-Modified и/или ETag на HTML-страницы",
                    hours=1.5,
                )
            ],
            raw=validators,
        )

    findings: List[Finding] = []
    status = "ok"
    score = 100
    checks: Dict[str, Any] = {}

    if etag:
        resp = await ctx.get(ctx.url, headers={"If-None-Match": etag})
        code = resp.status_code if resp is not None else None
        checks["if_none_match"] = {"sent": etag, "status": code}
        if code == 304:
            findings.append(Finding(level="ok", text=f"If-None-Match ({etag}) вернул 304 Not Modified", fix=""))
        else:
            findings.append(
                Finding(
                    level="warning",
                    text=f"If-None-Match ({etag}) вернул HTTP {code}, ожидался 304",
                    fix="Проверить обработку заголовка If-None-Match на стороне сервера/CDN и сравнение ETag",
                    hours=2.0,
                )
            )
            status = "warning"
            score = min(score, 60)

    if last_modified:
        resp = await ctx.get(ctx.url, headers={"If-Modified-Since": last_modified})
        code = resp.status_code if resp is not None else None
        checks["if_modified_since"] = {"sent": last_modified, "status": code}
        if code == 304:
            findings.append(Finding(level="ok", text=f"If-Modified-Since ({last_modified}) вернул 304 Not Modified", fix=""))
        else:
            findings.append(
                Finding(
                    level="warning",
                    text=f"If-Modified-Since ({last_modified}) вернул HTTP {code}, ожидался 304",
                    fix="Проверить обработку заголовка If-Modified-Since и корректность Last-Modified",
                    hours=1.5,
                )
            )
            status = "warning"
            score = min(score, 60)

    if not cache_control:
        findings.append(
            Finding(
                level="info",
                text="Не задан заголовок Cache-Control для главной",
                fix="Добавить Cache-Control с разумным max-age для статики и подходящей политикой для HTML",
                hours=1.0,
            )
        )
        if status == "ok":
            status = "warning"
        score = min(score, 90)

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={**validators, "checks": checks},
    )


# --------------------------------------------------------------------------- #
# Проверка 8: HTTP-заголовки (информационная)
# --------------------------------------------------------------------------- #
@check(id="http_headers", title="HTTP-заголовки главной страницы", category=CATEGORY)
async def http_headers(ctx: AuditContext) -> CheckResult:
    check_id = "http_headers"
    title = "HTTP-заголовки главной страницы"

    home = await ctx.home()
    if home is None:
        return _net_fail(check_id, title, "HTTP-заголовки главной")

    headers = {key: value for key, value in home.headers.items()}

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="ok",
        score=100,
        findings=[
            Finding(
                level="info",
                text=f"Получено заголовков ответа: {len(headers)} (полный список — в поле raw)",
                fix="",
            )
        ],
        raw={"url": str(home.url), "headers": headers},
    )


# --------------------------------------------------------------------------- #
# Проверка 9: заголовки безопасности
# --------------------------------------------------------------------------- #
@check(id="security_headers", title="Заголовки безопасности", category=CATEGORY)
async def security_headers(ctx: AuditContext) -> CheckResult:
    check_id = "security_headers"
    title = "Заголовки безопасности"

    home = await ctx.home()
    if home is None:
        return _net_fail(check_id, title, "заголовки безопасности")

    headers = home.headers
    hsts = headers.get("strict-transport-security", "")
    hsts_max_age = parse_hsts_max_age(hsts)
    csp = headers.get("content-security-policy", "")
    xfo = headers.get("x-frame-options", "")
    nosniff = headers.get("x-content-type-options", "")
    referrer = headers.get("referrer-policy", "")
    permissions = headers.get("permissions-policy", "")

    findings: List[Finding] = []
    present = 0

    if hsts_max_age is not None and hsts_max_age >= HSTS_MIN_MAX_AGE:
        present += 1
        findings.append(Finding(level="ok", text=f"HSTS включён (max-age={hsts_max_age})", fix=""))
    else:
        findings.append(
            Finding(
                level="warning",
                text=f"HSTS не настроен или max-age мал ({hsts_max_age if hsts_max_age is not None else 'нет заголовка'}), рекомендуется >= {HSTS_MIN_MAX_AGE}",
                fix=f"Добавить заголовок Strict-Transport-Security: max-age={HSTS_MIN_MAX_AGE}; includeSubDomains",
                hours=1.0,
            )
        )

    if csp:
        present += 1
        findings.append(Finding(level="ok", text="Content-Security-Policy задан", fix=""))
    else:
        findings.append(
            Finding(
                level="warning",
                text="Не задан Content-Security-Policy",
                fix="Добавить Content-Security-Policy (можно начать с report-only) для защиты от XSS",
                hours=4.0,
            )
        )

    frame_protected = bool(xfo) or ("frame-ancestors" in csp.lower())
    if frame_protected:
        present += 1
        findings.append(Finding(level="ok", text="Защита от встраивания в iframe настроена", fix=""))
    else:
        findings.append(
            Finding(
                level="warning",
                text="Нет защиты от кликджекинга (X-Frame-Options или frame-ancestors в CSP)",
                fix="Добавить X-Frame-Options: SAMEORIGIN либо директиву frame-ancestors в CSP",
                hours=0.5,
            )
        )

    if "nosniff" in nosniff.lower():
        present += 1
        findings.append(Finding(level="ok", text="X-Content-Type-Options: nosniff задан", fix=""))
    else:
        findings.append(
            Finding(
                level="warning",
                text="Не задан X-Content-Type-Options: nosniff",
                fix="Добавить заголовок X-Content-Type-Options: nosniff",
                hours=0.25,
            )
        )

    if referrer:
        present += 1
        findings.append(Finding(level="ok", text=f"Referrer-Policy задан ({referrer})", fix=""))
    else:
        findings.append(
            Finding(
                level="warning",
                text="Не задан Referrer-Policy",
                fix="Добавить Referrer-Policy: strict-origin-when-cross-origin",
                hours=0.25,
            )
        )

    if permissions:
        present += 1
        findings.append(Finding(level="ok", text="Permissions-Policy задан", fix=""))
    else:
        findings.append(
            Finding(
                level="warning",
                text="Не задан Permissions-Policy",
                fix="Добавить Permissions-Policy и отключить ненужные API (camera, microphone, geolocation)",
                hours=0.5,
            )
        )

    score = int(round(present / 6 * 100))
    status = "ok" if present == 6 else "warning"

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "hsts": hsts,
            "hsts_max_age": hsts_max_age,
            "csp": csp,
            "x_frame_options": xfo,
            "x_content_type_options": nosniff,
            "referrer_policy": referrer,
            "permissions_policy": permissions,
            "present": present,
            "total": 6,
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 10: утечки версий
# --------------------------------------------------------------------------- #
@check(id="version_leaks", title="Утечки версий сервера и движка", category=CATEGORY)
async def version_leaks(ctx: AuditContext) -> CheckResult:
    check_id = "version_leaks"
    title = "Утечки версий сервера и движка"

    home = await ctx.home()
    if home is None:
        return _net_fail(check_id, title, "главную страницу")

    powered_by = home.headers.get("x-powered-by", "")
    server = home.headers.get("server", "")
    generator_header = home.headers.get("x-generator", "")
    meta_generators = find_generators(home.text or "")

    php_version = parse_php_version(powered_by) or parse_php_version(server)
    outdated_php = is_php_outdated(php_version)

    leaks: List[str] = []
    if powered_by:
        leaks.append(f"X-Powered-By: {powered_by}")
    if re.search(r"\d+\.\d+", server):
        leaks.append(f"Server: {server}")
    if generator_header:
        leaks.append(f"X-Generator: {generator_header}")
    for gen in meta_generators:
        leaks.append(f"meta generator: {gen}")

    findings: List[Finding] = []
    status = "ok"
    score = 100

    if outdated_php:
        findings.append(
            Finding(
                level="critical",
                text=f"Используется устаревшая версия PHP {php_version[0]}.{php_version[1]} (< 8.1) — риск уязвимостей",
                fix="Обновить PHP до актуальной поддерживаемой версии (8.1+) и скрыть её версию в заголовках",
                hours=8.0,
            )
        )
        status = "critical"
        score = 0

    if leaks:
        findings.append(
            Finding(
                level="warning",
                text="Сервер раскрывает версии/технологии: " + "; ".join(leaks[:5]),
                fix="Скрыть версии: убрать заголовки X-Powered-By/X-Generator (expose_php=Off, ServerTokens Prod) и meta name=\"generator\"",
                hours=1.0,
            )
        )
        if status != "critical":
            status = "warning"
            score = min(score, 75)
    else:
        findings.append(Finding(level="ok", text="Утечек версий сервера и движка не обнаружено", fix=""))

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "x_powered_by": powered_by,
            "server": server,
            "x_generator": generator_header,
            "meta_generators": meta_generators,
            "php_version": list(php_version) if php_version else None,
            "outdated_php": outdated_php,
            "leaks": leaks,
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 11: базовые показатели производительности
# --------------------------------------------------------------------------- #
@check(id="performance_basic", title="Базовые показатели производительности", category=CATEGORY)
async def performance_basic(ctx: AuditContext) -> CheckResult:
    check_id = "performance_basic"
    title = "Базовые показатели производительности"

    home = await ctx.home()
    if home is None:
        return _net_fail(check_id, title, "главную страницу")

    # Свежий запрос с измерением TTFB и полного времени.
    timing: Dict[str, Any]
    client = ctx.client
    if client is None:
        timing = {"ttfb_ms": None, "total_ms": None, "content_encoding": "", "bytes": len(home.content or b"")}
    else:
        start = time.perf_counter()
        try:
            async with client.stream(
                "GET", ctx.url, headers={"Accept-Encoding": "gzip, br"}, follow_redirects=True
            ) as resp:
                ttfb = time.perf_counter() - start
                size = 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                timing = {
                    "ttfb_ms": round(ttfb * 1000, 1),
                    "total_ms": round((time.perf_counter() - start) * 1000, 1),
                    "content_encoding": resp.headers.get("content-encoding", ""),
                    "bytes": size,
                }
        except Exception:  # noqa: BLE001 - сбой отдельного запроса не должен ломать чек
            timing = {"ttfb_ms": None, "total_ms": None, "content_encoding": "", "bytes": len(home.content or b"")}

    html = home.text or ""
    html_size = len(html.encode("utf-8"))
    assets = count_assets(html)
    alt_svc = home.headers.get("alt-svc", "")

    ttfb_ms = timing.get("ttfb_ms")
    total_ms = timing.get("total_ms")
    encoding = (timing.get("content_encoding") or "").lower()

    findings: List[Finding] = []
    status = "ok"
    score = 100

    findings.append(
        Finding(
            level="info",
            text=(
                f"TTFB: {ttfb_ms if ttfb_ms is not None else 'н/д'} мс, полное время: "
                f"{total_ms if total_ms is not None else 'н/д'} мс, размер HTML: {html_size} байт"
            ),
            fix="",
        )
    )

    if ttfb_ms is not None and ttfb_ms > 800:
        findings.append(
            Finding(
                level="warning",
                text=f"Высокий TTFB главной страницы: {ttfb_ms} мс",
                fix="Включить серверное/полностраничное кеширование, оптимизировать бэкенд и базу данных, использовать CDN",
                hours=6.0,
            )
        )
        status = "warning"
        score = min(score, 70)

    if total_ms is not None and total_ms > 3000:
        findings.append(
            Finding(
                level="warning",
                text=f"Большое полное время загрузки HTML: {total_ms} мс",
                fix="Уменьшить размер HTML, вынести критический CSS, отложить подключаемые скрипты, включить сжатие",
                hours=4.0,
            )
        )
        status = "warning"
        score = min(score, 75)

    if encoding:
        findings.append(Finding(level="ok", text=f"Сжатие включено (Content-Encoding: {encoding})", fix=""))
    else:
        findings.append(
            Finding(
                level="warning",
                text="HTML не сжимается (нет Content-Encoding)",
                fix="Включить gzip/brotli для HTML на веб-сервере или CDN",
                hours=1.0,
            )
        )
        status = "warning"
        score = min(score, 80)

    if assets["scripts"] > 20:
        findings.append(
            Finding(
                level="warning",
                text=f"Много внешних скриптов: {assets['scripts']}",
                fix="Объединить и отложить скрипты (defer/async), удалить неиспользуемые библиотеки",
                hours=4.0,
            )
        )
        status = "warning"
        score = min(score, 80)

    if assets["stylesheets"] > 8:
        findings.append(
            Finding(
                level="warning",
                text=f"Много подключаемых таблиц стилей: {assets['stylesheets']}",
                fix="Объединить CSS-файлы и критический CSS встроить инлайном",
                hours=3.0,
            )
        )
        status = "warning"
        score = min(score, 85)

    if "h3" in alt_svc.lower():
        findings.append(Finding(level="ok", text="HTTP/3 (h3) рекламируется через Alt-Svc", fix=""))
    else:
        findings.append(
            Finding(
                level="info",
                text="Alt-Svc с поддержкой HTTP/3 не обнаружен",
                fix="Включить HTTP/3 на сервере/CDN для ускорения загрузки",
                hours=2.0,
            )
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "url": str(home.url),
            **timing,
            "html_size_bytes": html_size,
            "scripts": assets["scripts"],
            "stylesheets": assets["stylesheets"],
            "alt_svc": alt_svc,
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 12: смешанный контент
# --------------------------------------------------------------------------- #
@check(id="mixed_content", title="Смешанный контент (http на https)", category=CATEGORY)
async def mixed_content(ctx: AuditContext) -> CheckResult:
    check_id = "mixed_content"
    title = "Смешанный контент (http на https)"

    home = await ctx.home()
    if home is None:
        return _net_fail(check_id, title, "главную страницу")

    if urlparse(str(home.url)).scheme != "https":
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=[
                Finding(
                    level="info",
                    text="Сайт работает по HTTP — проверка смешанного контента неприменима",
                    fix="Перевести сайт на HTTPS",
                    hours=2.0,
                )
            ],
            raw={"scheme": "http"},
        )

    mixed = find_mixed_content(home.text or "")

    if not mixed:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="ok",
            score=100,
            findings=[Finding(level="ok", text="HTTP-ресурсов на HTTPS-странице не найдено", fix="")],
            raw={"count": 0, "items": []},
        )

    examples = ", ".join(f"<{item['tag']} {item['attribute']}=\"{item['url']}\">" for item in mixed[:5])
    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="warning",
        score=40,
        findings=[
            Finding(
                level="warning",
                text=f"Смешанный контент: {len(mixed)} ресурс(ов) загружается по http (например: {examples})",
                fix="Заменить все http://-адреса ресурсов на https:// или на относительные (протокол-независимые) ссылки",
                hours=2.0,
            )
        ],
        raw={"count": len(mixed), "items": mixed},
    )
