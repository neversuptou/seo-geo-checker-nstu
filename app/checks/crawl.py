"""Краулинг сайта: обход до N страниц и проверки, которые видны только по всему сайту.

Один обход на аудит (кэшируется в ctx), все проверки этой категории используют его результат.
В бережном режиме — меньше страниц и запросы по одному (темп задаёт транспорт в app/core.py).
"""
from __future__ import annotations

import asyncio
import re
from collections import Counter, defaultdict, deque
from typing import Any, Dict, List, Optional
from urllib.parse import urldefrag, urljoin, urlparse

from selectolax.lexbor import LexborHTMLParser

from app.core import AuditContext, CheckResult, Finding
from app.registry import check

CATEGORY = "Краулинг сайта"
MAX_PAGES, MAX_PAGES_GENTLE = 150, 40
MAX_DEPTH = 6
THIN_WORDS = 150
EXAMPLES = 10

SKIP_EXT = re.compile(
    r"\.(jpe?g|png|gif|webp|avif|svg|ico|bmp|pdf|zip|rar|7z|gz|mp4|mp3|webm|avi|mov|js|css|xml|json|txt|woff2?|ttf|eot|docx?|xlsx?)$",
    re.I,
)
SKIP_QUERY = re.compile(r"add-to-cart|add_to_wishlist|orderby|filter_|replytocom|sessionid|wishlist-action|share=", re.I)


def _bare_host(host: str) -> str:
    host = (host or "").lower()
    return host[4:] if host.startswith("www.") else host


def normalize_url(url: str, base: str) -> Optional[str]:
    """Абсолютный URL того же сайта без фрагмента; None — внешний, служебный или не-HTML."""
    if not url or url.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
        return None
    absolute, _ = urldefrag(urljoin(base, url.strip()))
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https"):
        return None
    if _bare_host(parsed.hostname or "") != _bare_host(urlparse(base).hostname or ""):
        return None
    if SKIP_EXT.search(parsed.path) or SKIP_QUERY.search(parsed.query):
        return None
    return parsed._replace(netloc=(parsed.netloc or "").lower(), path=parsed.path or "/").geturl()


def extract_page_data(html: str, url: str) -> Dict[str, Any]:
    """title, description, H1, canonical, noindex, число слов видимого текста и внутренние ссылки."""
    tree = LexborHTMLParser(html or "")

    def meta(name: str) -> str:
        node = tree.css_first(f'meta[name="{name}"]')
        return (node.attributes.get("content") or "").strip() if node is not None else ""

    title_node = tree.css_first("title")
    canonical_node = tree.css_first('link[rel="canonical"]')
    links: List[str] = []
    for a in tree.css("a[href]"):
        if "nofollow" in (a.attributes.get("rel") or ""):
            continue
        norm = normalize_url(a.attributes.get("href") or "", url)
        if norm and norm not in links:
            links.append(norm)

    for node in tree.css("script, style, noscript, nav, header, footer, svg, template"):
        node.decompose()
    body = tree.body
    words = len(re.findall(r"\w{2,}", body.text(separator=" ") if body is not None else ""))

    return {
        "title": title_node.text(strip=True) if title_node is not None else "",
        "description": meta("description"),
        "h1": [h.text(strip=True) for h in LexborHTMLParser(html or "").css("h1")],
        "canonical": urljoin(url, canonical_node.attributes.get("href") or "") if canonical_node is not None else "",
        "noindex": "noindex" in meta("robots").lower(),
        "words": words,
        "links": links,
    }


def find_duplicates(pages: List[Dict[str, Any]], field: str) -> Dict[str, List[str]]:
    """Одинаковые непустые значения поля (title/description/первый H1) на разных индексируемых страницах."""
    groups: Dict[str, List[str]] = defaultdict(list)
    for page in pages:
        value = page.get(field)
        if isinstance(value, list):
            value = value[0] if value else ""
        value = (value or "").strip().lower()
        if value:
            groups[value].append(page["url"])
    return {value: urls for value, urls in groups.items() if len(urls) > 1}


def disallow_patterns(robots_txt: str) -> List[re.Pattern]:
    """Disallow из группы User-agent: * как регулярки с поддержкой * и $ (Allow не учитываем — обход и так ограничен)."""
    patterns: List[re.Pattern] = []
    applies = False
    for line in (robots_txt or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            applies = value == "*"
        elif key == "disallow" and applies and value:
            anchored = value.endswith("$")
            body = re.escape(value.rstrip("$")).replace(r"\*", ".*")
            patterns.append(re.compile("^" + body + ("$" if anchored else "")))
    return patterns


def _blocked(url: str, patterns: List[re.Pattern]) -> bool:
    parsed = urlparse(url)
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    return any(p.match(target) for p in patterns)


async def get_crawl(ctx: AuditContext) -> Dict[str, Any]:
    """Обойти сайт один раз за аудит; параллельные вызовы ждут общий результат."""
    lock = ctx.__dict__.setdefault("_crawl_lock", asyncio.Lock())
    async with lock:
        cached = getattr(ctx, "_crawl", None)
        if cached is not None:
            return cached
        result = await _crawl(ctx)
        ctx._crawl = result  # type: ignore[attr-defined]
        return result


async def _crawl(ctx: AuditContext) -> Dict[str, Any]:
    limit = MAX_PAGES_GENTLE if ctx.gentle else MAX_PAGES
    robots = await ctx.get(f"{ctx.base}/robots.txt")
    disallowed = disallow_patterns(robots.text) if robots is not None and robots.status_code == 200 else []

    start = normalize_url(ctx.url, ctx.url) or ctx.url
    queue: deque = deque([(start, 0)])
    seen = {start}
    pages: Dict[str, Dict[str, Any]] = {}
    sem = asyncio.Semaphore(2 if ctx.gentle else 6)

    async def fetch(url: str, depth: int) -> None:
        async with sem:
            resp = await ctx.get(url)
        page: Dict[str, Any] = {"url": url, "depth": depth, "status": None, "final_url": url, "links": []}
        if resp is not None:
            page["status"] = resp.status_code
            page["final_url"] = str(resp.url)
            page["redirected"] = bool(resp.history)
            if resp.status_code == 200 and "html" in resp.headers.get("content-type", ""):
                page.update(extract_page_data(resp.text, str(resp.url)))
        pages[url] = page

    while queue and len(pages) < limit:
        batch = []
        while queue and len(pages) + len(batch) < limit:
            batch.append(queue.popleft())
        await asyncio.gather(*(fetch(url, depth) for url, depth in batch))
        for url, depth in batch:
            if depth >= MAX_DEPTH:
                continue
            for link in pages[url].get("links", []):
                if link in seen or _blocked(link, disallowed):
                    continue
                seen.add(link)
                queue.append((link, depth + 1))

    inbound: Counter = Counter()
    for page in pages.values():
        for link in set(page.get("links", [])):
            if link != page["url"]:
                inbound[link] += 1
    for url, page in pages.items():
        page["inbound"] = inbound.get(url, 0)

    return {"pages": list(pages.values()), "limit": limit, "truncated": bool(queue), "discovered": len(seen)}


# --------------------------------------------------------------------------- #
# Проверки
# --------------------------------------------------------------------------- #
def _examples(urls: List[str]) -> str:
    shown = ", ".join(urls[:EXAMPLES])
    return shown + (f" и ещё {len(urls) - EXAMPLES}" if len(urls) > EXAMPLES else "")


def _scope(crawl: Dict[str, Any]) -> str:
    note = f" (лимит {crawl['limit']}, найдено ссылок {crawl['discovered']})" if crawl["truncated"] else ""
    return f"Обойдено страниц: {len(crawl['pages'])}{note}"


def _indexable(pages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """200, HTML, без noindex и без canonical на другую страницу."""
    out = []
    for page in pages:
        if page.get("status") != 200 or "title" not in page or page.get("noindex"):
            continue
        canonical = (page.get("canonical") or "").rstrip("/")
        if canonical and canonical != page["final_url"].rstrip("/"):
            continue
        out.append(page)
    return out


def _result(cid: str, title: str, findings: List[Finding], raw: Dict[str, Any]) -> CheckResult:
    levels = {f.level for f in findings}
    status = "critical" if "critical" in levels else "warning" if "warning" in levels else "ok"
    score = {"critical": 30, "warning": 70, "ok": 100}[status]
    return CheckResult(id=cid, title=title, category=CATEGORY, status=status, score=score, findings=findings, raw=raw)


@check(id="crawl_status", title="Коды ответа страниц сайта", category=CATEGORY)
async def crawl_status(ctx: AuditContext) -> CheckResult:
    crawl = await get_crawl(ctx)
    pages = crawl["pages"]
    broken = [p["url"] for p in pages if p.get("status") is None or p["status"] >= 400]
    redirects = [p["url"] for p in pages if p.get("redirected")]
    findings = [Finding("ok", _scope(crawl))]
    if broken:
        findings.append(Finding(
            "critical", f"Битые внутренние страницы (4xx/5xx или нет ответа): {len(broken)} — {_examples(broken)}",
            fix="Исправить или удалить ссылки на эти страницы; удалённые страницы перенаправить 301 на релевантные",
            hours=max(1.0, len(broken) * 0.1),
        ))
    if redirects:
        findings.append(Finding(
            "warning", f"Внутренние ссылки ведут на редиректы: {len(redirects)} — {_examples(redirects)}",
            fix="Заменить в меню, шаблонах и тексте ссылки на конечные URL, чтобы не тратить краулинговый бюджет",
            hours=max(0.5, len(redirects) * 0.05),
        ))
    return _result("crawl_status", "Коды ответа страниц сайта", findings, {"broken": broken, "redirects": redirects})


@check(id="crawl_duplicates", title="Дубли title, description и H1 по сайту", category=CATEGORY)
async def crawl_duplicates(ctx: AuditContext) -> CheckResult:
    crawl = await get_crawl(ctx)
    pages = _indexable(crawl["pages"])
    findings = [Finding("ok", f"{_scope(crawl)}, индексируемых: {len(pages)}")]
    raw: Dict[str, Any] = {}
    for field, label in (("title", "title"), ("description", "description"), ("h1", "H1")):
        dups = find_duplicates(pages, field)
        raw[field] = dups
        if not dups:
            continue
        affected = sum(len(urls) for urls in dups.values())
        top_value, top_urls = max(dups.items(), key=lambda item: len(item[1]))
        share = affected / max(len(pages), 1)
        level = "critical" if field == "title" and share > 0.2 else "warning"
        findings.append(Finding(
            level,
            f"Повторяющиеся {label}: {len(dups)} групп, страниц {affected} ({share:.0%}). "
            f"Чаще всего «{top_value[:80]}» — {len(top_urls)} стр.: {_examples(top_urls)}",
            fix=f"Сделать {label} уникальным для каждой страницы (шаблон с названием товара/категории); "
                "дубли контента закрыть canonical",
            hours=max(1.0, len(dups) * 0.25),
        ))
    return _result("crawl_duplicates", "Дубли title, description и H1 по сайту", findings, raw)


@check(id="crawl_meta_missing", title="Страницы без title, description или H1", category=CATEGORY)
async def crawl_meta_missing(ctx: AuditContext) -> CheckResult:
    crawl = await get_crawl(ctx)
    pages = _indexable(crawl["pages"])
    groups = {
        "без title": [p["url"] for p in pages if not p.get("title")],
        "без description": [p["url"] for p in pages if not p.get("description")],
        "без H1": [p["url"] for p in pages if not p.get("h1")],
        "с несколькими H1": [p["url"] for p in pages if len(p.get("h1") or []) > 1],
    }
    findings = [Finding("ok", f"{_scope(crawl)}, индексируемых: {len(pages)}")]
    for label, urls in groups.items():
        if urls:
            findings.append(Finding(
                "critical" if label == "без title" else "warning",
                f"Страниц {label}: {len(urls)} — {_examples(urls)}",
                fix="Заполнить мета-теги и заголовок в шаблоне страницы; H1 — ровно один, о главной теме страницы",
                hours=max(0.5, len(urls) * 0.1),
            ))
    return _result("crawl_meta_missing", "Страницы без title, description или H1", findings, groups)


@check(id="crawl_thin_content", title="Страницы с малым количеством текста", category=CATEGORY)
async def crawl_thin_content(ctx: AuditContext) -> CheckResult:
    crawl = await get_crawl(ctx)
    pages = _indexable(crawl["pages"])
    thin = [p["url"] for p in pages if p.get("words", 0) < THIN_WORDS]
    findings = [Finding("ok", f"{_scope(crawl)}, индексируемых: {len(pages)}")]
    if thin:
        share = len(thin) / max(len(pages), 1)
        findings.append(Finding(
            "critical" if share > 0.3 else "warning",
            f"Тонкий контент (< {THIN_WORDS} слов без меню и подвала): {len(thin)} стр. ({share:.0%}) — {_examples(thin)}",
            fix="Дописать полезный текст (описание, характеристики, FAQ) или закрыть служебные страницы noindex. "
                "Тонкие страницы хуже ранжируются и почти не цитируются ИИ",
            hours=max(1.0, len(thin) * 0.3),
        ))
    return _result("crawl_thin_content", "Страницы с малым количеством текста", findings, {"thin": thin})


@check(id="crawl_depth_links", title="Глубина вложенности и перелинковка", category=CATEGORY)
async def crawl_depth_links(ctx: AuditContext) -> CheckResult:
    crawl = await get_crawl(ctx)
    pages = _indexable(crawl["pages"])
    start = normalize_url(ctx.url, ctx.url)
    deep = [p["url"] for p in pages if p["depth"] > 3]
    weak = [p["url"] for p in pages if p["inbound"] <= 1 and p["url"] != start]
    dead_end = [p["url"] for p in pages if not p.get("links")]
    findings = [Finding("ok", f"{_scope(crawl)}, макс. глубина: {max((p['depth'] for p in pages), default=0)}")]
    if deep:
        findings.append(Finding(
            "warning", f"Страницы глубже 3 кликов от главной: {len(deep)} — {_examples(deep)}",
            fix="Добавить ссылки из меню, категорий, хлебных крошек или блоков «похожие»", hours=2,
        ))
    if weak:
        findings.append(Finding(
            "warning", f"Слабо перелинкованные страницы (≤ 1 входящей ссылки): {len(weak)} — {_examples(weak)}",
            fix="Усилить внутреннюю перелинковку: ссылки из тематических страниц и блоков рекомендаций", hours=2,
        ))
    if dead_end:
        findings.append(Finding(
            "info", f"Страницы без исходящих внутренних ссылок: {len(dead_end)} — {_examples(dead_end)}",
            fix="Добавить на страницы навигацию или ссылки на связанные материалы", hours=0.5,
        ))
    return _result("crawl_depth_links", "Глубина вложенности и перелинковка", findings,
                   {"deep": deep, "weak": weak, "dead_end": dead_end})


@check(id="crawl_noindex_canonical", title="noindex и canonical по сайту", category=CATEGORY)
async def crawl_noindex_canonical(ctx: AuditContext) -> CheckResult:
    crawl = await get_crawl(ctx)
    pages = [p for p in crawl["pages"] if p.get("status") == 200 and "title" in p]
    by_url = {p["final_url"].rstrip("/"): p for p in crawl["pages"]}
    noindex_linked = [p["url"] for p in pages if p.get("noindex") and p["inbound"] > 3]
    canon_other = [p["url"] for p in pages if p.get("canonical") and p["canonical"].rstrip("/") != p["final_url"].rstrip("/")]
    canon_broken = [
        p["url"] for p in pages
        if p.get("canonical") and (target := by_url.get(p["canonical"].rstrip("/"))) is not None and target.get("status") != 200
    ]
    findings = [Finding("ok", _scope(crawl))]
    if noindex_linked:
        findings.append(Finding(
            "warning", f"Страницы с noindex, на которые много внутренних ссылок: {len(noindex_linked)} — {_examples(noindex_linked)}",
            fix="Проверить, нужен ли noindex; если да — убрать на них ссылки из меню и шаблонов", hours=1,
        ))
    if canon_broken:
        findings.append(Finding(
            "critical", f"canonical указывает на недоступную страницу: {len(canon_broken)} — {_examples(canon_broken)}",
            fix="Исправить canonical на рабочий URL (обычно — на саму страницу)", hours=1,
        ))
    if canon_other:
        findings.append(Finding(
            "info", f"canonical указывает на другую страницу: {len(canon_other)} — {_examples(canon_other)}",
            fix="Убедиться, что это намеренная склейка дублей, а не ошибка шаблона", hours=0.5,
        ))
    return _result("crawl_noindex_canonical", "noindex и canonical по сайту", findings,
                   {"noindex_linked": noindex_linked, "canonical_other": canon_other, "canonical_broken": canon_broken})
