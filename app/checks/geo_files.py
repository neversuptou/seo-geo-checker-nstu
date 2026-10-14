"""GEO/AI checks: файлы и директивы, важные для генеративного поиска и AI-агентов.

Проверки:
- ai_robots          — правила robots.txt для AI-ботов (GPTBot, ClaudeBot и др.)
- content_signal     — директивы Content-Signal (search / ai-input / ai-train)
- llms_txt           — наличие и валидность /llms.txt по спецификации llmstxt.org
- llms_full_txt      — наличие и размер /llms-full.txt
- markdown_version   — markdown-версия страниц (.md, link rel=alternate, Accept)
- mcp_server_card    — /.well-known/mcp/server-card.json
- agent_skills_index — /.well-known/agent-skills/index.json
- ai_meta_directives — noai / noimageai / noindex / nosnippet / max-snippet

Чистая логика парсинга вынесена в отдельные синхронные функции без сети,
поэтому её можно покрывать юнит-тестами:
`parse_robots`, `is_allowed`, `parse_content_signals`, `validate_llms_txt`,
`find_markdown_link_tags`, `extract_meta_robots`, `parse_meta_directives`,
`looks_like_html`, `validate_server_card`.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from selectolax.lexbor import LexborHTMLParser

from app.core import AuditContext, CheckResult, Finding
from app.registry import check

CATEGORY = "GEO / AI"

# AI-боты, для которых важно явно описать правила доступа в robots.txt.
AI_BOTS: List[str] = [
    "GPTBot",
    "OAI-SearchBot",
    "ChatGPT-User",
    "ClaudeBot",
    "Claude-User",
    "Claude-SearchBot",
    "PerplexityBot",
    "Perplexity-User",
    "Google-Extended",
    "Applebot-Extended",
    "Bytespider",
    "CCBot",
    "YandexBot",
    "YandexAdditional",
    "meta-externalagent",
    "Amazonbot",
]

# Поисковые боты: их блокировка лишает сайт трафика, поэтому это critical.
SEARCH_BOTS: List[str] = [
    "OAI-SearchBot",
    "PerplexityBot",
    "Claude-SearchBot",
    "YandexBot",
]

# Директивы, нежелательные для GEO/AI-выдачи.
AI_META_DIRECTIVES: List[str] = ["noai", "noimageai", "noindex", "nosnippet", "max-snippet"]

# Директивы meta robots, которые имеет смысл анализировать.
META_ROBOTS_NAMES = {"robots", "googlebot", "yandex", "yandexbot", "bingbot"}

_MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\([^)]+\)")
_MARKDOWN_ALT_TYPES = ("text/markdown", "text/x-markdown")


# --------------------------------------------------------------------------- #
# Чистые функции: robots.txt
# --------------------------------------------------------------------------- #
def parse_robots(text: str) -> Dict[str, Any]:
    """Разобрать robots.txt в структуру групп правил.

    Возвращает словарь:
    {
        "groups": [
            {"user_agents": ["gptbot"], "rules": [{"type": "allow"|"disallow", "path": "/"}]}
        ],
        "sitemaps": [...],
        "crawl_delays": [...],
        "content_signals": {...},
    }

    Соседние строки User-agent объединяются в одну группу с общими правилами.
    """
    groups: List[Dict[str, Any]] = []
    sitemaps: List[str] = []
    crawl_delays: List[Dict[str, Any]] = []

    if text is None:
        text = ""
    text = text.lstrip("\ufeff")

    current: Optional[Dict[str, Any]] = None

    def new_group() -> Dict[str, Any]:
        group: Dict[str, Any] = {"user_agents": [], "rules": []}
        groups.append(group)
        return group

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()

        if field == "user-agent":
            # Новая группа начинается, если у текущей уже есть правила или её нет.
            if current is None or current["rules"]:
                current = new_group()
            current["user_agents"].append(value)
        elif field in ("allow", "disallow"):
            if current is None:
                current = new_group()
                current["user_agents"].append("*")
            current["rules"].append({"type": field, "path": value})
        elif field == "sitemap":
            if value:
                sitemaps.append(value)
        elif field == "crawl-delay":
            if value:
                agents = list(current["user_agents"]) if current else ["*"]
                crawl_delays.append({"user_agents": agents, "value": value})

    return {
        "groups": groups,
        "sitemaps": sitemaps,
        "crawl_delays": crawl_delays,
        "content_signals": parse_content_signals(text),
    }


def _pattern_to_regex(pattern: str) -> str:
    """Преобразовать путь robots.txt в regex: `*` -> `.*`, `$` в конце -> якорь."""
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


def pattern_matches(pattern: str, path: str) -> bool:
    """Совпадает ли путь с шаблоном robots.txt (поддержка `*` и `$`)."""
    if pattern == "":
        return True
    regex = _pattern_to_regex(pattern)
    try:
        return re.match(regex, path) is not None
    except re.error:
        return path.startswith(pattern)


def _agent_equals(agent: str, ua: str) -> bool:
    return agent.strip().lower() == ua.strip().lower()


def matched_groups(rules: Dict[str, Any], ua: str) -> List[Dict[str, Any]]:
    """Группы, применимые к user-agent: точные совпадения, иначе группа `*`."""
    groups = rules.get("groups", []) if isinstance(rules, dict) else []
    specific = [g for g in groups if any(_agent_equals(a, ua) for a in g.get("user_agents", []))]
    if specific:
        return specific
    return [g for g in groups if any(a.strip() == "*" for a in g.get("user_agents", []))]


def is_allowed(rules: Any, ua: str, path: str = "/") -> bool:
    """Разрешён ли `path` для user-agent `ua`.

    Используется правило самого длинного совпадения (longest match),
    при равной длине приоритет у Allow. `rules` — результат `parse_robots`
    либо просто список правил [{"type": ..., "path": ...}].
    """
    if isinstance(rules, dict):
        group_rules: List[Dict[str, Any]] = []
        for group in matched_groups(rules, ua):
            group_rules.extend(group.get("rules", []))
    else:
        group_rules = list(rules or [])

    best: Optional[Dict[str, Any]] = None
    best_len = -1
    for rule in group_rules:
        pattern = rule.get("path", "")
        rtype = rule.get("type", "disallow")
        # Пустой Disallow означает «разрешить всё» и не должен блокировать.
        if pattern == "" and rtype == "disallow":
            continue
        if not pattern_matches(pattern, path):
            continue
        length = len(pattern)
        if length > best_len:
            best_len = length
            best = rule
        elif length == best_len and best is not None and rtype == "allow":
            best = rule

    if best is None:
        return True
    return best.get("type") == "allow"


def resolve_bot_access(rules: Dict[str, Any], ua: str) -> Dict[str, Any]:
    """Детальная информация о доступе бота: разрешено ли и есть ли явные правила."""
    groups = matched_groups(rules, ua)
    explicit = any(any(_agent_equals(a, ua) for a in g.get("user_agents", [])) for g in groups)
    return {
        "allowed": is_allowed(rules, ua, "/"),
        "explicit": explicit,
        "groups": [g.get("user_agents", []) for g in groups],
        "rules": [r for g in groups for r in g.get("rules", [])],
    }


# --------------------------------------------------------------------------- #
# Чистые функции: Content-Signal
# --------------------------------------------------------------------------- #
def parse_content_signals(text: str) -> Dict[str, Any]:
    """Разобрать строки `Content-Signal:` из robots.txt.

    Возвращает {"present": bool, "values": {"search": "yes", ...}, "raw": [...]}.
    """
    values: Dict[str, str] = {}
    raw_lines: List[str] = []
    if not text:
        return {"present": False, "values": values, "raw": raw_lines}

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        if field.strip().lower() != "content-signal":
            continue
        value = value.strip()
        raw_lines.append(value)
        for part in value.split(","):
            if "=" in part:
                key, _, val = part.partition("=")
                key = key.strip().lower()
                val = val.strip().lower()
                if key:
                    values[key] = val

    return {"present": bool(raw_lines), "values": values, "raw": raw_lines}


# --------------------------------------------------------------------------- #
# Чистые функции: llms.txt
# --------------------------------------------------------------------------- #
def validate_llms_txt(text: str) -> List[str]:
    """Проверить текст llms.txt по спецификации llmstxt.org.

    Возвращает список проблем на русском. Пустой список — файл корректен.
    """
    problems: List[str] = []
    if not text or not text.strip():
        return ["Файл пуст"]

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    stripped = [line.strip() for line in lines]
    non_empty = [i for i, line in enumerate(stripped) if line]
    first_i = non_empty[0]
    first = stripped[first_i]

    if not first.startswith("# "):
        if first.startswith("#"):
            problems.append("Заголовок H1 записан неверно: после '#' нужен пробел — '# Название'")
        else:
            problems.append("Первая строка должна быть заголовком H1 в формате '# Название'")

    h1_lines = [line for line in stripped if line.startswith("# ")]
    if len(h1_lines) > 1:
        problems.append("Найдено несколько заголовков H1 — допускается только один H1 в начале файла")

    h2_indexes = [i for i, line in enumerate(stripped) if line.startswith("## ")]
    if not h2_indexes:
        problems.append("Нет ни одного раздела H2 ('## Раздел') со списком ссылок")

    bounds = h2_indexes + [len(stripped)]
    for pos, start in enumerate(h2_indexes):
        end = bounds[pos + 1]
        section_title = stripped[start][3:].strip() or "(без названия)"
        body = [line for line in stripped[start + 1:end] if line]
        if not body:
            problems.append(f"Раздел «{section_title}» пуст — добавьте список ссылок")
            continue
        links = [line for line in body if _MARKDOWN_LINK_RE.search(line)]
        if not links:
            problems.append(
                f"В разделе «{section_title}» нет markdown-ссылок вида '- [Название](URL)'"
            )

    return problems


# --------------------------------------------------------------------------- #
# Чистые функции: HTML / мета
# --------------------------------------------------------------------------- #
def looks_like_html(text: str) -> bool:
    """Похож ли текст на HTML (защита от HTML-страницы ошибки вместо файла)."""
    if not text:
        return False
    head = text.lstrip()[:300].lower()
    return (
        head.startswith("<!doctype")
        or head.startswith("<html")
        or head.startswith("<?xml")
        or "<head>" in head
        or "<body" in head
    )


def is_markdown_like(content_type: str, text: str) -> bool:
    """Похож ли ответ на markdown/plain-текст, а не на HTML."""
    ct = (content_type or "").lower()
    if "text/html" in ct or "application/xhtml" in ct:
        return False
    if any(t in ct for t in _MARKDOWN_ALT_TYPES):
        return True
    if "text/plain" in ct:
        return not looks_like_html(text)
    # Нет внятного content-type — ориентируемся на тело ответа.
    return bool(text) and not looks_like_html(text)


def find_markdown_link_tags(html: str) -> List[str]:
    """Найти href из `<link rel="alternate" type="text/markdown">`."""
    if not html:
        return []
    try:
        tree = LexborHTMLParser(html)
    except Exception:
        return []
    hrefs: List[str] = []
    for node in tree.css("link"):
        rel = (node.attributes.get("rel") or "").lower()
        typ = (node.attributes.get("type") or "").lower()
        if "alternate" not in rel:
            continue
        if any(t in typ for t in _MARKDOWN_ALT_TYPES):
            href = node.attributes.get("href")
            if href:
                hrefs.append(href)
    return hrefs


def extract_meta_robots(html: str) -> List[str]:
    """Собрать значения content из meta robots-подобных тегов."""
    if not html:
        return []
    try:
        tree = LexborHTMLParser(html)
    except Exception:
        return []
    values: List[str] = []
    for node in tree.css("meta"):
        name = (node.attributes.get("name") or "").lower()
        if name in META_ROBOTS_NAMES:
            content = node.attributes.get("content")
            if content:
                values.append(content)
    return values


def parse_meta_directives(html: str, x_robots_tag: str = "") -> Dict[str, Any]:
    """Найти AI/индексирующие директивы в meta robots и заголовке X-Robots-Tag.

    Возвращает {"found": [...], "sources": {...}, "raw": {...}}.
    """
    meta_values = extract_meta_robots(html)
    parts: List[Tuple[str, str]] = [("meta robots", v) for v in meta_values]
    if x_robots_tag:
        parts.append(("X-Robots-Tag", x_robots_tag))

    haystack = " ".join(v for _, v in parts).lower()
    found = [d for d in AI_META_DIRECTIVES if d in haystack]
    # max-snippet:-1 означает «без ограничений», ограничением считаем только 0..49
    if "max-snippet" in found:
        values = [int(v) for v in re.findall(r"max-snippet\s*:\s*(-?\d+)", haystack)]
        if values and all(v < 0 or v >= 50 for v in values):
            found.remove("max-snippet")

    sources: Dict[str, List[str]] = {}
    for directive in found:
        sources[directive] = [name for name, value in parts if directive in value.lower()]

    return {
        "found": found,
        "sources": sources,
        "raw": {"meta_robots": meta_values, "x_robots_tag": x_robots_tag},
    }


# --------------------------------------------------------------------------- #
# Чистые функции: MCP server card
# --------------------------------------------------------------------------- #
def validate_server_card(data: Any) -> List[str]:
    """Проверить server-card.json на обязательные поля."""
    if not isinstance(data, dict):
        return ["Корневой элемент должен быть JSON-объектом"]
    problems: List[str] = []
    for field in ("name", "version", "endpoints"):
        if field not in data:
            problems.append(f"Отсутствует обязательное поле '{field}'")
    endpoints = data.get("endpoints")
    if "endpoints" in data and not isinstance(endpoints, (list, dict)):
        problems.append("Поле 'endpoints' должно быть списком или объектом")
    return problems


def _safe_json(text: str) -> Tuple[Optional[Any], Optional[str]]:
    """Разобрать JSON без исключений: (data, error)."""
    if not text or not text.strip():
        return None, "Пустой ответ"
    try:
        return json.loads(text), None
    except Exception as exc:  # noqa: BLE001 - нужна любая причина
        return None, str(exc)


# --------------------------------------------------------------------------- #
# Вспомогательные конструкторы результатов
# --------------------------------------------------------------------------- #
def _network_error(check_id: str, title: str, url: str, what: str) -> CheckResult:
    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="warning",
        score=0,
        findings=[
            Finding(
                level="warning",
                text=f"Не удалось получить {what} ({url}) — сетевой сбой или файл недоступен",
                fix=f"Проверить доступность {url} и повторить аудит",
                hours=0.5,
            )
        ],
        raw={"url": url, "error": "network"},
    )


# --------------------------------------------------------------------------- #
# Проверка 1: robots.txt и AI-боты
# --------------------------------------------------------------------------- #
@check(id="ai_robots", title="Правила robots.txt для AI-ботов", category=CATEGORY)
async def ai_robots(ctx: AuditContext) -> CheckResult:
    check_id = "ai_robots"
    title = "Правила robots.txt для AI-ботов"
    url = f"{ctx.base}/robots.txt"

    resp = await ctx.get(url)
    if resp is None:
        return _network_error(check_id, title, url, "robots.txt")

    if resp.status_code >= 400:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=40,
            findings=[
                Finding(
                    level="warning",
                    text=f"robots.txt недоступен (HTTP {resp.status_code}) — правила для AI-ботов не заданы",
                    fix="Создать robots.txt в корне сайта и описать в нём доступ AI-ботов и поисковых роботов",
                    hours=1.0,
                )
            ],
            raw={"url": url, "status": resp.status_code},
        )

    rules = parse_robots(resp.text)
    bots: Dict[str, Any] = {}
    explicit_any = False
    blocked_search: List[str] = []
    blocked_other: List[str] = []

    for bot in AI_BOTS:
        access = resolve_bot_access(rules, bot)
        bots[bot] = {
            "allowed": access["allowed"],
            "explicit": access["explicit"],
            "rules": access["rules"],
            "groups": access["groups"],
        }
        if access["explicit"]:
            explicit_any = True
        if not access["allowed"]:
            if bot in SEARCH_BOTS:
                blocked_search.append(bot)
            else:
                blocked_other.append(bot)

    findings: List[Finding] = []
    if blocked_search:
        status = "critical"
        score = max(0, 100 - 40 * len(blocked_search))
        for bot in blocked_search:
            findings.append(
                Finding(
                    level="critical",
                    text=f"Поисковый AI-бот {bot} заблокирован в robots.txt — сайт не попадает в AI-поиск",
                    fix=f"Разрешить {bot} доступ к сайту: добавить 'User-agent: {bot}' и 'Allow: /' (либо убрать точечную блокировку)",
                    hours=1.0,
                )
            )
        if blocked_other:
            findings.append(
                Finding(
                    level="warning",
                    text="Заблокированы AI-боты: " + ", ".join(blocked_other),
                    fix="Проверить, какие AI-боты должны иметь доступ, и добавить для них 'Allow: /'",
                    hours=1.0,
                )
            )
    elif blocked_other:
        status = "warning"
        score = 60
        findings.append(
            Finding(
                level="warning",
                text="Заблокированы AI-боты: " + ", ".join(blocked_other),
                fix="Если контент не должен использоваться AI — это ок; иначе добавить 'Allow: /' для нужных ботов",
                hours=1.0,
            )
        )
    elif not explicit_any:
        status = "warning"
        score = 75
        findings.append(
            Finding(
                level="warning",
                text="В robots.txt нет явных правил ни для одного AI-бота — доступ регулируется только группой '*'",
                fix="Добавить явные секции User-agent для AI-ботов (GPTBot, ClaudeBot, PerplexityBot, Google-Extended и др.) с осознанным Allow/Disallow",
                hours=1.5,
            )
        )
    else:
        status = "ok"
        score = 100
        allowed_count = sum(1 for b in bots.values() if b["allowed"])
        findings.append(
            Finding(
                level="ok",
                text=f"AI-боты явно описаны в robots.txt, доступ разрешён {allowed_count} из {len(AI_BOTS)}",
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
            "search_bots": SEARCH_BOTS,
            "blocked_search_bots": blocked_search,
            "blocked_other_bots": blocked_other,
            "explicit_rules": explicit_any,
            "bots": bots,
            "sitemaps": rules.get("sitemaps", []),
            "groups_count": len(rules.get("groups", [])),
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 2: Content-Signal
# --------------------------------------------------------------------------- #
@check(id="content_signal", title="Директивы Content-Signal в robots.txt", category=CATEGORY)
async def content_signal(ctx: AuditContext) -> CheckResult:
    check_id = "content_signal"
    title = "Директивы Content-Signal в robots.txt"
    url = f"{ctx.base}/robots.txt"

    resp = await ctx.get(url)
    if resp is None:
        return _network_error(check_id, title, url, "robots.txt")

    if resp.status_code >= 400:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=40,
            findings=[
                Finding(
                    level="warning",
                    text=f"robots.txt недоступен (HTTP {resp.status_code}) — Content-Signal не задан",
                    fix="Создать robots.txt и добавить строку 'Content-Signal: search=yes, ai-input=yes, ai-train=no'",
                    hours=0.5,
                )
            ],
            raw={"url": url, "status": resp.status_code},
        )

    signals = parse_content_signals(resp.text)
    values = signals["values"]

    if not signals["present"]:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=50,
            findings=[
                Finding(
                    level="warning",
                    text="В robots.txt нет директивы Content-Signal — издатели не заявляют права на использование контента в AI",
                    fix="Добавить в robots.txt строку 'Content-Signal: search=yes, ai-input=yes, ai-train=no' (значения — по вашей политике)",
                    hours=0.5,
                )
            ],
            raw={"url": url, "present": False, "values": {}, "raw": []},
        )

    findings: List[Finding] = []
    status = "ok"
    score = 100

    known = ("search", "ai-input", "ai-train")
    findings.append(
        Finding(
            level="ok",
            text="Content-Signal задан: "
            + ", ".join(f"{k}={values.get(k, 'не задано')}" for k in known),
            fix="",
        )
    )
    unknown = [k for k in values if k not in known]
    if unknown:
        findings.append(
            Finding(
                level="info",
                text="Неизвестные ключи Content-Signal: " + ", ".join(unknown),
                fix="Привести ключи к поддерживаемым: search, ai-input, ai-train",
                hours=0.25,
            )
        )
        status = "warning"
        score = min(score, 80)

    if values.get("ai-train") == "yes" and values.get("ai-input") == "yes":
        findings.append(
            Finding(
                level="info",
                text="Контент разрешён и для обучения, и для AI-ответов (ai-train=yes, ai-input=yes)",
                fix="Если обучение на контенте нежелательно — указать ai-train=no",
                hours=0.25,
            )
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={"url": url, "present": True, "values": values, "raw": signals["raw"]},
    )


# --------------------------------------------------------------------------- #
# Проверка 3: /llms.txt
# --------------------------------------------------------------------------- #
@check(id="llms_txt", title="Файл /llms.txt", category=CATEGORY)
async def llms_txt(ctx: AuditContext) -> CheckResult:
    check_id = "llms_txt"
    title = "Файл /llms.txt"
    url = f"{ctx.base}/llms.txt"

    resp = await ctx.get(url)
    if resp is None:
        return _network_error(check_id, title, url, "llms.txt")

    content_type = resp.headers.get("content-type", "")
    body = resp.text or ""

    if resp.status_code >= 400:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=30,
            findings=[
                Finding(
                    level="warning",
                    text=f"llms.txt не найден (HTTP {resp.status_code}) — AI-ассистенты не получают карту контента",
                    fix="Создать /llms.txt по спецификации llmstxt.org: H1 с названием, краткое описание и разделы H2 со ссылками на ключевые материалы",
                    hours=3.0,
                )
            ],
            raw={"url": url, "status": resp.status_code},
        )

    html_like = looks_like_html(body) or "text/html" in content_type.lower()
    if html_like:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=20,
            findings=[
                Finding(
                    level="warning",
                    text="По адресу /llms.txt отдаётся HTML-страница (вероятно, страница 404), а не markdown",
                    fix="Настроить отдачу реального markdown-файла /llms.txt с Content-Type text/plain или text/markdown",
                    hours=2.0,
                )
            ],
            raw={"url": url, "status": resp.status_code, "content_type": content_type},
        )

    problems = validate_llms_txt(body)
    if not is_markdown_like(content_type, body):
        problems.append(
            f"Неожиданный Content-Type '{content_type or 'не задан'}' — ожидается text/plain или text/markdown"
        )

    if problems:
        findings = [
            Finding(
                level="warning",
                text="llms.txt найден, но есть замечания: " + "; ".join(problems[:6]),
                fix="Исправить структуру llms.txt по спецификации llmstxt.org (H1, описание, разделы H2 со списками ссылок)",
                hours=1.5,
            )
        ]
        status = "warning"
        score = 60
    else:
        findings = [
            Finding(
                level="ok",
                text="llms.txt найден и соответствует спецификации llmstxt.org",
                fix="",
            )
        ]
        status = "ok"
        score = 100

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
            "size_bytes": len(body.encode("utf-8")),
            "problems": problems,
        },
    )


# --------------------------------------------------------------------------- #
# Проверка 4: /llms-full.txt
# --------------------------------------------------------------------------- #
@check(id="llms_full_txt", title="Файл /llms-full.txt", category=CATEGORY)
async def llms_full_txt(ctx: AuditContext) -> CheckResult:
    check_id = "llms_full_txt"
    title = "Файл /llms-full.txt"
    url = f"{ctx.base}/llms-full.txt"

    resp = await ctx.get(url)
    if resp is None:
        return _network_error(check_id, title, url, "llms-full.txt")

    content_type = resp.headers.get("content-type", "")
    body = resp.text or ""
    size = len(body.encode("utf-8"))

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
                    text=f"llms-full.txt не найден (HTTP {resp.status_code}) — нет развёрнутой выжимки контента для AI",
                    fix="Сформировать /llms-full.txt с полным текстом ключевых страниц (или крупными markdown-выдержками)",
                    hours=3.0,
                )
            ],
            raw={"url": url, "status": resp.status_code},
        )

    if looks_like_html(body):
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=30,
            findings=[
                Finding(
                    level="warning",
                    text="По адресу /llms-full.txt отдаётся HTML, а не markdown-текст",
                    fix="Отдавать markdown-файл с Content-Type text/plain или text/markdown",
                    hours=2.0,
                )
            ],
            raw={"url": url, "status": resp.status_code, "content_type": content_type},
        )

    if size < 500:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=70,
            findings=[
                Finding(
                    level="warning",
                    text=f"llms-full.txt слишком короткий ({size} байт) — вероятно, не содержит полезного контента",
                    fix="Наполнить llms-full.txt текстом ключевых страниц (рекомендуется от нескольких КБ)",
                    hours=2.0,
                )
            ],
            raw={"url": url, "status": resp.status_code, "content_type": content_type, "size_bytes": size},
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="ok",
        score=100,
        findings=[
            Finding(
                level="ok",
                text=f"llms-full.txt найден, размер {size} байт",
                fix="",
            )
        ],
        raw={"url": url, "status": resp.status_code, "content_type": content_type, "size_bytes": size},
    )


# --------------------------------------------------------------------------- #
# Проверка 5: markdown-версия страниц
# --------------------------------------------------------------------------- #
@check(id="markdown_version", title="Markdown-версия страницы", category=CATEGORY)
async def markdown_version(ctx: AuditContext) -> CheckResult:
    check_id = "markdown_version"
    title = "Markdown-версия страницы"

    md_url = ctx.url + ".md"
    direct = False
    direct_status: Optional[int] = None
    md_resp = await ctx.get(md_url)
    if md_resp is not None:
        direct_status = md_resp.status_code
        if md_resp.status_code == 200 and is_markdown_like(
            md_resp.headers.get("content-type", ""), md_resp.text or ""
        ):
            direct = True

    home = await ctx.home()
    home_html = home.text if home is not None else ""
    link_hrefs = find_markdown_link_tags(home_html)

    accept = await ctx.get(ctx.url, headers={"Accept": "text/markdown"})
    accept_ok = False
    accept_ct = ""
    if accept is not None:
        accept_ct = accept.headers.get("content-type", "")
        if "text/markdown" in accept_ct.lower():
            accept_ok = True

    raw = {
        "md_url": md_url,
        "direct_md": direct,
        "direct_status": direct_status,
        "link_rel_alternate": link_hrefs,
        "accept_text_markdown": accept_ok,
        "accept_content_type": accept_ct,
    }

    if direct or link_hrefs or accept_ok:
        sources = []
        if direct:
            sources.append(f"прямой файл {md_url}")
        if link_hrefs:
            sources.append("link rel=alternate type=text/markdown")
        if accept_ok:
            sources.append("согласование по Accept: text/markdown")
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="ok",
            score=100,
            findings=[
                Finding(level="ok", text="Markdown-версия доступна: " + "; ".join(sources), fix="")
            ],
            raw=raw,
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="warning",
        score=30,
        findings=[
            Finding(
                level="warning",
                text="Markdown-версия страницы недоступна ни через URL+.md, ни через link rel=alternate, ни по Accept: text/markdown",
                fix="Отдавать markdown-версию страниц (например, /page.md) и добавить в HTML '<link rel=\"alternate\" type=\"text/markdown\" href=\"...\">' либо поддержать Accept: text/markdown",
                hours=6.0,
            )
        ],
        raw=raw,
    )


# --------------------------------------------------------------------------- #
# Проверка 6: MCP server card
# --------------------------------------------------------------------------- #
@check(id="mcp_server_card", title="MCP server card", category=CATEGORY)
async def mcp_server_card(ctx: AuditContext) -> CheckResult:
    check_id = "mcp_server_card"
    title = "MCP server card"
    url = f"{ctx.base}/.well-known/mcp/server-card.json"

    resp = await ctx.get(url)
    if resp is None:
        return _network_error(check_id, title, url, "server-card.json")

    if resp.status_code >= 400:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="ok",
            score=100,
            findings=[
                Finding(
                    level="info",
                    text=f"MCP server card не найден (HTTP {resp.status_code}) — сайт не заявляет MCP-эндпоинты",
                    fix="Если есть MCP-сервер, опубликовать /.well-known/mcp/server-card.json с полями name, version, endpoints",
                    hours=3.0,
                )
            ],
            raw={"url": url, "status": resp.status_code},
        )

    data, error = _safe_json(resp.text or "")
    if error is not None:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=30,
            findings=[
                Finding(
                    level="warning",
                    text=f"server-card.json повреждён: {error}",
                    fix="Привести файл к валидному JSON с полями name, version, endpoints",
                    hours=1.0,
                )
            ],
            raw={"url": url, "status": resp.status_code, "error": error},
        )

    problems = validate_server_card(data)
    if problems:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=60,
            findings=[
                Finding(
                    level="warning",
                    text="server-card.json неполный: " + "; ".join(problems),
                    fix="Добавить/исправить поля name, version и endpoints в server-card.json",
                    hours=1.0,
                )
            ],
            raw={"url": url, "status": resp.status_code, "problems": problems, "data": data},
        )

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="ok",
        score=100,
        findings=[Finding(level="ok", text="MCP server card найден и заполнен корректно", fix="")],
        raw={"url": url, "status": resp.status_code, "data": data},
    )


# --------------------------------------------------------------------------- #
# Проверка 7: agent skills index
# --------------------------------------------------------------------------- #
@check(id="agent_skills_index", title="Индекс agent skills", category=CATEGORY)
async def agent_skills_index(ctx: AuditContext) -> CheckResult:
    check_id = "agent_skills_index"
    title = "Индекс agent skills"
    url = f"{ctx.base}/.well-known/agent-skills/index.json"

    resp = await ctx.get(url)
    if resp is None:
        return _network_error(check_id, title, url, "index.json")

    if resp.status_code >= 400:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="ok",
            score=100,
            findings=[
                Finding(
                    level="info",
                    text=f"Индекс agent skills не найден (HTTP {resp.status_code})",
                    fix="Если публикуются agent skills, добавить /.well-known/agent-skills/index.json с перечнем скиллов",
                    hours=2.0,
                )
            ],
            raw={"url": url, "status": resp.status_code},
        )

    data, error = _safe_json(resp.text or "")
    if error is not None:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=40,
            findings=[
                Finding(
                    level="warning",
                    text=f"agent-skills/index.json повреждён: {error}",
                    fix="Привести файл к валидному JSON (например, объект со списком скиллов)",
                    hours=1.0,
                )
            ],
            raw={"url": url, "status": resp.status_code, "error": error},
        )

    if not isinstance(data, (dict, list)):
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=50,
            findings=[
                Finding(
                    level="warning",
                    text="agent-skills/index.json должен быть JSON-объектом или массивом",
                    fix="Оформить индекс как объект со списком скиллов или массив скиллов",
                    hours=1.0,
                )
            ],
            raw={"url": url, "status": resp.status_code, "data": data},
        )

    count = len(data) if isinstance(data, list) else len(data.get("skills", data))
    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status="ok",
        score=100,
        findings=[Finding(level="ok", text=f"Индекс agent skills найден, элементов: {count}", fix="")],
        raw={"url": url, "status": resp.status_code, "data": data},
    )


# --------------------------------------------------------------------------- #
# Проверка 8: AI-директивы в meta robots / X-Robots-Tag
# --------------------------------------------------------------------------- #
@check(id="ai_meta_directives", title="AI-директивы meta robots и X-Robots-Tag", category=CATEGORY)
async def ai_meta_directives(ctx: AuditContext) -> CheckResult:
    check_id = "ai_meta_directives"
    title = "AI-директивы meta robots и X-Robots-Tag"

    resp = await ctx.home()
    if resp is None:
        return _network_error(check_id, title, ctx.url, "главную страницу")

    x_robots = resp.headers.get("x-robots-tag", "")
    parsed = parse_meta_directives(resp.text or "", x_robots)
    found = parsed["found"]

    if not found:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="ok",
            score=100,
            findings=[
                Finding(
                    level="ok",
                    text="AI-ограничивающих директив (noai, noimageai, noindex, nosnippet, max-snippet) не найдено",
                    fix="",
                )
            ],
            raw={"url": str(resp.url), **parsed["raw"], "found": found},
        )

    findings: List[Finding] = []
    if "noindex" in found:
        status = "critical"
        score = 0
        findings.append(
            Finding(
                level="critical",
                text="Главная страница закрыта от индексации директивой noindex — сайт выпадает из поиска и AI-выдачи",
                fix="Убрать noindex из meta robots / заголовка X-Robots-Tag на главной странице",
                hours=0.5,
            )
        )
        remaining = [d for d in found if d != "noindex"]
    else:
        status = "warning"
        score = 50
        remaining = list(found)

    if remaining:
        findings.append(
            Finding(
                level="warning",
                text="На главной найдены ограничивающие директивы: " + ", ".join(remaining),
                fix="Проверить необходимость каждой директивы: noai/noimageai запрещают AI-использование, nosnippet/max-snippet ограничивают выдачу",
                hours=0.5,
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
            "url": str(resp.url),
            "found": found,
            "sources": parsed["sources"],
            **parsed["raw"],
        },
    )
