from __future__ import annotations

import pytest

from app.checks.geo_files import (
    find_markdown_link_tags,
    is_allowed,
    parse_content_signals,
    parse_meta_directives,
    parse_robots,
    pattern_matches,
    validate_llms_txt,
    validate_server_card,
)

# --------------------------------------------------------------------------- #
# Фикстуры robots.txt
# --------------------------------------------------------------------------- #
ROBOTS_TYPICAL = """\
# robots.txt
User-agent: *
Disallow: /admin/
Allow: /

User-agent: GPTBot
Allow: /

User-agent: Google-Extended
Disallow: /
"""

ROBOTS_WILDCARDS = """\
User-agent: *
Disallow: /*.pdf$
Disallow: /private/*
Allow: /private/public/
"""

ROBOTS_LONGEST = """\
User-agent: *
Disallow: /
Allow: /public/
Allow: /public/open/
"""

ROBOTS_EMPTY_DISALLOW = """\
User-agent: *
Disallow:
"""


@pytest.fixture
def robots_typical():
    return parse_robots(ROBOTS_TYPICAL)


@pytest.fixture
def robots_wildcards():
    return parse_robots(ROBOTS_WILDCARDS)


@pytest.fixture
def robots_longest():
    return parse_robots(ROBOTS_LONGEST)


# --------------------------------------------------------------------------- #
# parse_robots
# --------------------------------------------------------------------------- #
def test_parse_robots_groups_and_rules(robots_typical):
    groups = robots_typical["groups"]
    assert len(groups) == 3

    wildcard = groups[0]
    assert wildcard["user_agents"] == ["*"]
    assert wildcard["rules"] == [
        {"type": "disallow", "path": "/admin/"},
        {"type": "allow", "path": "/"},
    ]

    gpt = groups[1]
    assert gpt["user_agents"] == ["GPTBot"]
    assert gpt["rules"] == [{"type": "allow", "path": "/"}]


def test_parse_robots_merges_consecutive_user_agents():
    text = "User-agent: A\nUser-agent: B\nDisallow: /x\n"
    rules = parse_robots(text)
    assert len(rules["groups"]) == 1
    assert rules["groups"][0]["user_agents"] == ["A", "B"]
    assert rules["groups"][0]["rules"] == [{"type": "disallow", "path": "/x"}]


def test_parse_robots_ignores_comments_and_sitemap():
    text = "# comment\nUser-agent: *  # trailing\nDisallow: /a # why\nSitemap: https://e.com/s.xml\n"
    rules = parse_robots(text)
    assert rules["groups"][0]["rules"] == [{"type": "disallow", "path": "/a"}]
    assert rules["sitemaps"] == ["https://e.com/s.xml"]


def test_parse_robots_empty():
    assert parse_robots("")["groups"] == []


# --------------------------------------------------------------------------- #
# is_allowed: группа для конкретного UA важнее '*'
# --------------------------------------------------------------------------- #
def test_is_allowed_specific_group_overrides_wildcard(robots_typical):
    # '*' разрешает всё кроме /admin/, но GPTBot имеет свою группу с Allow: /
    assert is_allowed(robots_typical, "GPTBot", "/admin/") is True
    assert is_allowed(robots_typical, "GPTBot", "/") is True
    # Google-Extended явно запрещён
    assert is_allowed(robots_typical, "Google-Extended", "/") is False
    # Обычный бот подчиняется группе '*'
    assert is_allowed(robots_typical, "SomeBot", "/admin/") is False
    assert is_allowed(robots_typical, "SomeBot", "/page/") is True


def test_is_allowed_unknown_bot_defaults_to_wildcard(robots_typical):
    assert is_allowed(robots_typical, "Amazonbot", "/admin/") is False
    assert is_allowed(robots_typical, "Amazonbot", "/") is True


def test_is_allowed_empty_disallow_allows_all(robots_longest):
    rules = parse_robots(ROBOTS_EMPTY_DISALLOW)
    assert is_allowed(rules, "GPTBot", "/anything") is True
    assert is_allowed(rules, "GPTBot", "/") is True


# --------------------------------------------------------------------------- #
# is_allowed: longest match
# --------------------------------------------------------------------------- #
def test_is_allowed_longest_match(robots_longest):
    # Disallow: / перекрывается более длинным Allow: /public/
    assert is_allowed(robots_longest, "AnyBot", "/public/page") is True
    assert is_allowed(robots_longest, "AnyBot", "/public/open/x") is True
    assert is_allowed(robots_longest, "AnyBot", "/other") is False
    assert is_allowed(robots_longest, "AnyBot", "/") is False


def test_is_allowed_tie_prefers_allow():
    text = "User-agent: *\nDisallow: /a\nAllow: /a\n"
    rules = parse_robots(text)
    assert is_allowed(rules, "Bot", "/a") is True


def test_is_allowed_accepts_plain_rule_list():
    rules = [
        {"type": "disallow", "path": "/"},
        {"type": "allow", "path": "/ok"},
    ]
    assert is_allowed(rules, "Bot", "/ok") is True
    assert is_allowed(rules, "Bot", "/no") is False


# --------------------------------------------------------------------------- #
# wildcards: * и $
# --------------------------------------------------------------------------- #
def test_wildcard_star_matches():
    assert pattern_matches("/*.pdf$", "/doc.pdf") is True
    assert pattern_matches("/*.pdf$", "/a/b/doc.pdf") is True
    assert pattern_matches("/*.pdf$", "/doc.pdf?x=1") is False
    assert pattern_matches("/private/*", "/private/secret") is True
    assert pattern_matches("/private/*", "/public") is False


def test_is_allowed_wildcards(robots_wildcards):
    assert is_allowed(robots_wildcards, "Bot", "/doc.pdf") is False
    assert is_allowed(robots_wildcards, "Bot", "/doc.pdf?download=1") is True
    assert is_allowed(robots_wildcards, "Bot", "/private/secret") is False
    # Allow: /private/public/ длиннее, чем Disallow: /private/*
    assert is_allowed(robots_wildcards, "Bot", "/private/public/file") is True


# --------------------------------------------------------------------------- #
# Content-Signal
# --------------------------------------------------------------------------- #
def test_parse_content_signals_values():
    text = (
        "User-agent: *\n"
        "Content-Signal: search=yes, ai-input=no, ai-train=no\n"
    )
    signals = parse_content_signals(text)
    assert signals["present"] is True
    assert signals["values"] == {"search": "yes", "ai-input": "no", "ai-train": "no"}
    assert signals["raw"] == ["search=yes, ai-input=no, ai-train=no"]


def test_parse_content_signals_absent():
    signals = parse_content_signals("User-agent: *\nDisallow: /\n")
    assert signals["present"] is False
    assert signals["values"] == {}


def test_parse_content_signals_case_and_comments():
    text = "CONTENT-SIGNAL: Search=Yes, AI-Train=No # policy\n"
    signals = parse_content_signals(text)
    assert signals["values"] == {"search": "yes", "ai-train": "no"}


def test_parse_robots_includes_content_signals():
    text = "User-agent: *\nDisallow: /\nContent-Signal: ai-train=no\n"
    rules = parse_robots(text)
    assert rules["content_signals"]["values"] == {"ai-train": "no"}


# --------------------------------------------------------------------------- #
# validate_llms_txt
# --------------------------------------------------------------------------- #
GOOD_LLMS = """\
# Example

> Краткое описание сайта для AI-ассистентов.

## Docs
- [Начало работы](https://example.com/start): краткое руководство
- [API](https://example.com/api): справочник

## Blog
- [Статья 1](https://example.com/blog/1): описание
"""


def test_validate_llms_txt_good():
    assert validate_llms_txt(GOOD_LLMS) == []


def test_validate_llms_txt_empty():
    problems = validate_llms_txt("")
    assert problems == ["Файл пуст"]
    assert validate_llms_txt("   \n  ") == ["Файл пуст"]


def test_validate_llms_txt_missing_h1():
    problems = validate_llms_txt("Просто текст без заголовка\n\n## Раздел\n- [A](https://a.b)\n")
    assert any("H1" in p for p in problems)


def test_validate_llms_txt_duplicate_h1():
    text = "# First\n\n# Second\n\n## Docs\n- [A](https://a.b)\n"
    problems = validate_llms_txt(text)
    assert any("несколько заголовков H1" in p for p in problems)


def test_validate_llms_txt_missing_sections():
    problems = validate_llms_txt("# Title\n\n> Summary\n")
    assert any("H2" in p for p in problems)


def test_validate_llms_txt_section_without_links():
    text = "# Title\n\n## Docs\nПросто абзац без ссылок\n"
    problems = validate_llms_txt(text)
    assert any("нет markdown-ссылок" in p for p in problems)


def test_validate_llms_txt_empty_section():
    text = "# Title\n\n## Docs\n\n## Links\n- [A](https://a.b)\n"
    problems = validate_llms_txt(text)
    assert any("пуст" in p for p in problems)


# --------------------------------------------------------------------------- #
# Дополнительно: чистые HTML/JSON парсеры
# --------------------------------------------------------------------------- #
def test_find_markdown_link_tags():
    html = (
        '<head>'
        '<link rel="alternate" type="text/markdown" href="/index.md">'
        '<link rel="stylesheet" href="/style.css">'
        '<link rel="alternate" type="application/rss+xml" href="/rss.xml">'
        "</head>"
    )
    assert find_markdown_link_tags(html) == ["/index.md"]
    assert find_markdown_link_tags("") == []


def test_find_markdown_link_tags_handles_html_error_page():
    assert find_markdown_link_tags("<html><body>404</body></html>") == []


def test_parse_meta_directives():
    html = (
        '<meta name="robots" content="noindex, nofollow">'
        '<meta name="googlebot" content="noai, noimageai">'
    )
    parsed = parse_meta_directives(html, x_robots_tag="max-snippet:0")
    assert set(parsed["found"]) == {"noindex", "noai", "noimageai", "max-snippet"}
    assert parsed["raw"]["x_robots_tag"] == "max-snippet:0"


def test_parse_meta_directives_clean():
    parsed = parse_meta_directives('<meta name="robots" content="index, follow">', "")
    assert parsed["found"] == []


def test_validate_server_card():
    assert validate_server_card({"name": "s", "version": "1.0", "endpoints": []}) == []
    assert validate_server_card("nope") == ["Корневой элемент должен быть JSON-объектом"]
    problems = validate_server_card({"name": "s"})
    assert any("'version'" in p for p in problems)
    assert any("'endpoints'" in p for p in problems)
    assert any("'endpoints' должно" in p for p in validate_server_card({"endpoints": "x"}))


def test_max_snippet_unlimited_is_not_restrictive():
    from app.checks.geo_files import parse_meta_directives
    html = "<meta name='robots' content='index, follow, max-snippet:-1' />"
    assert "max-snippet" not in parse_meta_directives(html)["found"]
    assert "max-snippet" in parse_meta_directives("<meta name='robots' content='max-snippet:0'>")["found"]
