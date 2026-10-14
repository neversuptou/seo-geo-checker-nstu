from __future__ import annotations

import gzip

import pytest

from app.checks.technical import (
    analyze_slugs,
    detect_template_duplicates,
    extract_page_meta,
    find_generators,
    find_mixed_content,
    is_php_outdated,
    looks_like_feed,
    parse_hsts_max_age,
    parse_php_version,
    parse_robots_txt,
    parse_sitemap,
    count_assets,
    extract_hreflang,
)

# --------------------------------------------------------------------------- #
# parse_sitemap: urlset
# --------------------------------------------------------------------------- #
URLSET = b"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/a</loc>
    <lastmod>2024-05-01</lastmod>
  </url>
  <url>
    <loc>https://example.com/b</loc>
  </url>
</urlset>
"""


def test_parse_sitemap_urlset():
    urls, children, lastmods = parse_sitemap(URLSET)
    assert urls == ["https://example.com/a", "https://example.com/b"]
    assert children == []
    assert lastmods == ["2024-05-01", None]


def test_parse_sitemap_urlset_without_namespace():
    xml = b"<urlset><url><loc>https://e.com/x</loc></url></urlset>"
    urls, children, lastmods = parse_sitemap(xml)
    assert urls == ["https://e.com/x"]
    assert children == []
    assert lastmods == [None]


# --------------------------------------------------------------------------- #
# parse_sitemap: sitemapindex
# --------------------------------------------------------------------------- #
SITEMAPINDEX = b"""<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap>
    <loc>https://example.com/sitemap-1.xml</loc>
    <lastmod>2024-06-01</lastmod>
  </sitemap>
  <sitemap>
    <loc>https://example.com/sitemap-2.xml</loc>
  </sitemap>
</sitemapindex>
"""


def test_parse_sitemap_index():
    urls, children, lastmods = parse_sitemap(SITEMAPINDEX)
    assert urls == []
    assert children == ["https://example.com/sitemap-1.xml", "https://example.com/sitemap-2.xml"]
    assert lastmods == ["2024-06-01", None]


# --------------------------------------------------------------------------- #
# parse_sitemap: gzip и некорректный ввод
# --------------------------------------------------------------------------- #
def test_parse_sitemap_gzip():
    urls, children, lastmods = parse_sitemap(gzip.compress(URLSET))
    assert urls == ["https://example.com/a", "https://example.com/b"]
    assert lastmods == ["2024-05-01", None]


def test_parse_sitemap_broken_returns_empty():
    assert parse_sitemap(b"") == ([], [], [])
    assert parse_sitemap(b"not xml at all") == ([], [], [])
    assert parse_sitemap(b"\x1f\x8b\x00broken") == ([], [], [])


def test_parse_sitemap_unknown_root():
    urls, children, lastmods = parse_sitemap(b"<root><x/></root>")
    assert (urls, children, lastmods) == ([], [], [])


# --------------------------------------------------------------------------- #
# detect_template_duplicates
# --------------------------------------------------------------------------- #
def _sample(url: str, title: str | None) -> dict:
    return {"url": url, "title": title}


def test_detect_template_duplicates_title_threshold():
    samples = [
        _sample("https://e.com/a", "Дубликат"),
        _sample("https://e.com/b", "Дубликат"),
        _sample("https://e.com/c", "Дубликат"),
        # два одинаковых заголовка — НЕ дубликат (порог >= 3)
        _sample("https://e.com/d", "Пара"),
        _sample("https://e.com/e", "Пара"),
        _sample("https://e.com/f", "Уникальный"),
    ]
    result = detect_template_duplicates(samples)
    assert result["total"] == 6
    assert result["duplicate_title_count"] == 3
    assert result["duplicate_title_share"] == pytest.approx(0.5)
    assert "Дубликат" in result["duplicate_title_groups"]
    assert "Пара" not in result["duplicate_title_groups"]


def test_detect_template_duplicates_slug_pattern():
    samples = [
        _sample("https://e.com/name-123/", "A"),
        _sample("https://e.com/name-456/", "B"),
        _sample("https://e.com/about", "C"),
        _sample("https://e.com/blog/post-1", "D"),
    ]
    result = detect_template_duplicates(samples)
    assert result["slug_pattern_count"] == 3
    assert result["slug_pattern_share"] == pytest.approx(0.75)


def test_detect_template_duplicates_combined_junk_share():
    samples = [
        _sample("https://e.com/a", "Dup"),
        _sample("https://e.com/b", "Dup"),
        _sample("https://e.com/c", "Dup"),
        _sample("https://e.com/name-1/", "X"),
        _sample("https://e.com/name-2/", "Y"),
        _sample("https://e.com/clean", "Z"),
        _sample("https://e.com/clean2", "W"),
        _sample("https://e.com/clean3", "V"),
        _sample("https://e.com/clean4", "U"),
        _sample("https://e.com/clean5", "T"),
    ]
    result = detect_template_duplicates(samples)
    assert result["junk_count"] == 5
    assert result["junk_share"] == pytest.approx(0.5)
    assert result["junk_share"] > 0.2


def test_detect_template_duplicates_empty():
    result = detect_template_duplicates([])
    assert result["total"] == 0
    assert result["junk_share"] == 0.0


# --------------------------------------------------------------------------- #
# parse_robots_txt: синтаксис robots.txt
# --------------------------------------------------------------------------- #
def test_parse_robots_txt_clean():
    text = "User-agent: *\nDisallow: /admin/\nAllow: /\nSitemap: https://e.com/sitemap.xml\n"
    result = parse_robots_txt(text)
    assert result["problems"] == []
    assert result["sitemaps"] == ["https://e.com/sitemap.xml"]
    assert result["disallowed_root"] == []
    assert result["rules_before_agent"] == 0


def test_parse_robots_txt_unknown_directive():
    result = parse_robots_txt("User-agent: *\nFoo: bar\nDisallow: /admin/\n")
    assert "Foo" in result["unknown_directives"]
    assert any("неизвестная директива" in p for p in result["problems"])


def test_parse_robots_txt_rule_before_user_agent():
    result = parse_robots_txt("Disallow: /x\nUser-agent: *\nAllow: /\n")
    assert result["rules_before_agent"] == 1
    assert any("до первого User-agent" in p for p in result["problems"])


def test_parse_robots_txt_missing_colon():
    result = parse_robots_txt("User-agent *\n")
    assert any("нет двоеточия" in p for p in result["problems"])


def test_parse_robots_txt_disallow_root_all_agents():
    result = parse_robots_txt("User-agent: *\nDisallow: /\n")
    assert set(result["disallowed_root"]) == {"*", "Googlebot", "Yandex"}


def test_parse_robots_txt_allow_root_not_disallowed():
    result = parse_robots_txt("User-agent: *\nDisallow: /\nAllow: /\n")
    # Allow на той же длине перекрывает Disallow
    assert result["disallowed_root"] == []


def test_parse_robots_txt_specific_agent_overrides_wildcard():
    text = "User-agent: *\nDisallow: /\n\nUser-agent: Googlebot\nAllow: /\n"
    result = parse_robots_txt(text)
    assert "Googlebot" not in result["disallowed_root"]
    assert "*" in result["disallowed_root"]


def test_parse_robots_txt_empty_sitemap_is_problem():
    result = parse_robots_txt("User-agent: *\nSitemap:\n")
    assert any("пустая директива Sitemap" in p for p in result["problems"])


# --------------------------------------------------------------------------- #
# Дополнительные чистые парсеры
# --------------------------------------------------------------------------- #
def test_extract_page_meta():
    html = (
        "<html><head>"
        "<title>  Привет  </title>"
        '<link rel="canonical" href="https://e.com/">'
        '<meta name="robots" content="noindex, nofollow">'
        "</head></html>"
    )
    meta = extract_page_meta(html)
    assert meta["title"] == "Привет"
    assert meta["canonical"] == "https://e.com/"
    assert meta["robots"] == "noindex, nofollow"


def test_extract_page_meta_empty():
    assert extract_page_meta("") == {"title": None, "canonical": None, "robots": None}


def test_extract_hreflang():
    html = (
        '<link rel="alternate" hreflang="en" href="https://e.com/en">'
        '<link rel="alternate" hreflang="x-default" href="https://e.com/">'
        '<link rel="stylesheet" href="/s.css">'
    )
    entries = extract_hreflang(html)
    assert len(entries) == 2
    assert entries[0] == {"hreflang": "en", "href": "https://e.com/en"}


def test_find_mixed_content():
    html = (
        '<img src="http://cdn.e.com/a.png">'
        '<script src="http://cdn.e.com/a.js"></script>'
        '<link rel="stylesheet" href="https://cdn.e.com/a.css">'
        '<iframe src="http://evil.e.com"></iframe>'
    )
    items = find_mixed_content(html)
    urls = {i["url"] for i in items}
    assert urls == {"http://cdn.e.com/a.png", "http://cdn.e.com/a.js", "http://evil.e.com"}
    assert find_mixed_content("") == []


def test_find_mixed_content_srcset():
    html = '<img srcset="http://e.com/a.png 1x, https://e.com/b.png 2x">'
    items = find_mixed_content(html)
    assert any(i["attribute"] == "srcset" for i in items)


def test_count_assets():
    html = (
        '<script src="/a.js"></script><script src="/b.js"></script>'
        '<script>inline()</script>'
        '<link rel="stylesheet" href="/a.css">'
        '<link rel="stylesheet" href="/b.css">'
    )
    assert count_assets(html) == {"scripts": 2, "stylesheets": 2}


def test_parse_hsts_max_age():
    assert parse_hsts_max_age("max-age=15552000; includeSubDomains") == 15552000
    assert parse_hsts_max_age("max-age = 31536000") == 31536000
    assert parse_hsts_max_age("") is None
    assert parse_hsts_max_age("includeSubDomains") is None


def test_php_version():
    assert parse_php_version("PHP/7.4.33") == (7, 4)
    assert parse_php_version("php 8.2.1") == (8, 2)
    assert parse_php_version("nginx") is None
    assert is_php_outdated((7, 4)) is True
    assert is_php_outdated((8, 0)) is True
    assert is_php_outdated((8, 1)) is False
    assert is_php_outdated(None) is False


def test_find_generators():
    html = '<meta name="generator" content="WordPress 5.0"><meta name="viewport" content="x">'
    assert find_generators(html) == ["WordPress 5.0"]


def test_looks_like_feed():
    assert looks_like_feed("<rss version='2.0'><channel></channel></rss>") is True
    assert looks_like_feed('<feed xmlns="http://www.w3.org/2005/Atom"></feed>') is True
    assert looks_like_feed('{"version": "https://jsonfeed.org/version/1"}') is True
    assert looks_like_feed("plain html", "application/json") is True
    assert looks_like_feed("just some text") is False


def test_analyze_slugs():
    urls = [
        "https://e.com/hello-world",
        "https://e.com/Bad_Slug",
        "https://e.com/page?utm_source=x",
        "https://other.com/external",
    ]
    stats = analyze_slugs(urls, "e.com")
    # внешняя ссылка отфильтрована
    assert stats["total"] == 3
    assert stats["non_kebab_count"] == 1
    assert stats["params_count"] == 1


def test_analyze_slugs_empty():
    stats = analyze_slugs([], "e.com")
    assert stats["total"] == 0
    assert stats["non_kebab_share"] == 0.0
