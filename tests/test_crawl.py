import httpx
import pytest

from app.checks.crawl import extract_page_data, find_duplicates, get_crawl, normalize_url
from app.core import AuditContext


def test_normalize_url():
    base = "https://example.com/catalog/"
    assert normalize_url("item#reviews", base) == "https://example.com/catalog/item"
    assert normalize_url("https://www.example.com/a", base) == "https://www.example.com/a"
    assert normalize_url("https://other.com/a", base) is None
    assert normalize_url("mailto:a@b.c", base) is None
    assert normalize_url("/img/photo.JPG", base) is None
    assert normalize_url("/shop/?add-to-cart=5", base) is None


def test_extract_page_data():
    html = """<html><head><title> Page </title><meta name="description" content="Desc">
    <meta name="robots" content="noindex, follow"><link rel="canonical" href="/canon/"></head>
    <body><nav><a href="/menu">menu words not counted</a></nav>
    <h1>Header</h1><p>one two three four five</p><a href="/x" rel="nofollow">x</a><a href="/y">y</a></body></html>"""
    data = extract_page_data(html, "https://example.com/page")
    assert data["title"] == "Page"
    assert data["description"] == "Desc"
    assert data["h1"] == ["Header"]
    assert data["canonical"] == "https://example.com/canon/"
    assert data["noindex"] is True
    assert data["links"] == ["https://example.com/menu", "https://example.com/y"]
    assert data["words"] == 6  # Header + 5 слов; меню и однобуквенные ссылки не считаются


def test_find_duplicates():
    pages = [
        {"url": "a", "title": "Same", "h1": ["X"]},
        {"url": "b", "title": "same ", "h1": ["Y"]},
        {"url": "c", "title": "Other", "h1": []},
    ]
    assert find_duplicates(pages, "title") == {"same": ["a", "b"]}
    assert find_duplicates(pages, "h1") == {}


SITE = {
    "/": '<title>Home</title><a href="/a">a</a><a href="/b">b</a>',
    "/a": '<title>A</title><a href="/c">c</a><a href="/">home</a>',
    "/b": '<title>B</title><a href="/c">c</a><a href="/private/x">x</a>',
    "/c": "<title>C</title>",
    "/robots.txt": "User-agent: *\nDisallow: /private/",
}


@pytest.mark.asyncio
async def test_get_crawl_bfs_depth_inbound_and_cache():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        body = SITE.get(request.url.path)
        if body is None:
            return httpx.Response(404, text="nope")
        ctype = "text/plain" if request.url.path.endswith(".txt") else "text/html"
        return httpx.Response(200, text=body, headers={"content-type": ctype})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        ctx = AuditContext("https://example.com", client=client)
        crawl = await get_crawl(ctx)
        again = await get_crawl(ctx)

    pages = {p["url"].replace("https://example.com", ""): p for p in crawl["pages"]}
    assert set(pages) == {"/", "/a", "/b", "/c"}  # /private/ закрыт в robots.txt
    assert pages["/c"]["depth"] == 2
    assert pages["/c"]["inbound"] == 2
    assert again is crawl
    assert calls.count("/c") == 1


def test_disallow_wildcards_do_not_block_whole_site():
    from app.checks.crawl import _blocked, disallow_patterns

    patterns = disallow_patterns("User-agent: *\nDisallow: /*?utm_*\nDisallow: /admin/\nDisallow: /*.pdf$\n\nUser-agent: Bot\nDisallow: /")
    assert not _blocked("https://e.com/services/", patterns)
    assert _blocked("https://e.com/page?utm_source=x", patterns)
    assert _blocked("https://e.com/admin/users", patterns)
    assert _blocked("https://e.com/files/a.pdf", patterns)
    assert not _blocked("https://e.com/files/a.pdf?x=1", patterns)
