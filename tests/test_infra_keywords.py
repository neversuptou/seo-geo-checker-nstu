from __future__ import annotations

import pytest

from app.checks.infra import (
    cert_days_left,
    count_spf_lookups,
    detect_cms,
    extract_meta_generator,
    host_matches_san,
    parse_dkim,
    parse_dmarc,
    parse_peer_cert,
    parse_rdap,
    parse_spf,
    registrable_domain,
)
from app.checks.keywords import bm25_scores, split_passages, stem, tokenize

# --------------------------------------------------------------------------- #
# SPF
# --------------------------------------------------------------------------- #
def test_parse_spf_typical():
    records = [
        "some-other-txt",
        "v=spf1 include:_spf.google.com include:mailgun.org ~all",
    ]
    spf = parse_spf(records)
    assert spf["present"] is True
    assert spf["count"] == 1
    assert spf["multiple"] is False
    assert spf["qualifier"] == "~all"
    assert spf["lookups"] == 2
    assert spf["lookup_breakdown"]["include"] == 2


def test_parse_spf_missing():
    spf = parse_spf(["google-site-verification=abc"])
    assert spf["present"] is False
    assert spf["record"] is None
    assert spf["lookups"] == 0


def test_parse_spf_multiple_records():
    records = ["v=spf1 include:a.com -all", "v=spf1 include:b.com ~all"]
    spf = parse_spf(records)
    assert spf["present"] is True
    assert spf["count"] == 2
    assert spf["multiple"] is True
    assert spf["qualifier"] == "-all"


def test_count_spf_lookups():
    spf = "v=spf1 a mx include:_spf.example.com ip4:1.2.3.4 -all redirect=_spf.other.com"
    counts = count_spf_lookups(spf)
    assert counts["a"] == 1
    assert counts["mx"] == 1
    assert counts["include"] == 1
    assert counts["redirect"] == 1
    assert sum(counts.values()) == 4


def test_count_spf_lookups_ignores_qualifier_and_ips():
    assert sum(count_spf_lookups("v=spf1 -all").values()) == 0
    assert sum(count_spf_lookups("v=spf1 ip4:10.0.0.0/8 ip6:2001:db8::/32 ?all").values()) == 0


# --------------------------------------------------------------------------- #
# DMARC
# --------------------------------------------------------------------------- #
def test_parse_dmarc():
    dmarc = parse_dmarc(["v=DMARC1; p=none; rua=mailto:dmarc@example.com; pct=100"])
    assert dmarc["present"] is True
    assert dmarc["policy"] == "none"
    assert dmarc["rua"] == "mailto:dmarc@example.com"
    assert dmarc["pct"] == "100"


def test_parse_dmarc_reject_with_sp():
    dmarc = parse_dmarc(["v=DMARC1; p=reject; sp=quarantine"])
    assert dmarc["policy"] == "reject"
    assert dmarc["subdomain_policy"] == "quarantine"


def test_parse_dmarc_missing():
    dmarc = parse_dmarc(["v=spf1 -all"])
    assert dmarc["present"] is False
    assert dmarc["policy"] is None


# --------------------------------------------------------------------------- #
# DKIM
# --------------------------------------------------------------------------- #
def test_parse_dkim_present():
    dkim = parse_dkim(["v=DKIM1; k=rsa; p=MIIBIjANBgkq..."])
    assert dkim["present"] is True


def test_parse_dkim_absent():
    assert parse_dkim(["v=spf1 -all"])["present"] is False
    assert parse_dkim([])["present"] is False


# --------------------------------------------------------------------------- #
# TLS-сертификат
# --------------------------------------------------------------------------- #
@pytest.fixture
def peer_cert():
    return {
        "issuer": (
            (("organizationName", "Let's Encrypt"),),
            (("commonName", "R3"),),
        ),
        "subject": ((("commonName", "example.com"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com")),
        "notAfter": "Dec 31 23:59:59 2030 GMT",
        "serialNumber": "0A1B2C",
    }


def test_parse_peer_cert(peer_cert):
    parsed = parse_peer_cert(peer_cert)
    assert parsed["issuer_org"] == "Let's Encrypt"
    assert parsed["issuer_cn"] == "R3"
    assert parsed["subject_cn"] == "example.com"
    assert parsed["san"] == ["example.com", "*.example.com"]
    assert parsed["days_left"] is not None and parsed["days_left"] > 0


def test_parse_peer_cert_empty():
    parsed = parse_peer_cert(None)
    assert parsed["san"] == []
    assert parsed["days_left"] is None


def test_host_matches_san_exact_and_wildcard():
    assert host_matches_san(["example.com", "*.example.com"], "www.example.com") is True
    assert host_matches_san(["*.example.com"], "example.com") is False
    assert host_matches_san(["*.example.com"], "a.b.example.com") is False
    assert host_matches_san(["example.com"], "other.com") is False


def test_cert_days_left_expired():
    assert cert_days_left("Jan 01 00:00:00 2000 GMT") < 0
    assert cert_days_left(None) is None


# --------------------------------------------------------------------------- #
# Домен / RDAP
# --------------------------------------------------------------------------- #
def test_registrable_domain():
    assert registrable_domain("www.example.com") == "example.com"
    assert registrable_domain("example.com") == "example.com"
    assert registrable_domain("shop.example.co.uk") == "example.co.uk"
    assert registrable_domain("example.com:443") == "example.com"


def test_parse_rdap():
    data = {
        "events": [
            {"eventAction": "registration", "eventDate": "2015-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            }
        ],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
        "status": ["client transfer prohibited"],
    }
    info = parse_rdap(data)
    assert info["registrar"] == "Example Registrar"
    assert info["registration"] == "2015-01-01T00:00:00Z"
    assert info["age_days"] is not None and info["age_days"] > 0
    assert info["days_to_expiry"] is not None and info["days_to_expiry"] > 0
    assert info["nameservers"] == ["ns1.example.com"]


def test_parse_rdap_garbage():
    info = parse_rdap(None)
    assert info["registrar"] is None
    assert info["age_days"] is None


# --------------------------------------------------------------------------- #
# Определение CMS
# --------------------------------------------------------------------------- #
def test_detect_cms_wordpress_from_html():
    html = (
        "<html><head>"
        '<meta name="generator" content="WordPress 6.4.2" />'
        '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">'
        "</head><body>hi</body></html>"
    )
    result = detect_cms(headers={}, html=html)
    assert result["primary"] == "WordPress"
    wp = next(item for item in result["detected"] if item["name"] == "WordPress")
    assert wp["version"] == "6.4.2"


def test_detect_cms_nextjs_from_header():
    result = detect_cms(headers={"X-Powered-By": "Next.js"}, html="<html></html>")
    assert "Next.js" in result["technologies"]


def test_detect_cms_shopify():
    html = '<html><head><script src="https://cdn.shopify.com/s/x.js"></script></head></html>'
    result = detect_cms(headers={}, html=html)
    assert "Shopify" in result["technologies"]


def test_detect_cms_bitrix():
    html = '<html><body><script src="/bitrix/js/main/core.js"></script></body></html>'
    result = detect_cms(headers={"X-Powered-CMS": "Bitrix Site Manager"}, html=html)
    assert "Bitrix" in result["technologies"]


def test_detect_cms_none():
    result = detect_cms(headers={"Server": "nginx"}, html="<html><body>plain</body></html>")
    assert result["detected"] == []
    assert result["primary"] is None


def test_extract_meta_generator():
    html = '<meta name="generator" content="Joomla! 4.5">'
    assert extract_meta_generator(html) == "Joomla! 4.5"
    assert extract_meta_generator("") == ""


# --------------------------------------------------------------------------- #
# Токенизация
# --------------------------------------------------------------------------- #
def test_tokenize_lowercase_and_words():
    tokens = tokenize("SEO Аудит, сайта! 2024")
    assert tokens == [stem("seo"), stem("аудит"), stem("сайта"), stem("2024")]


def test_tokenize_stemming_consistency():
    assert tokenize("Машины") == tokenize("машина")
    assert tokenize("кошки") == tokenize("кошками")
    assert stem("сайты") == stem("сайта")


def test_tokenize_empty():
    assert tokenize("") == []
    assert tokenize("!!!") == []


# --------------------------------------------------------------------------- #
# BM25
# --------------------------------------------------------------------------- #
def test_bm25_scores_ordering_by_frequency():
    docs = [["seo", "seo", "audit"], ["seo", "weather"], ["weather", "tomorrow"]]
    scores = bm25_scores(["seo"], docs)
    assert len(scores) == 3
    assert scores[0] > scores[1] > scores[2]


def test_bm25_scores_ordering_by_query_match():
    docs = [["seo", "audit", "site"], ["weather", "rain"], ["seo"]]
    scores = bm25_scores(["seo"], docs)
    assert scores[0] > scores[1]
    assert scores[2] > scores[1]


def test_bm25_scores_no_match_is_zero():
    docs = [["weather", "rain"], ["sun"]]
    scores = bm25_scores(["seo"], docs)
    assert scores == [0.0, 0.0]


def test_bm25_scores_empty():
    assert bm25_scores(["seo"], []) == []
    assert bm25_scores([], [["seo"]]) == [0.0]


# --------------------------------------------------------------------------- #
# Пассажи
# --------------------------------------------------------------------------- #
def test_split_passages():
    html = (
        "<html><head><title>Заголовок</title>"
        '<meta name="description" content="Описание страницы">'
        "</head><body>"
        "<h1>Главный заголовок</h1>"
        "<p>Это достаточно длинный абзац текста для проверки пассажей.</p>"
        "<script>var x = 'длинный скрипт, который не должен попасть в текст';</script>"
        "</body></html>"
    )
    parsed = split_passages(html)
    assert parsed["title"] == "Заголовок"
    assert parsed["description"] == "Описание страницы"
    assert parsed["h1"] == ["Главный заголовок"]
    assert any("длинный абзац" in p for p in parsed["passages"])
    assert all("скрипт" not in p for p in parsed["passages"])


def test_split_passages_empty():
    parsed = split_passages("")
    assert parsed["passages"] == []
