from __future__ import annotations

import json

from app.checks.geo_content import (
    AI_BOTS,
    analyze_no_js,
    analyze_sections,
    detect_dates_author,
    detect_faq,
    extract_brand,
)


def _lorem(n: int) -> str:
    return " ".join(f"слово{i}" for i in range(n))


# --- analyze_sections ------------------------------------------------------

SECTION_HTML = f"""
<html><head><title>GEO</title></head><body>
<header><nav>меню навигации</nav></header>
<h2>Что такое GEO-оптимизация?</h2>
<p>{_lorem(60)} 10 лет опыта и 500 проектов.</p>
<h2>Преимущества</h2>
<ul><li>Рост трафика из AI в 3 раза</li><li>Экономия 25% бюджета</li></ul>
<h3>Как выбрать подрядчика?</h3>
<p>Более 20 кейсов, срок от 4 недель, цена от 100 000 рублей.</p>
<table><tr><td>Тариф</td><td>Цена</td></tr><tr><td>Базовый</td><td>50 000</td></tr></table>
<footer>подвал сайта</footer>
</body></html>
"""


def test_analyze_sections_splits_by_headings():
    sections = analyze_sections(SECTION_HTML)
    headings = [s["heading"] for s in sections]
    assert headings == ["Что такое GEO-оптимизация?", "Преимущества", "Как выбрать подрядчика?"]
    assert [s["level"] for s in sections] == [2, 2, 3]


def test_analyze_sections_question_flag():
    sections = analyze_sections(SECTION_HTML)
    assert sections[0]["is_question"] is True
    assert sections[1]["is_question"] is False


def test_analyze_sections_lists_tables_numbers():
    sections = analyze_sections(SECTION_HTML)
    first, second, third = sections
    assert first["words"] >= 60
    assert first["numbers"] >= 3
    assert second["has_list"] is True
    assert second["has_table"] is False
    assert second["words"] > 0
    assert third["has_table"] is True
    assert third["numbers"] >= 3


def test_analyze_sections_no_headings():
    assert analyze_sections("<html><body><p>текст без заголовков</p></body></html>") == []


# --- content_no_js / SPA detection ----------------------------------------

SPA_HTML = (
    "<html><head><title>App</title></head><body>"
    '<div id="root"></div>'
    "<noscript>Please enable JavaScript to continue</noscript>"
    "</body></html>"
)

STATIC_HTML = (
    "<html><head><title>Статичный сайт</title></head><body>"
    "<h1>Заголовок</h1>"
    f"<p>{_lorem(320)}</p>"
    "</body></html>"
)


def test_no_js_detects_spa():
    data = analyze_no_js(SPA_HTML)
    assert data["is_spa_likely"] is True
    assert "#root" in data["empty_spa_containers"]
    assert data["noscript_mentions_js"] is True
    assert data["words"] < 150
    assert data["has_title"] is True
    assert data["has_h1"] is False
    assert data["spa_signs"]


def test_no_js_static_page_ok():
    data = analyze_no_js(STATIC_HTML)
    assert data["is_spa_likely"] is False
    assert data["empty_spa_containers"] == []
    assert data["words"] >= 150
    assert data["has_h1"] is True


def test_no_js_ignores_script_text():
    html = (
        "<html><head><title>t</title></head><body><h1>h</h1>"
        "<script>var a = 'очень много слов внутри скрипта, которые не должны считаться';</script>"
        "<style>.x { color: red; }</style><p>мало слов</p></body></html>"
    )
    data = analyze_no_js(html)
    assert data["words"] < 20


# --- dates / author / faq --------------------------------------------------

def test_detect_dates_author():
    html = (
        '<html><head>'
        '<meta property="article:published_time" content="2024-01-01">'
        '<meta property="article:modified_time" content="2024-06-01">'
        '<meta name="author" content="Иван Петров">'
        '</head><body><time datetime="2024-06-01">1 июня</time></body></html>'
    )
    data = detect_dates_author(html)
    assert data["published"] == "2024-01-01"
    assert data["modified"] == "2024-06-01"
    assert data["has_time_element"] is True
    assert data["has_date"] is True
    assert data["author"] == "Иван Петров"
    assert data["has_author"] is True


def test_detect_faq_heading_and_schema():
    html = '<html><body><h2>FAQ</h2><p>вопрос</p></body></html>'
    assert detect_faq(html)["present"] is True
    assert detect_faq("<html><body><h2>О нас</h2></body></html>")["present"] is False


# --- brand extraction ------------------------------------------------------

BRAND_HTML = f"""
<html><head><title>Бренд</title>
<script type="application/ld+json">
{json.dumps({
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "Ромашка",
    "url": "https://romashka.example",
    "logo": "https://romashka.example/logo.png",
    "sameAs": [
        "https://vk.com/romashka",
        "https://t.me/romashka",
        "https://www.wikidata.org/wiki/Q123",
    ],
    "contactPoint": {"@type": "ContactPoint", "telephone": "+7-999-000-00-00", "email": "hi@romashka.example"},
    "address": {"@type": "PostalAddress", "addressLocality": "Москва", "streetAddress": "ул. Ленина, 1"},
})}
</script>
</head><body><h1>Ромашка</h1></body></html>
"""


def test_extract_brand_full():
    brand = extract_brand(BRAND_HTML)
    assert brand["found"] is True
    assert brand["name"] == "Ромашка"
    assert brand["url"] == "https://romashka.example"
    assert brand["logo"].endswith("logo.png")
    assert brand["wikidata"] is True
    assert brand["wikipedia"] is False
    assert brand["socials"].get("VK") == "https://vk.com/romashka"
    assert brand["socials"].get("Telegram") == "https://t.me/romashka"
    assert brand["contact_point"] is True
    assert brand["telephone"] == "+7-999-000-00-00"
    assert brand["email"] == "hi@romashka.example"
    assert "Москва" in brand["address"]


def test_extract_brand_missing_org():
    brand = extract_brand("<html><body><h1>Без разметки</h1></body></html>")
    assert brand["found"] is False
    assert brand["same_as"] == []
    assert brand["contact_point"] is False


def test_extract_brand_handles_graph_and_invalid_json():
    graph_html = (
        '<script type="application/ld+json">'
        + json.dumps(
            {
                "@context": "https://schema.org",
                "@graph": [
                    {"@type": "WebSite", "name": "site"},
                    {"@type": "OnlineStore", "name": "Магазин"},
                ],
            }
        )
        + "</script>"
        '<script type="application/ld+json">{невалидный json</script>'
    )
    brand = extract_brand(graph_html)
    assert brand["found"] is True
    assert brand["name"] == "Магазин"


def test_ai_bots_have_real_user_agents():
    names = [name for name, _, _ in AI_BOTS]
    assert names == [
        "GPTBot",
        "OAI-SearchBot",
        "ClaudeBot",
        "PerplexityBot",
        "Google-Extended",
        "YandexBot",
        "Bytespider",
        "CCBot",
    ]
    for name, ua, _ in AI_BOTS:
        assert ua and "Mozilla" in ua
