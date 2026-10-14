import json

from app.checks.brand_knowledge import extract_brand, generate_queries, match_official_site


def test_extract_brand_jsonld():
    html = """
    <html lang="ru">
    <head>
        <script type="application/ld+json">
        {
            "@context": "https://schema.org",
            "@type": "Organization",
            "name": "CosmoShop"
        }
        </script>
        <title>CosmoShop - интернет-магазин косметики</title>
    </head>
    <body></body>
    </html>
    """
    res = extract_brand(html, "www.cosmoshop.ru")
    assert res["brand"] == "CosmoShop"
    assert "ru" in res["lang"]


def test_extract_brand_og_site_name():
    html = """
    <html lang="en">
    <head>
        <meta property="og:site_name" content="BeautyBrand">
        <title>BeautyBrand | Shop</title>
    </head>
    <body></body>
    </html>
    """
    res = extract_brand(html, "beautybrand.com")
    assert res["brand"] == "BeautyBrand"
    assert res["lang"] == "en"


def test_extract_brand_title_fallback():
    html = """
    <html>
    <head>
        <title>FreshCare — магазин ухода</title>
    </head>
    <body></body>
    </html>
    """
    res = extract_brand(html, "freshcare.io")
    assert res["brand"] == "FreshCare"


def test_generate_queries_en_fake_cosmetics():
    data = {
        "brand": "GlowCo",
        "title": "GlowCo - Natural skincare",
        "description": "Best natural skincare products for healthy skin",
        "h1": "Skincare",
        "h2": ["Moisturizers", "Serums", "Cleansers"],
        "nav_anchors": ["Cart", "Login", "Moisturizers", "Serums", "Contact"],
        "product_names": ["Glow Cream", "Glow Serum"],
        "lang": "en",
        "region": "Europe",
    }
    queries = generate_queries(data)
    assert 8 <= len(queries) <= 12
    assert all(q.strip() for q in queries)
    joined = " ".join(queries).lower()
    assert "cart" not in joined or joined.count("cart") == 0
    assert "login" not in joined
    assert "contact" not in joined


def test_generate_queries_ru_fake_cosmetics():
    data = {
        "brand": "Лайм",
        "title": "Лайм — магазин косметики",
        "description": "Лучшие средства для ухода за кожей",
        "h1": "Косметика",
        "h2": ["Кремы", "Сыворотки", "Очищение"],
        "nav_anchors": ["Корзина", "Войти", "Кремы", "Сыворотки", "Контакты"],
        "product_names": ["Крем ночной", "Сыворотка витаминная"],
        "lang": "ru",
        "region": "Россия",
    }
    queries = generate_queries(data)
    assert 8 <= len(queries) <= 12
    assert all(q.strip() for q in queries)
    joined = " ".join(queries).lower()
    assert "корзина" not in joined
    assert "войти" not in joined
    assert "контакты" not in joined


def test_match_official_site_fixture():
    entity_json = {
        "entities": {
            "Q12345": {
                "claims": {
                    "P856": [
                        {
                            "mainsnak": {
                                "datavalue": {
                                    "value": "https://www.glowco.com/"
                                }
                            }
                        }
                    ]
                }
            }
        }
    }
    assert match_official_site(entity_json, "glowco.com") is True
    assert match_official_site(entity_json, "example.com") is False
