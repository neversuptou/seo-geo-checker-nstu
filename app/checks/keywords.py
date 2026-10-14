"""Проверки релевантности ключевых слов.

Проверки:
- bm25_relevance — BM25-релевантность фразы к пассажам страницы, а также
  наличие ключа в title, H1 и description.

Чистая логика вынесена в функции без сети `tokenize`, `stem`, `bm25_scores`,
`split_passages`, поэтому её можно покрывать юнит-тестами.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Dict, List

from selectolax.lexbor import LexborHTMLParser

from app.core import AuditContext, CheckResult, Finding
from app.registry import check

CATEGORY = "Ключевые слова"

K1 = 1.5
B = 0.75

# Токен слова: латиница, кириллица (включая ё) и цифры.
_WORD_RE = re.compile(r"[a-zа-яёЁ0-9]+")

# Простые окончания для грубого стемминга. Длинные проверяются первыми.
_SUFFIXES: List[str] = [
    "иями", "ями", "ами", "ией", "иях", "иям", "ость", "ости", "остью",
    "ений", "ения", "ению", "ением", "ении", "ания", "анию", "анием", "ании",
    "аться", "иться", "ыться", "яется", "ается", "ирует",
    "ать", "ять", "еть", "ить", "ыть", "уть", "ють", "ишь", "ете", "ите",
    "ают", "яют", "ует", "оет", "еет", "ится", "атся",
    "ого", "его", "ому", "ему", "ыми", "ими", "ей", "ой", "ый", "ий",
    "ая", "яя", "ое", "ее", "ые", "ие", "ых", "их", "ую", "юю",
    "ам", "ям", "ах", "ях", "ов", "ев", "ем", "ом", "ия", "ие", "ии",
    # английские
    "ing", "edly", "ed", "es", "ly", "s",
    # короткие русские
    "а", "я", "ы", "и", "о", "е", "у", "ю", "ь",
]

_SUFFIXES_SORTED = sorted(_SUFFIXES, key=len, reverse=True)
_MIN_STEM = 4


def stem(word: str) -> str:
    """Грубый стемминг: отрезает наиболее длинное известное окончание."""
    if not word:
        return word
    for suffix in _SUFFIXES_SORTED:
        if word.endswith(suffix) and len(word) - len(suffix) >= _MIN_STEM:
            return word[: -len(suffix)]
    return word


def tokenize(text: str) -> List[str]:
    """Разбить текст на нормализованные токены (нижний регистр + стемминг)."""
    if not text:
        return []
    words = _WORD_RE.findall(text.lower())
    return [stem(w) for w in words if len(w) > 1]


def bm25_scores(
    query: List[str],
    docs: List[List[str]],
    k1: float = K1,
    b: float = B,
) -> List[float]:
    """BM25-оценка каждого документа по списку токенов запроса.

    Возвращает список оценок той же длины, что и `docs`.
    """
    n = len(docs)
    if n == 0:
        return []

    lengths = [len(doc) for doc in docs]
    avgdl = (sum(lengths) / n) if n else 0.0
    if avgdl <= 0:
        avgdl = 1.0

    doc_freq: Counter = Counter()
    for doc in docs:
        for term in set(doc):
            doc_freq[term] += 1

    query_counts = Counter(query)
    scores: List[float] = []
    for i, doc in enumerate(docs):
        term_freq = Counter(doc)
        dl = lengths[i]
        total = 0.0
        for term, qtf in query_counts.items():
            f = term_freq.get(term, 0)
            if f == 0:
                continue
            df = doc_freq.get(term, 0)
            idf = math.log((n - df + 0.5) / (df + 0.5) + 1.0)
            denom = f + k1 * (1.0 - b + b * (dl / avgdl))
            total += idf * (f * (k1 + 1.0)) / denom * qtf
        scores.append(total)
    return scores


def split_passages(html: str) -> Dict[str, Any]:
    """Разобрать HTML на пассажи (заголовки, абзацы, списки) и метаданные.

    Возвращает {"title", "description", "h1", "passages"}.
    """
    result: Dict[str, Any] = {"title": "", "description": "", "h1": [], "passages": []}
    if not html:
        return result

    try:
        tree = LexborHTMLParser(html)
    except Exception:
        return result

    for tag in ("script", "style", "noscript", "template", "svg"):
        for node in tree.css(tag):
            try:
                node.decompose()
            except Exception:
                pass

    title_node = tree.css_first("title")
    if title_node is not None:
        result["title"] = (title_node.text() or "").strip()

    for node in tree.css("meta"):
        name = (node.attributes.get("name") or "").lower()
        if name == "description":
            result["description"] = (node.attributes.get("content") or "").strip()
            break

    for node in tree.css("h1"):
        text = (node.text() or "").strip()
        if text:
            result["h1"].append(text)

    passages: List[str] = []
    for node in tree.css("h2, h3, h4, p, li"):
        text = re.sub(r"\s+", " ", node.text() or "").strip()
        if len(text) >= 20:
            passages.append(text)

    if not passages:
        body = tree.css_first("body")
        if body is not None:
            text = re.sub(r"\s+", " ", body.text() or "").strip()
            if text:
                passages = [text]

    result["passages"] = passages
    return result


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


@check(id="bm25_relevance", title="BM25-релевантность ключевых слов", category=CATEGORY)
async def bm25_relevance(ctx: AuditContext) -> CheckResult:
    check_id = "bm25_relevance"
    title = "BM25-релевантность ключевых слов"

    keywords = [k.strip() for k in (ctx.keywords or []) if k and k.strip()]
    if not keywords:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=[
                Finding(
                    level="info",
                    text="Ключевые слова не заданы — проверка релевантности пропущена",
                    fix="Передать список ключевых фраз для оценки релевантности",
                    hours=0.0,
                )
            ],
            raw={"keywords": []},
        )

    resp = await ctx.home()
    if resp is None:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=0,
            findings=[
                Finding(
                    level="warning",
                    text="Не удалось получить страницу для оценки релевантности ключей",
                    fix="Проверить доступность сайта и повторить аудит",
                    hours=0.5,
                )
            ],
            raw={"keywords": keywords, "error": "network"},
        )

    parsed = split_passages(resp.text or "")
    passages: List[str] = parsed["passages"]
    passage_tokens = [tokenize(p) for p in passages]
    title_norm = _normalize(parsed["title"])
    description_norm = _normalize(parsed["description"])
    h1_norm = " ".join(_normalize(h) for h in parsed["h1"])

    per_keyword: List[Dict[str, Any]] = []
    findings: List[Finding] = []
    missing: List[str] = []

    for keyword in keywords:
        query = tokenize(keyword)
        raw_scores = bm25_scores(query, passage_tokens)
        best_score = max(raw_scores) if raw_scores else 0.0
        best_index = raw_scores.index(best_score) if raw_scores else -1

        kw_norm = _normalize(keyword)
        in_title = bool(kw_norm) and kw_norm in title_norm
        in_h1 = bool(kw_norm) and kw_norm in h1_norm
        in_description = bool(kw_norm) and kw_norm in description_norm
        in_body = best_score > 0

        entry = {
            "keyword": keyword,
            "score": round(best_score, 3),
            "in_title": in_title,
            "in_h1": in_h1,
            "in_description": in_description,
            "in_body": in_body,
            "best_passage_index": best_index,
            "best_passage": passages[best_index] if best_index >= 0 else None,
        }
        per_keyword.append(entry)

        if not in_body and not in_title and not in_h1:
            missing.append(keyword)
            findings.append(
                Finding(
                    level="critical",
                    text=f"Ключевая фраза «{keyword}» отсутствует в тексте, title и H1",
                    fix=f"Добавить фразу «{keyword}» в H1, первый абзац и title главной страницы в естественном виде",
                    hours=2.0,
                )
            )
        elif not (in_title or in_h1):
            findings.append(
                Finding(
                    level="warning",
                    text=f"Ключевая фраза «{keyword}» есть в тексте, но не в title и не в H1 (BM25: {round(best_score, 3)})",
                    fix=f"Включить «{keyword}» в title и H1, сохраняя точное вхождение",
                    hours=1.0,
                )
            )
        else:
            findings.append(
                Finding(
                    level="ok",
                    text=f"Ключевая фраза «{keyword}» релевантна (BM25: {round(best_score, 3)}; "
                    f"title: {'да' if in_title else 'нет'}, H1: {'да' if in_h1 else 'нет'})",
                    fix="",
                )
            )

    if not passages:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="warning",
            score=0,
            findings=[
                Finding(
                    level="warning",
                    text="На странице не найден текстовый контент для анализа релевантности",
                    fix="Наполнить страницу осмысленным текстом с ключевыми фразами",
                    hours=4.0,
                )
            ],
            raw={"keywords": keywords, "per_keyword": per_keyword, "passages_count": 0},
        )

    total = len(keywords)
    missing_count = len(missing)
    if missing_count == 0:
        status = "ok"
        score = 100
    elif missing_count < total:
        status = "warning"
        score = max(30, int(round(100 * (total - missing_count) / total)))
    else:
        status = "critical"
        score = 0

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={
            "keywords": keywords,
            "per_keyword": per_keyword,
            "passages_count": len(passages),
            "missing": missing,
            "title": parsed["title"],
            "h1": parsed["h1"],
            "description": parsed["description"],
        },
    )
