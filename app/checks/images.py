"""Проверка оптимизации изображений и их загрузки.

Проверки:
- images_optimization — вес изображений, современные форматы, размеры (CLS),
  ленивая загрузка и общий вес картинок страницы.

Чистая логика (без сети) вынесена в синхронные функции и покрыта юнит-тестами:
`parse_images`, `image_issues`.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from selectolax.lexbor import LexborHTMLParser as HTMLParser

from app.core import AuditContext, CheckResult, Finding
from app.registry import check
from app.checks.structured_data import detect_shop, find_product_links

CATEGORY = "Изображения"

# Порог «тяжёлого» изображения: > 200 КБ — warning, > 500 КБ — critical.
HEAVY_WARN_BYTES = 200 * 1024
HEAVY_CRIT_BYTES = 500 * 1024

# Первые ~3 изображения обычно выше линии сгиба (кандидаты в LCP).
LAZY_AFTER = 3

# Максимум URL, для которых запрашиваются размеры через HEAD/GET.
MAX_PROBE = 20
PROBE_CONCURRENCY = 6

_LEGACY_EXTS = (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif")
_MODERN_FORMATS = ("webp", "avif")
_MODERN_CONTENT_TYPES = ("image/webp", "image/avif")

# Признаки lazy-заглушки в src.
_PLACEHOLDER_MARKERS = ("placeholder", "lazy", "blank", "spacer", "loading", "1x1", "transparent")

_NON_IMAGE_URL = ("data:", "blob:", "about:")


def _clean_url(url: str, base: str) -> str:
    u = (url or "").strip()
    if not u and not base:
        return ""
    if u.startswith(("http://", "https://", "//")):
        if u.startswith("//"):
            return "https:" + u
        return u
    if u.startswith(_NON_IMAGE_URL):
        return u
    if base:
        return urljoin(base.rstrip("/") + "/", u)
    return u


def _srcset_urls(srcset: str) -> List[str]:
    """Извлечь URL из атрибута srcset (без дескрипторов ширины/плотности)."""
    if not srcset:
        return []
    out: List[str] = []
    for part in srcset.split(","):
        candidate = part.strip().split(" ")[0].strip()
        if candidate:
            out.append(candidate)
    return out


def _looks_placeholder(url: str) -> bool:
    low = (url or "").lower()
    return any(marker in low for marker in _PLACEHOLDER_MARKERS)


def _picture_sources(node: Any) -> List[Dict[str, str]]:
    """Собрать <source> внутри <picture>, которому принадлежит изображение."""
    sources: List[Dict[str, str]] = []
    current = node
    depth = 0
    while current is not None and depth < 8:
        if (current.tag or "").lower() == "picture":
            for src_node in current.css("source"):
                attrs = src_node.attributes
                sources.append(
                    {
                        "type": (attrs.get("type") or "").strip().lower(),
                        "srcset": (attrs.get("srcset") or attrs.get("data-srcset") or "").strip(),
                        "media": (attrs.get("media") or "").strip(),
                    }
                )
            break
        current = getattr(current, "parent", None)
        depth += 1
    return sources


def parse_images(html: str, base: str = "") -> List[Dict[str, Any]]:
    """Чистая функция: собрать изображения страницы с их атрибутами.

    Для каждого <img> возвращается словарь с абсолютным src, srcset, data-src,
    loading/width/height/decoding и списком <source> родительского <picture>.
    data-src используется как основной адрес, если src — lazy-заглушка.
    """
    images: List[Dict[str, Any]] = []
    try:
        tree = HTMLParser(html or "")
    except Exception:  # pragma: no cover - защитный путь
        return images

    for index, node in enumerate(tree.css("img")):
        attrs = node.attributes

        src_raw = (attrs.get("src") or "").strip()
        data_src_raw = (attrs.get("data-src") or attrs.get("data-lazy-src") or attrs.get("data-original") or "").strip()
        srcset_raw = (attrs.get("srcset") or attrs.get("data-srcset") or "").strip()

        # Если src — заглушка, а data-src есть, считаем основным data-src.
        primary_raw = src_raw
        if (not src_raw or _looks_placeholder(src_raw)) and data_src_raw:
            primary_raw = data_src_raw

        images.append(
            {
                "index": index,
                "src": _clean_url(primary_raw, base),
                "src_raw": primary_raw,
                "srcset": srcset_raw,
                "data_src": _clean_url(data_src_raw, base) if data_src_raw else "",
                "loading": (attrs.get("loading") or "").strip().lower(),
                "width": (attrs.get("width") or "").strip(),
                "height": (attrs.get("height") or "").strip(),
                "decoding": (attrs.get("decoding") or "").strip().lower(),
                "alt": attrs.get("alt"),
                "sources": _picture_sources(node),
                "size": None,
                "content_type": "",
            }
        )
    return images


def _extension(url: str) -> str:
    path = urlparse(url or "").path.lower()
    for ext in _LEGACY_EXTS:
        if path.endswith(ext):
            return ext
    for fmt in _MODERN_FORMATS:
        if path.endswith("." + fmt):
            return "." + fmt
    return ""


def _has_modern_alternative(image: Dict[str, Any]) -> bool:
    """Есть ли webp/avif-версия в src/srcset/data-src/sources."""
    candidates: List[str] = []
    candidates.append(str(image.get("src") or ""))
    candidates.append(str(image.get("data_src") or ""))
    candidates.extend(_srcset_urls(str(image.get("srcset") or "")))
    for source in image.get("sources") or []:
        stype = str(source.get("type") or "").lower()
        if any(fmt in stype for fmt in _MODERN_FORMATS):
            return True
        candidates.extend(_srcset_urls(str(source.get("srcset") or "")))
    for candidate in candidates:
        low = candidate.lower().split("?", 1)[0]
        if any(low.endswith("." + fmt) for fmt in _MODERN_FORMATS):
            return True
    return False


def _is_legacy(image: Dict[str, Any]) -> bool:
    ctype = str(image.get("content_type") or "").lower()
    if ctype in ("image/jpeg", "image/jpg", "image/png", "image/gif", "image/bmp"):
        return True
    url = str(image.get("src") or image.get("data_src") or "")
    ext = _extension(url)
    return ext in _LEGACY_EXTS


def image_issues(images: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Чистая функция: проанализировать список изображений и вернуть проблемы.

    Возвращает словарь со списками URL: heavy_warning/heavy_critical,
    missing_dimensions, not_lazy, legacy, а также lazy_lcp, legacy_share
    и суммарный вес (total_weight / total_weight_mb).
    """
    total = len(images or [])
    heavy_warning: List[Dict[str, Any]] = []
    heavy_critical: List[Dict[str, Any]] = []
    missing_dimensions: List[str] = []
    not_lazy: List[str] = []
    legacy: List[str] = []
    lazy_lcp: Optional[str] = None
    total_weight = 0

    for index, image in enumerate(images or []):
        url = str(image.get("src") or image.get("data_src") or image.get("src_raw") or "")

        size = image.get("size")
        if isinstance(size, (int, float)) and size > 0:
            total_weight += int(size)
            if size > HEAVY_CRIT_BYTES:
                heavy_critical.append({"url": url, "size": int(size)})
            elif size > HEAVY_WARN_BYTES:
                heavy_warning.append({"url": url, "size": int(size)})

        if not str(image.get("width") or "").strip() or not str(image.get("height") or "").strip():
            missing_dimensions.append(url)

        loading = str(image.get("loading") or "").lower()
        if index >= LAZY_AFTER and loading != "lazy":
            not_lazy.append(url)
        if index == 0 and loading == "lazy":
            lazy_lcp = url

        if _is_legacy(image) and not _has_modern_alternative(image):
            legacy.append(url)

    legacy_share = round(len(legacy) / total, 3) if total else 0.0
    return {
        "total": total,
        "heavy_warning": heavy_warning,
        "heavy_critical": heavy_critical,
        "missing_dimensions": missing_dimensions,
        "missing_dimensions_count": len(missing_dimensions),
        "not_lazy": not_lazy,
        "not_lazy_count": len(not_lazy),
        "lazy_lcp": lazy_lcp,
        "legacy": legacy,
        "legacy_share": legacy_share,
        "total_weight": total_weight,
        "total_weight_mb": round(total_weight / (1024 * 1024), 2),
    }


# ===========================================================================
# Сетевой шаг
# ===========================================================================
def _size_from_response(resp: Any) -> tuple[Optional[int], str]:
    headers = getattr(resp, "headers", {}) or {}
    ctype = (headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    raw_len = headers.get("content-length")
    if raw_len:
        try:
            return int(raw_len), ctype
        except (TypeError, ValueError):
            pass
    return None, ctype


async def _probe_image(client: Any, sem: asyncio.Semaphore, image: Dict[str, Any]) -> None:
    """Определить content-type и размер изображения через HEAD (fallback — GET stream)."""
    url = str(image.get("src") or image.get("data_src") or "")
    if not url.startswith(("http://", "https://")):
        return
    async with sem:
        size: Optional[int] = None
        ctype = ""
        try:
            resp = await client.head(url, follow_redirects=True, timeout=10.0)
            size, ctype = _size_from_response(resp)
        except Exception:
            size, ctype = None, ""
        if size is None:
            try:
                async with client.stream("GET", url, follow_redirects=True, timeout=10.0) as resp:
                    size, ctype = _size_from_response(resp)
            except Exception:
                pass
    image["size"] = size
    image["content_type"] = ctype


def _extra_pages(ctx: AuditContext, html: str, limit: int = 2) -> List[str]:
    """До двух дополнительных страниц: карточки товара для магазина либо первые внутренние ссылки."""
    home_host = urlparse(ctx.base).netloc
    out: List[str] = []
    seen = {ctx.url.rstrip("/")}

    if detect_shop(html or "") or find_product_links(html or "", ctx.base, limit=1):
        candidates = find_product_links(html or "", ctx.base, limit=limit)
        for url in candidates:
            if url.rstrip("/") in seen:
                continue
            seen.add(url.rstrip("/"))
            out.append(url)
        if out:
            return out[:limit]

    try:
        tree = HTMLParser(html or "")
    except Exception:  # pragma: no cover - защитный путь
        return out
    for node in tree.css("a"):
        href = (node.attributes.get("href") or "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute = urljoin(ctx.base.rstrip("/") + "/", href)
        if not absolute.startswith(("http://", "https://")):
            continue
        if urlparse(absolute).netloc != home_host:
            continue
        clean = absolute.split("#", 1)[0].rstrip("/")
        if clean in seen or not clean:
            continue
        if any(clean.lower().endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg", ".pdf", ".css", ".js")):
            continue
        seen.add(clean)
        out.append(absolute)
        if len(out) >= limit:
            break
    return out[:limit]


def _fmt_size(num: int) -> str:
    if num >= 1024 * 1024:
        return f"{num / (1024 * 1024):.1f} МБ"
    if num >= 1024:
        return f"{num / 1024:.0f} КБ"
    return f"{num} Б"


# ===========================================================================
# Проверка
# ===========================================================================
@check(id="images_optimization", title="Оптимизация изображений и ленивая загрузка", category=CATEGORY)
async def images_optimization(ctx: AuditContext) -> CheckResult:
    check_id = "images_optimization"
    title = "Оптимизация изображений и ленивая загрузка"

    home = await ctx.home()
    if home is None:
        return CheckResult(
            id=check_id,
            title=title,
            category=CATEGORY,
            status="skipped",
            score=0,
            findings=[Finding(level="warning", text="Не удалось получить HTML главной страницы — проверка пропущена", fix="Проверить доступность сайта и повторить аудит", hours=0.5)],
            raw={},
        )

    home_html = home.text or ""
    images: List[Dict[str, Any]] = parse_images(home_html, ctx.base)
    pages: List[str] = [ctx.url]

    for extra_url in _extra_pages(ctx, home_html, limit=2):
        page = await ctx.get(extra_url)
        if page is None or page.status_code != 200:
            continue
        pages.append(extra_url)
        images += parse_images(page.text or "", ctx.base)

    # Уникальные изображения по адресу.
    unique: Dict[str, Dict[str, Any]] = {}
    for image in images:
        key = str(image.get("src") or image.get("data_src") or image.get("src_raw") or "")
        if not key or key.startswith("data:"):
            continue
        if key not in unique:
            unique[key] = image
    unique_images = list(unique.values())

    probed = 0
    if ctx.client is not None and unique_images:
        sem = asyncio.Semaphore(PROBE_CONCURRENCY)
        probe_targets = unique_images[:MAX_PROBE]
        await asyncio.gather(*[_probe_image(ctx.client, sem, image) for image in probe_targets])
        probed = len(probe_targets)

    issues = image_issues(unique_images)

    findings: List[Finding] = []
    score = 100

    if issues["heavy_critical"]:
        samples = "; ".join(f"{_truncate(i['url'])} — {_fmt_size(i['size'])}" for i in issues["heavy_critical"][:5])
        findings.append(
            Finding(
                level="critical",
                text=f"Очень тяжёлые изображения (> 500 КБ): {len(issues['heavy_critical'])}. {samples}",
                fix="Сжать изображения и пересохранить в WebP/AVIF, настроить адаптивные размеры; целевой вес — до 200 КБ",
                hours=3.0,
            )
        )
        score -= 30

    if issues["heavy_warning"]:
        samples = "; ".join(f"{_truncate(i['url'])} — {_fmt_size(i['size'])}" for i in issues["heavy_warning"][:5])
        findings.append(
            Finding(
                level="warning",
                text=f"Тяжёлые изображения (> 200 КБ): {len(issues['heavy_warning'])}. {samples}",
                fix="Оптимизировать размер и формат изображений, использовать WebP/AVIF и responsive srcset",
                hours=2.0,
            )
        )
        score -= 12

    if issues["legacy"]:
        share = int(round(issues["legacy_share"] * 100))
        level = "warning" if issues["legacy_share"] >= 0.5 else "info"
        samples = "; ".join(_truncate(u) for u in issues["legacy"][:5])
        findings.append(
            Finding(
                level=level,
                text=f"Устаревшие форматы (JPEG/PNG/GIF) без WebP/AVIF-версии: {len(issues['legacy'])} из {issues['total']} ({share}%). {samples}",
                fix="Конвертировать растровые изображения в WebP/AVIF и отдавать их через <picture> с JPEG-фолбэком",
                hours=3.0,
            )
        )
        if issues["legacy_share"] >= 0.5:
            score -= 12
        else:
            score -= 4

    if issues["missing_dimensions_count"]:
        samples = "; ".join(_truncate(u) for u in issues["missing_dimensions"][:5])
        findings.append(
            Finding(
                level="warning",
                text=f"У {issues['missing_dimensions_count']} изображений не заданы width/height — риск сдвига макета (CLS). {samples}",
                fix="Проставить атрибуты width и height (или aspect-ratio в CSS) всем изображениям, чтобы браузер резервировал место",
                hours=2.0,
            )
        )
        score -= 15

    if issues["lazy_lcp"]:
        findings.append(
            Finding(
                level="warning",
                text=f"Первое (LCP-кандидат) изображение использует loading=lazy: {_truncate(issues['lazy_lcp'])}",
                fix="Убрать loading=lazy у первого изображения экрана, добавить fetchpriority=\"high\" — lazy откладывает LCP",
                hours=0.5,
            )
        )
        score -= 10

    if issues["not_lazy_count"]:
        samples = "; ".join(_truncate(u) for u in issues["not_lazy"][:5])
        findings.append(
            Finding(
                level="warning",
                text=f"Изображения ниже первого экрана без loading=lazy: {issues['not_lazy_count']}. {samples}",
                fix="Добавить loading=\"lazy\" (и decoding=\"async\") изображениям, которые не видны сразу при загрузке",
                hours=1.5,
            )
        )
        score -= 8

    if probed:
        findings.append(
            Finding(
                level="info",
                text=f"Проверено изображений: {issues['total']} (запрошены размеры у {probed}), суммарный вес: {_fmt_size(issues['total_weight'])} ({issues['total_weight_mb']} МБ)",
                fix="Держать суммарный вес изображений страницы в разумных пределах (ориентир — до 1–2 МБ)",
                hours=0.0,
            )
        )
    else:
        findings.append(
            Finding(level="info", text=f"Найдено изображений: {issues['total']}", fix="", hours=0.0)
        )

    score = max(0, min(100, score))
    if issues["heavy_critical"]:
        status = "critical"
    elif score >= 80:
        status = "ok"
    elif score >= 40:
        status = "warning"
    else:
        status = "critical"

    if status == "ok":
        findings.append(Finding(level="ok", text="Изображения оптимизированы: формат, вес, размеры и ленивая загрузка в порядке", fix=""))

    return CheckResult(
        id=check_id,
        title=title,
        category=CATEGORY,
        status=status,
        score=score,
        findings=findings,
        raw={"pages": pages, "checked": probed, **issues},
    )


def _truncate(text: str, limit: int = 80) -> str:
    t = (text or "").strip()
    return t if len(t) <= limit else t[: limit - 1] + "…"
